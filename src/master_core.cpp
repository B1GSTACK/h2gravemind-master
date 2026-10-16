#include "master_core.h"

#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <map>
#include <thread>
#include <utility>
#include <vector>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
using SocketHandle = SOCKET;
using SockLen = int;
#else
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <unistd.h>
using SocketHandle = int;
using SockLen = socklen_t;
constexpr int INVALID_SOCKET = -1;
#endif

namespace
{
    constexpr uint32_t kMagic = 0x424C3248;  // "H2LB"
    constexpr uint8_t kHeartbeat = 8, kList = 9, kListReply = 10;
    constexpr size_t kHeaderSize = 14;        // u32 magic, u8 version, u8 type, u64 nonce
    constexpr size_t kMaxPacket = 1472;       // one UDP packet without fragmentation
    constexpr size_t kMinInfo = 16, kMaxInfo = kMaxPacket - kHeaderSize - 1 - 6;
    constexpr size_t kEntriesPerPacket = 2;   // what the game reads per reply
    constexpr int64_t kExpireMs = 45000;
    constexpr size_t kMaxGames = 4096, kMaxGamesPerIp = 32;
    constexpr int kListBurst = 6;             // list requests per source address and window (amplification guard)
    constexpr int64_t kListWindowMs = 10000;

    int64_t NowMs()
    {
        return std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now().time_since_epoch())
            .count();
    }

    // 127.x, 10.x, 172.16-31.x, 192.168.x, 169.254.x (network byte order address)
    bool PrivateAddress(uint32_t netOrder)
    {
        const uint32_t a = ntohl(netOrder);
        return (a >> 24) == 127 || (a >> 24) == 10 || (a >> 20) == 0xAC1 || (a >> 16) == 0xC0A8 || (a >> 16) == 0xA9FE;
    }

    std::string IpPort(uint32_t netIp, uint16_t netPort)
    {
        char ip[INET_ADDRSTRLEN] = {};
        in_addr a{};
        a.s_addr = netIp;
        inet_ntop(AF_INET, &a, ip, sizeof(ip));
        return std::string(ip) + ":" + std::to_string(ntohs(netPort));
    }

    // The game's info starts with its host name: 32 UTF-16LE characters.
    std::string HostName(const std::vector<uint8_t>& info)
    {
        std::string out;
        for (size_t i = 0; i + 1 < info.size() && i < 64; i += 2)
        {
            const unsigned c = info[i] | info[i + 1] << 8;
            if (!c) break;
            if (c < 0x80) out += static_cast<char>(c);
            else if (c < 0x800) out += {static_cast<char>(0xC0 | c >> 6), static_cast<char>(0x80 | (c & 0x3F))};
            else out += {static_cast<char>(0xE0 | c >> 12), static_cast<char>(0x80 | (c >> 6 & 0x3F)), static_cast<char>(0x80 | (c & 0x3F))};
        }
        return out;
    }

    struct Game
    {
        uint8_t version = 0;
        std::vector<uint8_t> info;
        int64_t lastSeen = 0;
    };
}

int RunMaster(const MasterOptions& options)
{
    auto log = [&](const std::string& line) {
        if (options.log) options.log(line);
        else std::printf("%s\n", line.c_str());
    };
#ifdef _WIN32
    WSADATA wsa;
    WSAStartup(MAKEWORD(2, 2), &wsa);
#endif
    SocketHandle s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    sockaddr_in local{};
    local.sin_family = AF_INET;
    local.sin_port = htons(options.port);
    if (s == INVALID_SOCKET || bind(s, reinterpret_cast<sockaddr*>(&local), sizeof(local)) != 0)
    {
        log("master: cannot bind UDP port " + std::to_string(options.port));
        return 1;
    }
    log("master: listening on UDP " + std::to_string(options.port) +
        " (hosts register every 15 s, entries expire after 45 s)");

    std::atomic<uint32_t> publicIp{options.publicIp};
    if (options.fetchPublicIp)
        std::thread([&publicIp, fetch = options.fetchPublicIp, log] {
            for (;;)
            {
                if (uint32_t ip = fetch())
                {
                    if (ip != publicIp.exchange(ip)) log("master: public address " + IpPort(ip, 0));
                    std::this_thread::sleep_for(std::chrono::minutes(10));
                }
                else
                    std::this_thread::sleep_for(std::chrono::seconds(30));
            }
        }).detach();

    std::map<std::pair<uint32_t, uint16_t>, Game> games;
    std::map<uint32_t, std::pair<int64_t, int>> listRequests;  // source ip -> window start, count
    size_t lastCount = SIZE_MAX;
    int64_t lastSweep = NowMs();

    while (!(options.quit && options.quit()))
    {
        fd_set readable;
        FD_ZERO(&readable);
        FD_SET(s, &readable);
        timeval timeout{0, 100000};
        if (select(static_cast<int>(s) + 1, &readable, nullptr, nullptr, &timeout) > 0)
        {
            uint8_t buf[2048];
            sockaddr_in from{};
            SockLen fromLen = sizeof(from);
            const int n = static_cast<int>(recvfrom(s, reinterpret_cast<char*>(buf), sizeof(buf), 0,
                                                    reinterpret_cast<sockaddr*>(&from), &fromLen));
            uint32_t magic = 0;
            if (n >= static_cast<int>(kHeaderSize) && (std::memcpy(&magic, buf, 4), magic == kMagic))
            {
                const uint8_t version = buf[4], type = buf[5];
                const auto key = std::make_pair(static_cast<uint32_t>(from.sin_addr.s_addr), from.sin_port);
                const int64_t now = NowMs();
                if (type == kHeartbeat && n >= static_cast<int>(kHeaderSize + kMinInfo) &&
                    n <= static_cast<int>(kHeaderSize + kMaxInfo))
                {
                    auto it = games.find(key);
                    if (it == games.end())
                    {
                        size_t fromIp = 0;
                        for (auto& [k, g] : games) fromIp += k.first == key.first;
                        if (games.size() >= kMaxGames || fromIp >= kMaxGamesPerIp) continue;
                        it = games.emplace(key, Game{}).first;
                        it->second.info.assign(buf + kHeaderSize, buf + n);
                        log("master: " + HostName(it->second.info) + " registered from " + IpPort(key.first, key.second) +
                            " (protocol " + std::to_string(version) + ")");
                    }
                    it->second.version = version;
                    it->second.info.assign(buf + kHeaderSize, buf + n);
                    it->second.lastSeen = now;
                }
                else if (type == kList)
                {
                    auto& [start, count] = listRequests[key.first];
                    if (now - start > kListWindowMs) start = now, count = 0;
                    if (++count > kListBurst) continue;
                    const bool outside = !PrivateAddress(key.first);
                    std::vector<uint8_t> reply;
                    uint8_t inPacket = 0;
                    auto flush = [&] {
                        reply[kHeaderSize] = inPacket;
                        sendto(s, reinterpret_cast<const char*>(reply.data()), static_cast<int>(reply.size()), 0,
                               reinterpret_cast<sockaddr*>(&from), fromLen);
                    };
                    auto begin = [&] {
                        reply.assign(buf, buf + kHeaderSize);  // magic, the asker's version, its nonce
                        reply[5] = kListReply;
                        reply.push_back(0);
                        inPacket = 0;
                    };
                    begin();
                    for (auto& [k, g] : games)
                    {
                        if (g.version != version) continue;
                        if (inPacket == kEntriesPerPacket || reply.size() + 6 + g.info.size() > kMaxPacket)
                        {
                            flush();
                            begin();
                        }
                        uint32_t ip = k.first;
                        if (outside && PrivateAddress(ip) && publicIp) ip = publicIp;  // a game on the master's network
                        const uint8_t* p = reinterpret_cast<const uint8_t*>(&ip);
                        reply.insert(reply.end(), p, p + 4);
                        p = reinterpret_cast<const uint8_t*>(&k.second);
                        reply.insert(reply.end(), p, p + 2);
                        reply.insert(reply.end(), g.info.begin(), g.info.end());
                        ++inPacket;
                    }
                    flush();  // also an empty list: the browser knows the master answered
                }
            }
        }

        const int64_t now = NowMs();
        if (now - lastSweep > 1000)
        {
            lastSweep = now;
            for (auto it = games.begin(); it != games.end();)
                it = now - it->second.lastSeen > kExpireMs ? games.erase(it) : std::next(it);
            for (auto it = listRequests.begin(); it != listRequests.end();)
                it = now - it->second.first > kListWindowMs ? listRequests.erase(it) : std::next(it);
            if (games.size() != lastCount)
            {
                lastCount = games.size();
                log("master: " + std::to_string(lastCount) + " game(s) registered");
                if (options.printList)
                    for (auto& [k, g] : games)
                        log("  " + IpPort(k.first, k.second) + "  " + HostName(g.info) + "  (protocol " +
                            std::to_string(g.version) + ")");
            }
        }
    }
#ifdef _WIN32
    closesocket(s);
#else
    close(s);
#endif
    return 0;
}
