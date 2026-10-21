#include "master_core.h"

#include <algorithm>
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
    constexpr uint8_t kHeartbeat = 8, kList = 9, kListReply = 10, kUnlist = 24;
    constexpr size_t kHeaderSize = 14;        // u32 magic, u8 version, u8 type, u64 nonce
    constexpr size_t kMaxPacket = 1472;       // one UDP packet without fragmentation
    constexpr size_t kMinInfo = 16, kMaxInfo = kMaxPacket - kHeaderSize - 1 - 6;
    constexpr size_t kEntriesPerPacket = 2;   // what the game reads per reply
    constexpr int64_t kExpireMs = 45000;
    constexpr size_t kMaxGames = 4096, kMaxGamesPerIp = 32;
    constexpr int kListBurst = 6;             // list requests per source address and window (amplification guard)
    constexpr int64_t kListWindowMs = 10000;

    // NAT traversal (docs/IPV6.md "NAT traversal"): a player who gets no answer from a listed game asks us, from its
    // game socket, to introduce it (40, exactly 128 bytes); we pass the address that request came from to the game
    // by the way its heartbeats come (41) and answer the player (42); the game then sends a few punches that open
    // its router for the player's HELLO. A player who still can't get in sends its pings to relay servers (48,
    // exactly 256 bytes), which we pass to the game the same way (49): the game moves to the best relay. A game
    // hears its public address from us at most once a minute (46). Keepalives (47) only keep the game's router
    // open toward us. Address entries: u8 family 4, the IPv4 (4 bytes, network order), u16 port (big endian).
    constexpr uint8_t kIntroRequest = 40, kIntroduce = 41, kIntroReply = 42, kSeen = 46, kRelayRequest = 48,
                      kRelayNeeded = 49;
    constexpr uint8_t kIntroOk = 0, kIntroUnknown = 1, kIntroLimited = 2;
    constexpr int kIntroSize = 128, kRelayRequestSize = 256;
    constexpr size_t kHostEntryAt = kHeaderSize + 1;  // after the flags byte
    constexpr size_t kRelayCountAt = kHostEntryAt + 19, kRelayRttSize = 10, kRelayAsk = 16;
    constexpr int kIntroBurst = 10, kIntroPerGame = 30;  // per source / per game and window
    constexpr int64_t kSeenEveryMs = 60000;

    void WriteEntry(std::vector<uint8_t>& out, uint32_t netIp, uint16_t netPort)
    {
        const uint8_t* ip = reinterpret_cast<const uint8_t*>(&netIp);
        const uint8_t* port = reinterpret_cast<const uint8_t*>(&netPort);  // network order: big endian already
        out.push_back(4);
        out.insert(out.end(), ip, ip + 4);
        out.insert(out.end(), port, port + 2);
    }

    bool ReadEntry(const uint8_t* p, uint32_t* netIp, uint16_t* netPort)  // IPv4 entries only
    {
        if (p[0] != 4) return false;
        std::memcpy(netIp, p + 1, 4);
        std::memcpy(netPort, p + 5, 2);
        return *netPort != 0;
    }

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
        int64_t seenSent = 0;                    // kSeen
        std::pair<int64_t, int> intros{0, 0};    // introductions to this game: window start, count
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
    std::map<uint32_t, std::pair<int64_t, int>> introRequests;  // source ip -> window start, count (40 and 48)
    auto count = [](std::pair<int64_t, int>& window, int64_t now) {  // requests in the window, this one included
        if (now - window.first > kListWindowMs) window = {now, 0};
        return ++window.second;
    };
    auto send = [&](const std::vector<uint8_t>& data, uint32_t netIp, uint16_t netPort) {
        sockaddr_in to{};
        to.sin_family = AF_INET;
        to.sin_addr.s_addr = netIp;
        to.sin_port = netPort;
        sendto(s, reinterpret_cast<const char*>(data.data()), static_cast<int>(data.size()), 0,
               reinterpret_cast<sockaddr*>(&to), sizeof(to));
    };
    // The game a player names: as listed (a game on our own network is listed under our public IPv4: found by
    // its port among the private ones)
    auto findGame = [&](uint32_t netIp, uint16_t netPort) {
        auto it = games.find({netIp, netPort});
        if (it == games.end() && publicIp && netIp == publicIp)
            for (auto g = games.begin(); g != games.end() && it == games.end(); ++g)
                if (PrivateAddress(g->first.first) && g->first.second == netPort) it = g;
        return it;
    };
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
                    if (now - it->second.seenSent >= kSeenEveryMs)
                    {
                        // its public address as we see it (the launcher shows it; old games ignore the message)
                        it->second.seenSent = now;
                        std::vector<uint8_t> seen(buf, buf + kHeaderSize);
                        seen[5] = kSeen;
                        WriteEntry(seen, key.first, key.second);
                        send(seen, key.first, key.second);
                    }
                }
                else if (type == kUnlist)
                {
                    // the host closed its game: gone from the lists at once (not 45 s later)
                    if (auto it = games.find(key); it != games.end())
                    {
                        log("master: " + HostName(it->second.info) + " closed (" + IpPort(key.first, key.second) + ")");
                        games.erase(it);
                    }
                }
                else if ((type == kIntroRequest && n == kIntroSize) || (type == kRelayRequest && n == kRelayRequestSize))
                {
                    uint32_t ip = 0;
                    uint16_t port = 0;
                    if (!ReadEntry(buf + kHostEntryAt, &ip, &port)) continue;
                    const int asked = count(introRequests[key.first], now);
                    if (asked > kIntroBurst + 1) continue;  // told once, then silence
                    std::vector<uint8_t> reply(buf, buf + kHeaderSize);  // the player's nonce
                    reply[5] = kIntroReply;
                    auto answer = [&](uint8_t status) {
                        if (type != kIntroRequest) return;  // a relay request gets no answer
                        reply.push_back(status);
                        WriteEntry(reply, key.first, key.second);
                        send(reply, key.first, key.second);
                    };
                    auto game = findGame(ip, port);
                    if (asked > kIntroBurst || (game != games.end() && count(game->second.intros, now) > kIntroPerGame))
                    {
                        answer(kIntroLimited);
                        continue;
                    }
                    if (game == games.end())
                    {
                        answer(kIntroUnknown);
                        continue;
                    }
                    // To the game at the address its heartbeats come from, with the address this request came from
                    // (never one written in it: nobody can aim a game at someone else)
                    std::vector<uint8_t> out(buf, buf + kHeaderSize);
                    out[5] = type == kIntroRequest ? kIntroduce : kRelayNeeded;
                    WriteEntry(out, key.first, key.second);
                    if (type == kRelayRequest)
                    {
                        const uint8_t rtts = std::min<uint8_t>(buf[kRelayCountAt], kRelayAsk);
                        out.push_back(rtts);
                        out.insert(out.end(), buf + kRelayCountAt + 1, buf + kRelayCountAt + 1 + rtts * kRelayRttSize);
                    }
                    send(out, game->first.first, game->first.second);
                    answer(kIntroOk);
                    if (type == kIntroRequest)
                        log("master: introduced " + IpPort(key.first, key.second) + " to " + HostName(game->second.info));
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
            for (auto* requests : {&listRequests, &introRequests})
                for (auto it = requests->begin(); it != requests->end();)
                    it = now - it->second.first > kListWindowMs ? requests->erase(it) : std::next(it);
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
