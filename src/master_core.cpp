#include "master_core.h"

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <map>
#include <thread>
#include <tuple>
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
    constexpr uint8_t kHeartbeat = 8, kList = 9, kListReply = 10, kUnlist = 24, kListReplyFamilies = 32;
    constexpr uint8_t kListWantsFamilies = 1;  // the list request's flags byte (after the header)
    constexpr size_t kHeaderSize = 14;        // u32 magic, u8 version, u8 type, u64 nonce
    constexpr size_t kMaxPacket = 1472;       // one UDP packet without fragmentation
    constexpr size_t kMinInfo = 16, kMaxInfo = kMaxPacket - kHeaderSize - 1 - 21;
    constexpr size_t kEntriesPerPacket = 2;   // what the game reads per reply
    constexpr int64_t kExpireMs = 45000;
    // per source (an IPv4 address, an IPv6 /64) and per IPv6 site (/48: one customer's networks)
    constexpr size_t kMaxGames = 4096, kMaxGamesPerSource = 32, kMaxGamesPerSite = 256;
    constexpr int kListBurst = 6, kListBurstSite = 4 * kListBurst;  // list requests per window (amplification guard)
    constexpr int64_t kListWindowMs = 10000;

    // NAT traversal (docs/IPV6.md "NAT traversal"): a player who gets no answer from a listed game asks us, from its
    // game socket, to introduce it (40, exactly 128 bytes); we pass the address that request came from to the game
    // by the way its heartbeats come (41) and answer the player (42); the game then sends a few punches that open
    // its router / firewall for the player's HELLO. A player who still can't get in sends its pings to relay servers
    // (48, exactly 256 bytes), which we pass to the game the same way (49): the game moves to the best relay. A game
    // hears its public address from us at most once a minute (46). Keepalives (47) only keep the game's router open
    // toward us. Address entries: u8 family 4 / 6, the address (4 / 16 bytes, network order), u16 port (big endian).
    constexpr uint8_t kIntroRequest = 40, kIntroduce = 41, kIntroReply = 42, kSeen = 46, kRelayRequest = 48,
                      kRelayNeeded = 49;
    constexpr uint8_t kIntroOk = 0, kIntroUnknown = 1, kIntroLimited = 2;
    constexpr int kIntroSize = 128, kRelayRequestSize = 256;
    constexpr size_t kHostEntryAt = kHeaderSize + 1;  // after the flags byte
    constexpr size_t kRelayCountAt = kHostEntryAt + 19, kRelayRttSize = 10, kRelayAsk = 16;
    constexpr int kIntroBurst = 10, kIntroBurstSite = 4 * kIntroBurst, kIntroPerGame = 30;  // per window
    constexpr int64_t kSeenEveryMs = 60000;

    // An IPv4 or IPv6 address and port. IPv4: the 4 bytes first (network order), the rest 0; port in network order.
    struct Addr
    {
        uint8_t family = 0;  // 4 or 6 (0 = none)
        std::array<uint8_t, 16> ip{};
        uint16_t port = 0;
        bool operator<(const Addr& o) const { return std::tie(family, ip, port) < std::tie(o.family, o.ip, o.port); }
        bool operator==(const Addr& o) const { return family == o.family && ip == o.ip && port == o.port; }
        uint32_t Ipv4() const  // network order
        {
            uint32_t v;
            std::memcpy(&v, ip.data(), 4);
            return v;
        }
        static Addr V4(uint32_t netIp, uint16_t netPort)
        {
            Addr a;
            a.family = 4;
            std::memcpy(a.ip.data(), &netIp, 4);
            a.port = netPort;
            return a;
        }
        // the limits' keys: an IPv4 address; an IPv6 /64 (one network: a PC can have many addresses in it) or /48
        Addr Source() const
        {
            Addr a = *this;
            a.port = 0;
            if (family == 6) std::fill(a.ip.begin() + 8, a.ip.end(), 0);
            return a;
        }
        Addr Site() const
        {
            Addr a = Source();
            if (family == 6) std::fill(a.ip.begin() + 6, a.ip.end(), 0);
            return a;
        }
    };

    Addr FromSockaddr(const sockaddr_storage& ss)
    {
        Addr a;
        if (ss.ss_family == AF_INET)
        {
            const auto& s4 = reinterpret_cast<const sockaddr_in&>(ss);
            a = Addr::V4(s4.sin_addr.s_addr, s4.sin_port);
        }
        else if (ss.ss_family == AF_INET6)
        {
            const auto& s6 = reinterpret_cast<const sockaddr_in6&>(ss);
            const uint8_t* b = reinterpret_cast<const uint8_t*>(&s6.sin6_addr);
            static const uint8_t kMapped[12] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF};  // ::ffff:a.b.c.d
            if (std::memcmp(b, kMapped, 12) == 0)
            {
                uint32_t v4;
                std::memcpy(&v4, b + 12, 4);
                a = Addr::V4(v4, s6.sin6_port);
            }
            else
            {
                a.family = 6;
                std::memcpy(a.ip.data(), b, 16);
                a.port = s6.sin6_port;
            }
        }
        return a;
    }

    // for a socket of family `socketFamily` (an IPv4 address on an IPv6 socket becomes ::ffff:a.b.c.d)
    SockLen ToSockaddr(const Addr& a, int socketFamily, sockaddr_storage* out)
    {
        std::memset(out, 0, sizeof(*out));
        if (socketFamily == AF_INET)
        {
            auto* s4 = reinterpret_cast<sockaddr_in*>(out);
            s4->sin_family = AF_INET;
            s4->sin_addr.s_addr = a.Ipv4();
            s4->sin_port = a.port;
            return sizeof(sockaddr_in);
        }
        auto* s6 = reinterpret_cast<sockaddr_in6*>(out);
        s6->sin6_family = AF_INET6;
        s6->sin6_port = a.port;
        uint8_t* b = reinterpret_cast<uint8_t*>(&s6->sin6_addr);
        if (a.family == 4)
        {
            b[10] = b[11] = 0xFF;
            std::memcpy(b + 12, a.ip.data(), 4);
        }
        else
            std::memcpy(b, a.ip.data(), 16);
        return sizeof(sockaddr_in6);
    }

    void WriteEntry(std::vector<uint8_t>& out, const Addr& a)
    {
        const uint8_t* port = reinterpret_cast<const uint8_t*>(&a.port);  // network order: big endian already
        out.push_back(a.family);
        out.insert(out.end(), a.ip.begin(), a.ip.begin() + (a.family == 6 ? 16 : 4));
        out.insert(out.end(), port, port + 2);
    }

    bool ReadEntry(const uint8_t* p, Addr* a)
    {
        if (p[0] != 4 && p[0] != 6) return false;
        const size_t n = p[0] == 6 ? 16 : 4;
        *a = Addr{};
        a->family = p[0];
        std::memcpy(a->ip.data(), p + 1, n);
        std::memcpy(&a->port, p + 1 + n, 2);
        return a->port != 0;
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

    // IPv4 as above; IPv6: loopback, unique local (fc00::/7), link-local (fe80::/10): no NAT there, so a game on one of
    // those is only listed to browsers on such addresses
    bool PrivateAddress(const Addr& a)
    {
        if (a.family == 4) return PrivateAddress(a.Ipv4());
        static const std::array<uint8_t, 16> kLoopback{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};
        return a.ip == kLoopback || (a.ip[0] & 0xFE) == 0xFC || (a.ip[0] == 0xFE && (a.ip[1] & 0xC0) == 0x80);
    }

    std::string IpPort(const Addr& a)
    {
        char ip[INET6_ADDRSTRLEN] = {};
        inet_ntop(a.family == 6 ? AF_INET6 : AF_INET, a.ip.data(), ip, sizeof(ip));
        const std::string port = std::to_string(ntohs(a.port));
        return a.family == 6 ? "[" + std::string(ip) + "]:" + port : std::string(ip) + ":" + port;
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
        Addr arrival;                            // IPv6: our address its heartbeats come to (we answer from it)
    };

    // One UDP socket for IPv4 and IPv6 (IPv4 only where the system has no IPv6). On Linux an IPv6 packet's own
    // destination address is read (IPV6_PKTINFO) so what we send back leaves from it: a server with several IPv6
    // addresses would otherwise answer from another one, which the player's firewall drops.
    class Socket
    {
    public:
        bool Open(uint16_t port)
        {
            s_ = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
            if (s_ != INVALID_SOCKET)
            {
                int off = 0;
                setsockopt(s_, IPPROTO_IPV6, IPV6_V6ONLY, reinterpret_cast<const char*>(&off), sizeof(off));
#ifndef _WIN32
                int on = 1;
                setsockopt(s_, IPPROTO_IPV6, IPV6_RECVPKTINFO, &on, sizeof(on));
#endif
                sockaddr_in6 local{};
                local.sin6_family = AF_INET6;
                local.sin6_addr = in6addr_any;
                local.sin6_port = htons(port);
                if (bind(s_, reinterpret_cast<sockaddr*>(&local), sizeof(local)) == 0)
                {
                    family_ = AF_INET6;
                    return true;
                }
                Close();
            }
            s_ = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
            sockaddr_in local{};
            local.sin_family = AF_INET;
            local.sin_port = htons(port);
            if (s_ == INVALID_SOCKET || bind(s_, reinterpret_cast<sockaddr*>(&local), sizeof(local)) != 0) return false;
            family_ = AF_INET;
            return true;
        }
        bool Ipv6() const { return family_ == AF_INET6; }
        bool Wait(int ms)
        {
            fd_set readable;
            FD_ZERO(&readable);
            FD_SET(s_, &readable);
            timeval timeout{0, ms * 1000};
            return select(static_cast<int>(s_) + 1, &readable, nullptr, nullptr, &timeout) > 0;
        }
        // the packet's length (<= 0: none); *to = our IPv6 address it came to, when known
        int Recv(uint8_t* buf, size_t size, Addr* from, Addr* to)
        {
            sockaddr_storage ss{};
            *to = Addr{};
#ifdef _WIN32
            SockLen len = sizeof(ss);
            const int n = recvfrom(s_, reinterpret_cast<char*>(buf), static_cast<int>(size), 0, reinterpret_cast<sockaddr*>(&ss),
                                   &len);
#else
            iovec iov{buf, size};
            alignas(cmsghdr) char control[256];
            msghdr msg{};
            msg.msg_name = &ss;
            msg.msg_namelen = sizeof(ss);
            msg.msg_iov = &iov;
            msg.msg_iovlen = 1;
            msg.msg_control = control;
            msg.msg_controllen = sizeof(control);
            const int n = static_cast<int>(recvmsg(s_, &msg, 0));
            for (cmsghdr* c = n > 0 ? CMSG_FIRSTHDR(&msg) : nullptr; c; c = CMSG_NXTHDR(&msg, c))
                if (c->cmsg_level == IPPROTO_IPV6 && c->cmsg_type == IPV6_PKTINFO)
                {
                    in6_pktinfo info;
                    std::memcpy(&info, CMSG_DATA(c), sizeof(info));
                    sockaddr_storage local{};
                    auto& l6 = reinterpret_cast<sockaddr_in6&>(local);
                    l6.sin6_family = AF_INET6;
                    l6.sin6_addr = info.ipi6_addr;
                    *to = FromSockaddr(local);
                    if (to->family != 6) *to = Addr{};  // an IPv4 packet (mapped): the system picks fine
                }
#endif
            if (n > 0) *from = FromSockaddr(ss);
            return n;
        }
        void Send(const std::vector<uint8_t>& data, const Addr& to, const Addr& fromLocal = {})
        {
            if (to.family == 6 && !Ipv6()) return;
            sockaddr_storage ss;
            const SockLen len = ToSockaddr(to, family_, &ss);
#ifndef _WIN32
            if (fromLocal.family == 6 && to.family == 6)
            {
                iovec iov{const_cast<uint8_t*>(data.data()), data.size()};
                alignas(cmsghdr) char control[CMSG_SPACE(sizeof(in6_pktinfo))] = {};
                msghdr msg{};
                msg.msg_name = &ss;
                msg.msg_namelen = len;
                msg.msg_iov = &iov;
                msg.msg_iovlen = 1;
                msg.msg_control = control;
                msg.msg_controllen = sizeof(control);
                cmsghdr* c = CMSG_FIRSTHDR(&msg);
                c->cmsg_level = IPPROTO_IPV6;
                c->cmsg_type = IPV6_PKTINFO;
                c->cmsg_len = CMSG_LEN(sizeof(in6_pktinfo));
                in6_pktinfo info{};
                std::memcpy(&info.ipi6_addr, fromLocal.ip.data(), 16);
                std::memcpy(CMSG_DATA(c), &info, sizeof(info));
                sendmsg(s_, &msg, 0);
                return;
            }
#endif
            (void)fromLocal;
            sendto(s_, reinterpret_cast<const char*>(data.data()), static_cast<int>(data.size()), 0,
                   reinterpret_cast<const sockaddr*>(&ss), len);
        }
        void Close()
        {
            if (s_ == INVALID_SOCKET) return;
#ifdef _WIN32
            closesocket(s_);
#else
            close(s_);
#endif
            s_ = INVALID_SOCKET;
        }

    private:
        SocketHandle s_ = INVALID_SOCKET;
        int family_ = AF_INET;
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
    Socket s;
    if (!s.Open(options.port))
    {
        log("master: cannot bind UDP port " + std::to_string(options.port));
        return 1;
    }
    log("master: listening on UDP " + std::to_string(options.port) + (s.Ipv6() ? " (IPv4 and IPv6;" : " (IPv4 only;") +
        " hosts register every 15 s, entries expire after 45 s)");

    std::atomic<uint32_t> publicIp{options.publicIp};
    if (options.fetchPublicIp)
        std::thread([&publicIp, fetch = options.fetchPublicIp, log] {
            for (;;)
            {
                if (uint32_t ip = fetch())
                {
                    if (ip != publicIp.exchange(ip)) log("master: public address " + IpPort(Addr::V4(ip, 0)));
                    std::this_thread::sleep_for(std::chrono::minutes(10));
                }
                else
                    std::this_thread::sleep_for(std::chrono::seconds(30));
            }
        }).detach();

    using Window = std::pair<int64_t, int>;  // window start, count
    std::map<Addr, Game> games;
    std::map<Addr, Window> listRequests, siteListRequests, introRequests, siteIntroRequests;  // by Source() / Site()
    auto count = [](Window& window, int64_t now) {  // requests in the window, this one included
        if (now - window.first > kListWindowMs) window = {now, 0};
        return ++window.second;
    };
    // The game a player names: as listed (a game on our own network is listed under our public IPv4: found by
    // its port among the private ones)
    auto findGame = [&](const Addr& want) {
        auto it = games.find(want);
        if (it == games.end() && want.family == 4 && publicIp && want.Ipv4() == publicIp)
            for (auto g = games.begin(); g != games.end() && it == games.end(); ++g)
                if (g->first.family == 4 && PrivateAddress(g->first.Ipv4()) && g->first.port == want.port) it = g;
        return it;
    };
    size_t lastCount = SIZE_MAX;
    int64_t lastSweep = NowMs();

    while (!(options.quit && options.quit()))
    {
        if (s.Wait(100))
        {
            uint8_t buf[2048];
            Addr from, to;
            const int n = s.Recv(buf, sizeof(buf), &from, &to);
            uint32_t magic = 0;
            if (n >= static_cast<int>(kHeaderSize) && from.family && (std::memcpy(&magic, buf, 4), magic == kMagic))
            {
                const uint8_t version = buf[4], type = buf[5];
                const int64_t now = NowMs();
                if (type == kHeartbeat && n >= static_cast<int>(kHeaderSize + kMinInfo) &&
                    n <= static_cast<int>(kHeaderSize + kMaxInfo))
                {
                    auto it = games.find(from);
                    if (it == games.end())
                    {
                        size_t fromSource = 0, fromSite = 0;
                        for (auto& [k, g] : games)
                        {
                            fromSource += k.Source() == from.Source();
                            fromSite += from.family == 6 && k.Site() == from.Site();
                        }
                        if (games.size() >= kMaxGames || fromSource >= kMaxGamesPerSource || fromSite >= kMaxGamesPerSite)
                            continue;
                        it = games.emplace(from, Game{}).first;
                        it->second.info.assign(buf + kHeaderSize, buf + n);
                        log("master: " + HostName(it->second.info) + " registered from " + IpPort(from) + " (protocol " +
                            std::to_string(version) + ")");
                    }
                    it->second.version = version;
                    it->second.info.assign(buf + kHeaderSize, buf + n);
                    it->second.lastSeen = now;
                    it->second.arrival = to;
                    if (now - it->second.seenSent >= kSeenEveryMs)
                    {
                        // its public address as we see it (the launcher shows it; old games ignore the message)
                        it->second.seenSent = now;
                        std::vector<uint8_t> seen(buf, buf + kHeaderSize);
                        seen[5] = kSeen;
                        WriteEntry(seen, from);
                        s.Send(seen, from, to);
                    }
                }
                else if (type == kUnlist)
                {
                    // the host closed its game: gone from the lists at once (not 45 s later)
                    if (auto it = games.find(from); it != games.end())
                    {
                        log("master: " + HostName(it->second.info) + " closed (" + IpPort(from) + ")");
                        games.erase(it);
                    }
                }
                else if ((type == kIntroRequest && n == kIntroSize) || (type == kRelayRequest && n == kRelayRequestSize))
                {
                    Addr want;
                    if (!ReadEntry(buf + kHostEntryAt, &want)) continue;
                    if (type == kRelayRequest && buf[kRelayCountAt] > kRelayAsk) continue;
                    const int asked = count(introRequests[from.Source()], now);
                    const int askedSite = from.family == 6 ? count(siteIntroRequests[from.Site()], now) : 0;
                    if (asked > kIntroBurst + 1 || askedSite > kIntroBurstSite + 1) continue;  // told once, then silence
                    std::vector<uint8_t> reply(buf, buf + kHeaderSize);  // the player's nonce
                    reply[5] = kIntroReply;
                    auto answer = [&](uint8_t status) {
                        if (type != kIntroRequest) return;  // a relay request gets no answer
                        reply.push_back(status);
                        WriteEntry(reply, from);
                        s.Send(reply, from, to);
                    };
                    if (asked > kIntroBurst || askedSite > kIntroBurstSite)
                    {
                        answer(kIntroLimited);
                        continue;
                    }
                    // a game of the asker's address family (an introduction can't cross IPv4 / IPv6)
                    auto game = findGame(want);
                    if (game == games.end() || game->first.family != from.family)
                    {
                        answer(kIntroUnknown);
                        continue;
                    }
                    if (count(game->second.intros, now) > kIntroPerGame)
                    {
                        answer(kIntroLimited);
                        continue;
                    }
                    // To the game at the address its heartbeats come from, with the address this request came from
                    // (never one written in it: nobody can aim a game at someone else)
                    std::vector<uint8_t> out(buf, buf + kHeaderSize);
                    out[5] = type == kIntroRequest ? kIntroduce : kRelayNeeded;
                    WriteEntry(out, from);
                    if (type == kRelayRequest)
                    {
                        const uint8_t rtts = buf[kRelayCountAt];
                        out.push_back(rtts);
                        out.insert(out.end(), buf + kRelayCountAt + 1, buf + kRelayCountAt + 1 + rtts * kRelayRttSize);
                    }
                    s.Send(out, game->first, game->second.arrival);
                    answer(kIntroOk);
                    if (type == kIntroRequest) log("master: introduced " + IpPort(from) + " to " + HostName(game->second.info));
                }
                else if (type == kList)
                {
                    if (count(listRequests[from.Source()], now) > kListBurst ||
                        (from.family == 6 && count(siteListRequests[from.Site()], now) > kListBurstSite))
                        continue;  // too many from this source: each one can cost many reply packets
                    const bool families = n > static_cast<int>(kHeaderSize) && (buf[kHeaderSize] & kListWantsFamilies);
                    const bool outside = !PrivateAddress(from);
                    std::vector<uint8_t> reply;
                    uint8_t inPacket = 0;
                    auto flush = [&] {
                        reply[kHeaderSize] = inPacket;
                        s.Send(reply, from, to);
                    };
                    auto begin = [&] {
                        reply.assign(buf, buf + kHeaderSize);  // magic, the asker's version, its nonce
                        reply[5] = families ? kListReplyFamilies : kListReply;
                        reply.push_back(0);
                        inPacket = 0;
                    };
                    // IPv4 games in the order of before (address and port in network byte order, as numbers), then IPv6
                    std::vector<std::pair<const Addr*, const Game*>> listed;
                    for (auto& [k, g] : games)
                        if (g.version == version && (k.family == 4 || families)) listed.push_back({&k, &g});
                    std::stable_sort(listed.begin(), listed.end(), [](auto& a, auto& b) {
                        if (a.first->family != b.first->family) return a.first->family < b.first->family;
                        return a.first->family == 4 && std::make_pair(a.first->Ipv4(), a.first->port) <
                                                           std::make_pair(b.first->Ipv4(), b.first->port);
                    });
                    begin();
                    for (auto& [k, g] : listed)
                    {
                        Addr game = *k;
                        if (outside && PrivateAddress(game))
                        {
                            if (game.family == 6) continue;  // no NAT on IPv6: unreachable from outside
                            if (publicIp) game = Addr::V4(publicIp, game.port);  // a game on the master's network
                        }
                        const size_t size = (families ? 3 + (game.family == 6 ? 16 : 4) + 2 : 6) + g->info.size();
                        if (inPacket == kEntriesPerPacket || reply.size() + size > kMaxPacket)
                        {
                            flush();
                            begin();
                        }
                        if (families)
                        {
                            // {u8 family, address, u16 port (network order), u16 info size (little endian), info}
                            WriteEntry(reply, game);
                            reply.push_back(static_cast<uint8_t>(g->info.size() & 0xFF));
                            reply.push_back(static_cast<uint8_t>(g->info.size() >> 8));
                        }
                        else
                        {
                            // {u32 ipv4, u16 port, info}
                            reply.insert(reply.end(), game.ip.begin(), game.ip.begin() + 4);
                            const uint8_t* p = reinterpret_cast<const uint8_t*>(&game.port);
                            reply.insert(reply.end(), p, p + 2);
                        }
                        reply.insert(reply.end(), g->info.begin(), g->info.end());
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
            for (auto* requests : {&listRequests, &siteListRequests, &introRequests, &siteIntroRequests})
                for (auto it = requests->begin(); it != requests->end();)
                    it = now - it->second.first > kListWindowMs ? requests->erase(it) : std::next(it);
            if (games.size() != lastCount)
            {
                lastCount = games.size();
                log("master: " + std::to_string(lastCount) + " game(s) registered");
                if (options.printList)
                    for (auto& [k, g] : games)
                        log("  " + IpPort(k) + "  " + HostName(g.info) + "  (protocol " + std::to_string(g.version) + ")");
            }
        }
    }
    s.Close();
    return 0;
}
