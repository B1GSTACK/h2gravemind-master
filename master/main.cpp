// Standalone master server for Halo 2 Project Gravemind (Linux / Docker; builds on Windows too). The game's own
// h2gravemind.exe --master runs the same core (src/master_core.cpp).
// Usage: h2gravemind-master [--port 11770] [--public-ip a.b.c.d]
#include "../src/master_core.h"

#include <atomic>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <string>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#endif

namespace
{
    std::atomic<bool> g_stop{false};
    void OnSignal(int) { g_stop = true; }
}

int main(int argc, char** argv)
{
    MasterOptions o;
    for (int i = 1; i < argc; ++i)
    {
        const std::string a = argv[i];
        if (a == "--port" && i + 1 < argc)
            o.port = static_cast<uint16_t>(std::atoi(argv[++i]));
        else if (a == "--public-ip" && i + 1 < argc)
        {
            in_addr addr{};
            if (inet_pton(AF_INET, argv[++i], &addr) != 1)
            {
                std::fprintf(stderr, "bad --public-ip %s\n", argv[i]);
                return 2;
            }
            o.publicIp = addr.s_addr;
        }
        else
        {
            std::fprintf(stderr, "usage: %s [--port 11770] [--public-ip a.b.c.d]\n", argv[0]);
            return 2;
        }
    }
    if (const char* port = std::getenv("MASTER_PORT")) o.port = static_cast<uint16_t>(std::atoi(port));
    std::signal(SIGINT, OnSignal);
    std::signal(SIGTERM, OnSignal);
    o.quit = [] { return g_stop.load(); };
    o.log = [](const std::string& line) {
        char stamp[32];
        const std::time_t now = std::time(nullptr);
        std::strftime(stamp, sizeof(stamp), "%Y-%m-%d %H:%M:%S", std::gmtime(&now));
        std::printf("%s %s\n", stamp, line.c_str());
        std::fflush(stdout);
    };
    return RunMaster(o);
}
