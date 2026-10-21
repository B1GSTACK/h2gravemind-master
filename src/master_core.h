#pragma once
// The master server's core, portable (Windows: h2gravemind.exe --master; Linux / Docker: master/, no game code).
// It does not depend on the game's protocol version: a heartbeat (header type 8) is kept as it came (the version
// and the game's info bytes), entries expire after 45 s, and a list request (type 9) gets the entries of its own
// protocol version (type 10 replies: u8 count, then {u32 ipv4, u16 port, info} entries, at most 2 per packet). So
// masters run by others keep working when the game's protocol changes.
// NAT traversal: it also introduces a player to a listed game (types 40 -> 41 / 42), passes a player's relay pings
// to the game (48 -> 49) and tells a game its public address (46), IPv4 only; games without it never send those.
// Header (packed, little endian): u32 magic "H2LB", u8 version, u8 type, u64 nonce (echoed in the reply).
#include <cstdint>
#include <functional>
#include <string>

constexpr uint16_t kMasterDefaultPort = 11770;

struct MasterOptions
{
    uint16_t port = kMasterDefaultPort;
    // The master's public IPv4 (network byte order), for games on the master's own network: players on the
    // internet get it instead of the game's private address. 0 = none; fetchPublicIp (if set) refreshes it.
    uint32_t publicIp = 0;
    std::function<uint32_t()> fetchPublicIp;
    std::function<bool()> quit;               // polled; true stops the master
    std::function<void(const std::string&)> log;  // one line, no newline
    bool printList = true;                    // print the registered games when the list changes
};

int RunMaster(const MasterOptions& options);
