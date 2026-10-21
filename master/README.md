# Halo 2 Project Gravemind — master server

The master server keeps the internet list of games. It is tiny and stateless:

- **UDP 11770** only (no TCP, no HTTP).
- Games (player-hosted lobbies and dedicated servers) send a heartbeat every 15 s; an entry expires after 45 s,
  or at once when the game says it closed (unlist).
- Players' server browsers ask for the list; the master answers with the games of the **same protocol version**
  (it stores each game's info as opaque bytes, so it keeps working when the game's protocol changes — masters
  never need updating for a new game version).
- No database, no disk, no configuration. Memory use is a few MB.
- Limits: 4096 games in total, 32 per source address, 6 list requests per address every 10 s (the list reply is
  larger than the request, so this keeps it from being used to reflect traffic).

The game ships with `master01.gravemind.haloarchive.com:11770` and `master02.gravemind.haloarchive.com:11770` as
its default masters. Every game registers with **all** the masters in the player's list and the browser asks all
of them and merges the lists, so masters back each other up; any number can be added.

## Docker

Build from the repository root:

```sh
docker build -f master/Dockerfile -t h2gravemind-master .
docker run -d --name h2gravemind-master --restart unless-stopped -p 11770:11770/udp h2gravemind-master
```

docker compose:

```yaml
services:
  master:
    build:
      context: .
      dockerfile: master/Dockerfile
    restart: unless-stopped
    ports:
      - "11770:11770/udp"
```

Logs go to stdout (`docker logs h2gravemind-master`): one line per game that registers and the count when it
changes.

Options: `--port N` (or the `MASTER_PORT` environment variable) and `--public-ip a.b.c.d` (only needed when games
run on the master's own private network: players on the internet then get that address for them).

Without Docker: `g++ -O2 -std=c++17 -o h2gravemind-master master/main.cpp src/master_core.cpp -pthread`.

## Checking it

`python3 master/smoke_test.py <host> 11770` registers a fake game and asks for the list.

## Protocol

Little endian, packed. Header (14 bytes): `u32 magic 0x424C3248 ("H2LB")`, `u8 protocol version`, `u8 type`,
`u64 nonce`.

- type 8, heartbeat (game -> master): header + the game's info (16..1451 bytes, opaque to the master; it starts
  with the host name, 32 UTF-16LE characters).
- type 9, list request (browser -> master): header, optionally `u8 flags` (1 = IPv4 and IPv6 games, type 32).
- type 10, list reply (master -> browser): the request's header with type 10 (same version and nonce), `u8
  count`, then `count` entries `{u32 IPv4, u16 port (both network byte order), info}`, at most 2 per packet,
  as many packets as needed (one with count 0 when the list is empty). IPv4 games only.
- type 32, list reply with families (to a list request with flags 1): the same, with entries `{u8 family 4 / 6, the
  address (4 / 16 bytes, network order), u16 port (big endian), u16 info size (little endian), info}`. A game on a
  private IPv6 address (unique local, link-local, loopback) is only listed to browsers on such addresses.
- type 24, unlist (game -> master): header only. The game closed: the master drops it from the list at once
  (instead of 45 s after its last heartbeat). Masters without it simply ignore the message.

IPv4 and IPv6 on one socket (IPv4 only where the system has no IPv6). On Linux, what the master sends to an IPv6
address leaves from the address the packet came to.

NAT traversal (hosting without opening a port; games that don't know it never send these). An entry is `u8 family
4 / 6, the address (4 / 16 bytes, network order), u16 port (big endian)`; an introduction never crosses IPv4 / IPv6.

- type 40, introduce me (player -> master, exactly 128 bytes): header (nonce = the player's), `u8 flags 0`, the
  game's entry as listed (19 bytes, zero filled), zero padding. The master answers type 42 `{u8 status: 0 ok, 1
  unknown game, 2 too many requests; the player's own entry}` and sends the game type 41 `{the player's entry: the
  address the request came from}` with the player's nonce. The game then sends a few type 43 packets to the player,
  which open its router for the player's HELLO.
- type 46, seen (master -> game, at most once a minute): `{the game's entry as the master sees it}`.
- type 47, keepalive (game -> master every 4 s between heartbeats): header only, ignored; it keeps the way from the
  master to the game open in the game's router.
- type 48, relay request (player -> master, exactly 256 bytes): header, `u8 flags`, the game's entry (19 bytes), `u8
  count`, `count` x `{u64 session, u16 ping ms}`, zero padding. Passed to the game as type 49 `{the player's entry, u8
  count, the pings}`: the game moves to the relay server with the best ping for everyone.
- Limits: 10 requests (40 and 48) per source and 10 s, 30 introductions per game and 10 s; 6 list requests per source
  and 10 s; 32 games per source. A source is an IPv4 address or an IPv6 /64; an IPv6 /48 gets 4 times the requests
  and 256 games.
