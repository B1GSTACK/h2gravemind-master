"""Smoke test of a running master server: registers a fake game (heartbeat) and asks for the list.
Usage: python master/smoke_test.py [host] [port]"""
import socket
import struct
import sys
import time

host = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
port = int(sys.argv[2]) if len(sys.argv) > 2 else 11770
MAGIC, VERSION = 0x424C3248, 16


def header(kind, nonce):
    return struct.pack("<IBBQ", MAGIC, VERSION, kind, nonce)


info = "Smoke test".encode("utf-16-le").ljust(64, b"\0") + bytes(range(256)) * 2  # opaque to the master
game = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
game.sendto(header(8, 0) + info, (host, port))
time.sleep(0.5)

browser = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
browser.settimeout(3)
browser.sendto(header(9, 1234), (host, port))
data, _ = browser.recvfrom(2048)
magic, version, kind, nonce = struct.unpack_from("<IBBQ", data)
count = data[14]
assert (magic, version, kind, nonce) == (MAGIC, VERSION, 10, 1234), (magic, version, kind, nonce)
assert count == 1, count
ip, gport = struct.unpack_from("<4sH", data, 15)
assert data[21:21 + len(info)] == info, "info bytes changed"
print("ok: 1 game listed from %s:%d, %d info bytes kept" % (socket.inet_ntoa(ip), socket.ntohs(gport), len(info)))

# another protocol version sees nothing
other = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
other.settimeout(3)
other.sendto(struct.pack("<IBBQ", MAGIC, VERSION + 1, 9, 5), (host, port))
data, _ = other.recvfrom(2048)
assert data[14] == 0, "a different protocol version must not see the game"
print("ok: another protocol version gets an empty list")

# the game closes (unlist): gone from the list at once
game.sendto(header(24, 0), (host, port))
time.sleep(0.5)
browser.sendto(header(9, 1235), (host, port))
data, _ = browser.recvfrom(2048)
assert data[14] == 0, "an unlisted game must leave the list"
print("ok: an unlisted game leaves the list at once")
