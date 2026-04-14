#!/usr/bin/env python3
import sys
import ipaddress
import shlex
import socket
import struct

DNS_SERVER_IP = "2.144.21.230" # change here
DNS_PORT = 53
TIMEOUT = 5.0

TYPE_AAAA = 28
CLASS_IN = 1

def encode_name(name: str) -> bytes:
    labels = name.rstrip(".").split(".")
    out = bytearray()
    for label in labels:
        if not label or len(label) > 63:
            raise ValueError(f"Invalid domain: {name}")
        out.append(len(label))
        out.extend(label.encode("ascii"))
    out.append(0)
    return bytes(out)


def decode_name(data: bytes, offset: int):
    labels = []
    jumped = False
    resume_offset = offset
    seen = set()

    while True:
        if offset >= len(data):
            raise ValueError("Name exceeds packet length")

        length = data[offset]

        if length == 0:
            offset += 1
            break

        if (length & 0xC0) == 0xC0:
            if offset + 1 >= len(data):
                raise ValueError("Incomplete compression pointer")
            pointer = ((length & 0x3F) << 8) | data[offset + 1]
            if pointer in seen:
                raise ValueError("Compression loop detected")
            seen.add(pointer)
            if not jumped:
                resume_offset = offset + 2
                jumped = True
            offset = pointer
            continue

        offset += 1
        if offset + length > len(data):
            raise ValueError("Label exceeds packet length")
        labels.append(data[offset:offset + length].decode("ascii"))
        offset += length

    return ".".join(labels), (resume_offset if jumped else offset)


def build_query(hostname: str, txid: int) -> bytes:
    flags = 0x0100  # RD
    header = struct.pack("!HHHHHH", txid, flags, 1, 0, 0, 0)
    question = encode_name(hostname) + struct.pack("!HH", TYPE_AAAA, CLASS_IN)
    dns_message = header + question
    return struct.pack("!H", len(dns_message)) + dns_message  # TCP length prefix


def recv_exact(sock: socket.socket, size: int) -> bytes:
    chunks = []
    remaining = size
    while remaining > 0:
        chunk = sock.recv(remaining)
        if not chunk:
            raise ConnectionError("Connection closed by server")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def parse_response(packet: bytes, expected_txid: int):
    if len(packet) < 12:
        raise ValueError("DNS packet too short")

    txid, flags, qdcount, ancount, nscount, arcount = struct.unpack("!HHHHHH", packet[:12])
    if txid != expected_txid:
        raise ValueError("Transaction ID mismatch")

    rcode = flags & 0x000F
    if rcode != 0:
        errors = {
            1: "Format error",
            2: "Server failure",
            3: "NXDOMAIN",
            4: "Not implemented",
            5: "Refused",
        }
        raise ValueError(errors.get(rcode, f"DNS error rcode={rcode}"))

    offset = 12

    for _ in range(qdcount):
        _, offset = decode_name(packet, offset)
        if offset + 4 > len(packet):
            raise ValueError("Truncated question section")
        offset += 4

    answers = []
    for _ in range(ancount):
        name, offset = decode_name(packet, offset)
        if offset + 10 > len(packet):
            raise ValueError("Truncated resource record header")

        rtype, rclass, ttl, rdlength = struct.unpack("!HHIH", packet[offset:offset + 10])
        offset += 10

        if offset + rdlength > len(packet):
            raise ValueError("Truncated RDATA")

        rdata = packet[offset:offset + rdlength]
        offset += rdlength

        if rtype == TYPE_AAAA and rclass == CLASS_IN and rdlength == 16:
            answers.append((name, str(ipaddress.IPv6Address(rdata)), ttl))

    return answers


def query_aaaa_tcp(sock: socket.socket, hostname: str, txid: int):
    query = build_query(hostname, txid)
    sock.sendall(query)
    msg_len = struct.unpack("!H", recv_exact(sock, 2))[0]
    response = recv_exact(sock, msg_len)
    return parse_response(response, txid)


def repl():
    if len(sys.argv) >= 2:
        DNS_SERVER_IP = sys.argv[1]
    if len(sys.argv) >= 3:
        DNS_PORT = int(sys.argv[1])
    
    print(f"TCP AAAA lookup against {DNS_SERVER_IP}:{DNS_PORT}")
    print("Enter one or more hostnames per line. Type 'quit' or 'exit' to stop.")

    txid = 0
    with socket.create_connection((DNS_SERVER_IP, DNS_PORT), timeout=TIMEOUT) as sock:
        sock.settimeout(TIMEOUT)

        while True:
            try:
                line = input("aaaa> ").strip()
            except (EOFError, KeyboardInterrupt):
                print()
                break

            if not line:
                continue
            if line.lower() in {"quit", "exit"}:
                break

            try:
                hostnames = shlex.split(line)
            except ValueError as e:
                print(f"Input parse error: {e}")
                continue

            for hostname in hostnames:
                txid = (txid + 1) & 0xFFFF
                try:
                    answers = query_aaaa_tcp(sock, hostname, txid)
                    if answers:
                        print(f"{hostname}:")
                        for _, addr, ttl in answers:
                            print(f"  AAAA  {addr}  TTL={ttl}")
                    else:
                        print(f"{hostname}: no AAAA records")
                except ValueError as e:
                    print(f"{hostname}: ERROR: {e}")
                except Exception as e:
                    print(f"{hostname}: ERROR: {e}")
                    return  # or reconnect here if you want


if __name__ == "__main__":
    repl()