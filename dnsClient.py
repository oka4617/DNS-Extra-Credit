import argparse
import socket
import struct

# Useful resources to solve this lab:
# 1. https://datatracker.ietf.org/doc/html/rfc1034
# 2. https://datatracker.ietf.org/doc/html/rfc1035
# 3. Kurose/Ross Book!


def dns_query(qtype_str, name, server):
    # Normalize domain (comment hint says lowercase)
    name = name.strip().lower()

    # Create a UDP socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(2.0)  # avoid hanging forever if server doesn't respond
    server_address = (server, 53)  # DNS UDP port

    # Create the DNS query
    ID = 0x1234
    QR = 0
    OPCODE = 0
    AA = 0
    TC = 0
    RD = 1
    RA = 0
    Z = 0
    RCODE = 0
    QDCOUNT = 1
    ANCOUNT = 0
    NSCOUNT = 0
    ARCOUNT = 0

    flags = (
        (QR << 15)
        | (OPCODE << 11)
        | (AA << 10)
        | (TC << 9)
        | (RD << 8)
        | (RA << 7)
        | (Z << 4)
        | (RCODE)
    )

    header = struct.pack("!HHHHHH", ID, flags, QDCOUNT, ANCOUNT, NSCOUNT, ARCOUNT)

    # Encode the QNAME
    qname_parts = name.split(".")
    qname_encoded_parts = [
        struct.pack("B", len(part)) + part.encode("ascii") for part in qname_parts
    ]
    qname_encoded = b"".join(qname_encoded_parts) + b"\x00"

    # Encode the QTYPE and QCLASS
    if qtype_str == "A":
        qtype = 1
    elif qtype_str == "AAAA":
        qtype = 28
    else:
        raise ValueError("Invalid type")

    qclass = 1  # IN

    # Question section
    question = qname_encoded + struct.pack("!HH", qtype, qclass)

    # Send the query to the server
    message = header + question
    sock.sendto(message, server_address)

    # Receive the response from the server
    data, _ = sock.recvfrom(4096)

    # Parse the response header (12 bytes)
    response_header = data[:12]
    resp_id, resp_flags, resp_qdcount, resp_ancount, resp_nscount, resp_arcount = struct.unpack(
        "!HHHHHH", response_header
    )

    # Parse the response question section (same length as our question in typical replies)
    response_question = data[12 : 12 + len(question)]

    # Some servers *should* echo it exactly; if yours does, this will pass.
    # If it ever fails due to compression/variation, you can comment it out.
    assert response_question == question

    # Parse the response answer section
    response_answer = data[12 + len(question) :]
    offset = 0

    for _ in range(resp_ancount):
        # Parse the NAME (labels or pointer)
        name_parts = []
        while True:
            length = response_answer[offset]
            offset += 1

            if length == 0:
                break

            if length & 0xC0 == 0xC0:
                # Pointer (two bytes, first two bits are 11)
                pointer = struct.unpack("!H", response_answer[offset - 1 : offset + 1])[0] & 0x3FFF
                offset += 1
                name_parts.append(parse_name(data, pointer))
                break
            else:
                # Label
                label = response_answer[offset : offset + length].decode("ascii")
                offset += length
                name_parts.append(label)

        rr_name = ".".join(name_parts)

        # Parse TYPE, CLASS, TTL, RDLENGTH (2+2+4+2 = 10 bytes)
        rr_type, rr_class, ttl, rdlength = struct.unpack(
            "!HHIH", response_answer[offset : offset + 10]
        )
        offset += 10

        # Parse RDATA
        rdata = response_answer[offset : offset + rdlength]
        offset += rdlength

        if rr_type == 1:
            ipv4 = socket.inet_ntop(socket.AF_INET, rdata)
            print(f"{rr_name} has IPv4 address {ipv4}")
            return ipv4
        elif rr_type == 28:
            ipv6 = socket.inet_ntop(socket.AF_INET6, rdata)
            print(f"{rr_name} has IPv6 address {ipv6}")
            return ipv6

    # If we got here, no A/AAAA answer in the answer section
    return None


def parse_name(data, offset):
    name_parts = []
    while True:
        length = data[offset]
        offset += 1

        if length == 0:
            break

        if length & 0xC0 == 0xC0:
            pointer = struct.unpack("!H", data[offset - 1 : offset + 1])[0] & 0x3FFF
            offset += 1
            name_parts.append(parse_name(data, pointer))
            break
        else:
            label = data[offset : offset + length].decode("ascii")
            offset += length
            name_parts.append(label)

    return ".".join(name_parts)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Send a DNS query and parse the reply.")
    parser.add_argument("--type", choices=["A", "AAAA"], required=True, help="the type of address requested")
    parser.add_argument("--name", required=True, help="the host name being queried")
    parser.add_argument("--server", required=True, help="the IP address of the DNS server to query")
    args = parser.parse_args()

    result = dns_query(args.type, args.name, args.server)
    # Optional: print result if you want a final line
    # print("Result:", result)
