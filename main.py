from datetime import timedelta
import json
import random
import socket
from struct import pack, unpack
import sys

record_types = {
    "A": 1,
    "NS": 2,
    "CNAME": 5,
    "SOA": 6,
    # "WKS": 11,
    "PTR": 12,
    # "HINFO": 13,
    # "MINFO": 14,
    "MX": 15,
    "TXT": 16,
}

# Support only IN class
qclass = 1

# Use google as default dns
default_dns = "8.8.8.8"


# Define handlers for specific record types


# Returns
# IP Address: 4 bytes
#
# + offset
def a_handler(res, offset):
    return (
        "".join(str(x) + "." for x in res[offset : offset + 4]).rstrip("."),
        offset + 4,
    )


# MX record is 2 bytes for priority
# Rest of response is domain
# Returns
# PRIORITY: 2 bytes
# DOMAIN: <domain_format>
#
# + offset
def mx_handler(res, offset):
    prority = unpack(">H", res[offset : offset + 2])[0]
    domain, offset = decode_domain(res, offset + 2)

    return {"PRIORITY": prority, "MX_SERVER": domain}, offset


# Returns
# MNAME: <domain_format>
# RNAME: <domain_forma>
# Serial: 4 bytes
# Refresh: 4 bytes
# Retry: 4 bytes
# Expire: 4 bytes
# Minimum TTL: 4 bytes
#
# + offset
def soa_handler(res, offset):
    mname, offset = decode_domain(res, offset)
    rname, offset = decode_domain(res, offset)
    serial, offset = decode_as_4_bytes(res, offset)
    refresh, offset = decode_as_4_bytes(res, offset)
    retry, offset = decode_as_4_bytes(res, offset)
    expire, offset = decode_as_4_bytes(res, offset)
    minimum, offset = decode_as_4_bytes(res, offset)

    return {
        "MNAME": mname,
        "RNAME": rname,
        "SERIAL": serial,
        "REFRESH": refresh,
        "RETRY": retry,
        "EXPIRE": expire,
        "MINIMUM": minimum,
    }, offset
    
def ptr_handler(res, offset):
    ptr_domain, offset = decode_domain(res, offset)
    return ptr_domain, offset


record_handlers = {
    record_types["A"]: a_handler,
    record_types["SOA"]: soa_handler,
    record_types["MX"]: mx_handler,
    record_types["PTR"]: ptr_handler,    
}


def validate_request_data(domain, qtype):
    if not (domain) or "." not in domain:
        raise ValueError(f"{domain} is not a valid domain")
    if qtype not in record_types:
        raise ValueError(f"{qtype} is unsupported dns record type")


# First parameter is called subject because it can be domain 
# or ip in case of PTR request
def dns_query(subject, qtype, dns_serv=default_dns):
    validate_request_data(subject, qtype)
    if qtype == 'PTR':
        domain = get_arpa_domain(subject)
    else:
        domain = subject
        
    dns_query = (
        encode_header()
        + b"".join(encode_domain(domain))
        + pack(">H", record_types[qtype])
        + pack(">H", qclass)
    )

    resp = {}

    data = send_and_receive(dns_query, dns_serv)

    resp["header"], offset = decode_header(data)

    # Decode question
    resp["question_domain"], offset = decode_domain(data, offset)
    resp["question_type"], offset = decode_as_2_bytes(data, offset)
    resp["question_class"], offset = decode_as_2_bytes(data, offset)

    answer_count = resp["header"]["an_count"]
    answers = []
    for _ in range(answer_count):
        answer = {}
        # Decode answer
        answer["answer_domain"], offset = decode_domain(data, offset)
        answer["answer_type"], offset = decode_as_2_bytes(data, offset)
        answer["answer_class"], offset = decode_as_2_bytes(data, offset)
        answer["answer_ttl"], offset = decode_as_4_bytes(data, offset)
        answer["resp_length"], offset = decode_as_2_bytes(data, offset)
        answer["answer_ttl_str"] = str(timedelta(seconds=answer["answer_ttl"]))
        answer["answer_body"], offset = record_handlers[answer["answer_type"]](
            data, offset
        )

        answers.append(answer)

    resp["answers"] = answers

    return json.dumps(resp)


def send_and_receive(dns_query, dns_serv):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.connect((dns_serv, 53))
        sock.sendall(pack(">H", len(dns_query)))
        sock.sendall(dns_query)
        data_len = unpack(">H", sock.recv(2))[0]
        return sock.recv(data_len)


def encode_header():
    transaction_id = random.randint(0, 2**16)
    qr = 0
    opcode = 0
    aa = 0
    tc = 0
    rd = 1
    ra = 0
    z = 0
    rcode = 0

    flags_code = (
        rcode
        | (z << 4)
        | (ra << 7)
        | (rd << 8)
        | (tc << 9)
        | (aa << 10)
        | (opcode << 11)
        | (qr << 15)
    )

    qd_count = 1
    an_count = 0
    ns_count = 0
    ar_count = 0

    return pack(
        ">HHHHHH", transaction_id, flags_code, qd_count, an_count, ns_count, ar_count
    )


def decode_header(res) -> tuple[int, int, int, int, int, int, int]:
    transaction_id, flags_code, qd_count, an_count, ns_count, ar_count = unpack(
        ">HHHHHH", res[:12]
    )

    return {
        "transaction_id": transaction_id,
        "flags_code": flags_code,
        "qd_count": qd_count,
        "an_count": an_count,
        "ns_count": ns_count,
        "ar_count": ar_count,
    }, 12

def get_arpa_domain(ip):
    return '.'.join(ip.split('.')[::-1]) + '.in-addr.arpa'

def encode_domain(domain):
    encoded_domain = []
    for part in domain.split("."):
        encoded_domain.append(pack(">B", len(part)))
        encoded_domain.append(part.encode())

    encoded_domain.append(pack(">B", 0))
    return encoded_domain


def decode_domain(res, offset) -> tuple[str, int]:
    domain = ""

    while True:
        size = res[offset]
        offset += 1

        # It means we need to jump to other part of response to get rest of domain
        if size & 0xC0 == 0xC0:
            next_byte = res[offset]
            jump_addr = ((size & 0x3F) << 8) | next_byte
            domain += decode_domain(res, jump_addr)[0]
            return domain, offset + 1

        if size == 0:
            break
        else:
            domain += res[offset : offset + size].decode()
            offset += size
        domain += "."

    return domain.rstrip("."), offset


def decode_as_2_bytes(res, offset) -> tuple[int, int]:
    decoded_val = unpack(">H", res[offset : offset + 2])
    return decoded_val[0], offset + 2


def decode_as_4_bytes(res, offset):
    return unpack(">I", res[offset : offset + 4])[0], offset + 4


def main():
    try:
        sys.stdout.write(dns_query("212.77.98.9", "PTR", default_dns))
    except socket.error as sock_err:
        sys.stderr.write(
            f"error: cannot connect, write or receive from server ({default_dns}):53 -> ({sock_err})\n"
        )
        sys.exit(1)
    except Exception as e:
        import traceback

        sys.stderr.write(f"Type: {type(e).__name__}\n")
        sys.stderr.write(f"Message: {e}\n")
        sys.stderr.write("Traceback:\n")
        traceback.print_exc()


if __name__ == "__main__":
    main()
