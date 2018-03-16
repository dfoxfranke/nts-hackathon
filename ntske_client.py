import sys
import socket
import binascii
import struct
import OpenSSL

from aes_siv import AES_SIV
from rfc5705 import export_keying_materials
from ntske_record import *

def main(argv):
    if len(argv) != 4:
        print("Usage: python ntske_client.py <host> <port> <ca.pem>", file=sys.stderr)
        return 2
    host = argv[1]
    port = argv[2]
    ca_pem = argv[3]

    def verify_callback(conn, cert, errno, depth, result):
        if result == 0:
            return False
        if depth == 0:
            #FIXME: check hostname
            pass
        return True

    ctx = OpenSSL.SSL.Context(OpenSSL.SSL.SSLv23_METHOD)
    ctx.set_options(OpenSSL.SSL.OP_NO_SSLv2 |
                    OpenSSL.SSL.OP_NO_SSLv3 |
                    OpenSSL.SSL.OP_NO_TLSv1 |
                    OpenSSL.SSL.OP_NO_TLSv1_1)
    ctx.set_cipher_list(b"ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256")
    ctx.load_verify_locations(ca_pem)
    ctx.set_verify(OpenSSL.SSL.VERIFY_PEER, verify_callback)
    ctx.set_alpn_protos([b"ntske/1"])

    addrs = socket.getaddrinfo(host, port, socket.AF_INET, socket.SOCK_STREAM)
    if len(addrs) == 0:
        print("Host not found", file=sys.stderr)
        return 1
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    ssl = OpenSSL.SSL.Connection(ctx, sock)
    ssl.set_tlsext_host_name(bytes(host, "utf-8"))
    ssl.connect(addrs[0][4])
    ssl.do_handshake()
    if ssl.get_alpn_proto_negotiated != b"ntske/1":
        print("Failed to negotiate ntske/1", file=sys.stderr)
        return 1

    npn_neg = Record()
    npn_neg.critical = True
    npn_neg.rec_type = RT_NEXT_PROTO_NEG
    npn_neg.body = struct.pack(">H", 15)
    
    aead_neg = Record()
    aead_neg.critical = True
    aead_neg.rec_type = RT_AEAD_NEG
    aead_neg.body = struct.pack(">H", 0)

    eom = Record()
    eom.critical = True
    eom.rec_type = RT_END_OF_MESSAGE
    eom.body = b''

    ssl.sendall(bytes(npn_neg) + bytes(aead_neg) + bytes(eom))

    npn_ack = False
    aead_ack = False
    cookies = list()

    while True:
        resp = ssl.recv(4)
        if(len(resp) < 4):
            print("Premature end of server response", file=sys.stderr)
            return 1
        resp += ssl.recv(struct.unpack(">H", resp[2:4])[0])
        record = Record(resp)
        if record.rec_type == END_OF_MESSAGE:
            break
        elif record.rec_type == RT_NEXT_PROTO_NEG:
            if npn_ack:
                print("Duplicate NPN record", file=sys.stderr)
                return 1
            if record.body != struct.pack(">H", 0):
                print("Unacceptable NPN response", file=sys.stderr)
                return 1
            npn_ack = True
        elif record.rec_type == RT_ERROR:
            print("Received error response", file=sys.stderr)
            return 1
        elif record.rec_type == RT_WARNING:
            print("Received warning response (aborting)", file=sys.stderr)
            return 1
        elif record.rec_type == RT_AEAD_NEG:
            if aead_ack:
                print("Duplicate AEAD record", file=sys.stderr)
                return 1
            if record.body != struct.pack(">H", 15):
                print("Unacceptable AEAD response", file=sys.stderr)
                return 1
            aead_ack = True
        elif record.rec_type == RT_NEW_COOKIE:
            cookies.append(record.body)
        else:
            if record.critical:
                print("Unrecognized critical record", file=sys.stderr)
                return 1

    ssl.shutdown()

    if not npn_ack:
        print("No NPN record in server response", file=sys.stderr)
        return 1
    if not aead_ack:
        print("No AEAD record in server response", file=sys.stderr)
        return 1
    if len(cookies) == 0:
        print("No cookies provided in server response", file=sys.stderr)
        return 1

    c2s_key = export_key_materials(ssl, 32, b"EXPORTER-network-time-security/1", b'\0\0\0\x0f\x00')
    s2c_key = export_key_materials(ssl, 32, b"EXPORTER-network-time-security/1", b'\0\0\0\x0f\x01')

    print("C2S: " + binascii.hexlify(c2s_key).decode('utf-8'))
    print("S2C: " + binascii.hexlify(s2c_key).decode('utf-8'))
    for cookie in cookies:
        print("Cookie: " + binascii.hexlify(cookie).decode('utf-8'))
    return 0

if __name__ == "__main__":
    sys.exit(main(sys.argv))
