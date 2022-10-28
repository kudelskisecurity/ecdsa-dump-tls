#!/usr/bin/env python3

import argparse
import hashlib
import sys

import ecdsa
from Crypto.Util.asn1 import DerSequence
from ecdsa.util import sigencode_der
from scapy.all import rdpcap, raw
from scapy.layers.inet import IP
from scapy.layers.inet import TCP
from scapy.layers.tls.cert import PubKeyECDSA
from scapy.layers.tls.extensions import TLS_Ext_ServerName
from scapy.layers.tls.handshake import TLSServerKeyExchange, TLSCertificate, TLSClientHello
from scapy.layers.tls.record import TLS
from scapy.packet import bind_layers


def get_parser():
    parser = argparse.ArgumentParser(
        prog="ecdsa-dump-tls",
        description="Dump ECDSA signatures, original message from TLS ServerKeyExchange records"
    )
    parser.add_argument("--input", "-i", type=str, required=True,
                        help="Path to the input file. Must be a PCAP file with TLS handshake traffic inside.",
                        dest="input_path")
    parser.add_argument("--output", "-o", type=str, required=True,
                        help="Path to the output file to dump to",
                        dest="output_path")
    parser.add_argument("--private-key", "-p", type=str, default=None,
                        help="Path to a private key file (DER format). Used for testing purposes and setting"
                             "a fixed nonce value in the signatures.",
                        dest="private_key_path")
    parser.add_argument("--nonce", "-k", type=int, default=1,
                        help="Value for the fixed nonce. This is for testing purposes only.",
                        dest="nonce")
    parser.add_argument("--testing-port", type=int, default=8443,
                        help="Testing port to use. This is for testing purposes only.",
                        dest="testing_port")
    return parser


def load_private_key(path):
    with open(path, "rb") as f:
        return f.read()


def main():
    parser: argparse.ArgumentParser = get_parser()
    args = parser.parse_args()

    input_path = args.input_path
    output_path = args.output_path

    if args.private_key_path is not None:
        bind_layers(TCP, TLS, sport=args.testing_port)
        bind_layers(TCP, TLS, dport=args.testing_port)
        private_key_bytes = load_private_key(args.private_key_path)

    msg_building_errors_count = 0
    der_decoding_errors_count = 0

    cap = rdpcap(input_path)
    previous_client_random = None
    previous_client_sni = None
    with open(output_path, "a+") as fout:
        for p in cap:
            if TLS in p:
                tls = p[TLS]
                handshake_type = 22
                if tls.type == handshake_type:
                    if TLSClientHello in tls:
                        client_hello = tls[TLSClientHello]
                        previous_client_random = client_hello.gmt_unix_time.to_bytes(4, "big")
                        previous_client_random += client_hello.random_bytes
                    try:
                        sni = client_hello[TLS_Ext_ServerName]
                        previous_client_sni = sni.servernames[0].servername.decode("utf-8")
                    except:
                        previous_client_sni = ""

                # get the Server Key Exchange packet
                if TLSServerKeyExchange in tls:
                    ske = tls[TLSServerKeyExchange]

                    # get signature value
                    signature = ske.sig
                    sig_alg = signature.sig_alg
                    sig_val = signature.sig_val

                    # check that sig_alg is ECDSA with secp256r1 (see RFC 8446 section 4.2.3)
                    ecdsa_secp256r1_sha256 = 0x0403
                    if sig_alg == ecdsa_secp256r1_sha256:
                        try:
                            der = DerSequence()
                            der.decode(sig_val)
                            r = der[0]
                            s = der[1]
                        except ValueError:
                            der_decoding_errors_count += 1
                            print(
                                f"[ERROR] failed to decode DER sig_val. Error count: {der_decoding_errors_count} - "
                                f"Domain: {previous_client_sni}",
                                file=sys.stderr)
                            continue

                        # get pubkey from certificate in server hello
                        if TLSCertificate in tls:
                            cert = tls[TLSCertificate]
                            ee_cert = cert.certs[0][1]
                            pubkey: PubKeyECDSA = ee_cert.pubKey
                            pubkey_hex = pubkey.der.hex()

                        ecdh_params_bytes = raw(ske.params)

                        # client hello random
                        client_random = previous_client_random
                        server_random = ske.tls_session.server_random

                        try:
                            msg = client_random + server_random + ecdh_params_bytes
                        except TypeError:
                            # some value was None and failed to concat above
                            msg_building_errors_count += 1
                            print(f"[ERROR] failed to build message. Error count: {msg_building_errors_count} - "
                                  f"Domain: {previous_client_sni}",
                                  file=sys.stderr)
                            print(f"{server_random=}", file=sys.stderr)
                            continue

                        # Warning: DO NOT HASH because verify() does it internally
                        # msg = hashlib.sha256(msg).digest()
                        is_valid = pubkey.verify(msg, sig_val)
                        if not is_valid:
                            print("[ERROR] invalid signature", file=sys.stderr)

                        # get timestamp from packet in PCAP
                        timestamp = int(p.time.to_integral())

                        # get target IP or domain name (some identifier)
                        ip = p[IP]
                        src_addr = ip.src
                        server_name = previous_client_sni

                        # replace signature value with new one with always the same nonce
                        if args.private_key_path is not None:
                            sk = ecdsa.SigningKey.from_der(private_key_bytes)
                            sig_val = sk.sign(msg, sigencode=sigencode_der, hashfunc=hashlib.sha256, k=args.nonce)
                            der = DerSequence()
                            der.decode(sig_val)
                            r = der[0]
                            s = der[1]

                        # build output line
                        output_line = f"{r};{s};{sig_val.hex()};{pubkey_hex};{src_addr};{server_name};{msg.hex()};{timestamp}\n"
                        print(output_line, end="", file=fout)


if __name__ == '__main__':
    main()
