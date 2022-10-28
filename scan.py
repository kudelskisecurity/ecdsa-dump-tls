#!/usr/bin/env python3
import argparse
import subprocess
import time


def get_parser():
    parser = argparse.ArgumentParser(
        prog="scan-tls",
        description="Perform TLS handshakes on the specified targets"
    )
    parser.add_argument("--input", "-i", type=str, required=True,
                        help="Path to the input file. Must contain a target on each line (host) and"
                             "optionally host:port",
                        dest="input_path")
    parser.add_argument("--handshakes-per-target", type=int, default=4,
                        help="Number of handshakes to perform per target",
                        dest="handshakes_per_target")
    parser.add_argument("--timeout", type=float, default=3,
                        help="Number seconds before timeout for each handshake",
                        dest="timeout")
    parser.add_argument("--handshake-delay", type=float, default=0.2,
                        help="Number of seconds to wait between each handshake",
                        dest="handshake_delay")

    return parser


def main():
    parser: argparse.ArgumentParser = get_parser()
    args = parser.parse_args()

    input_path = args.input_path

    print(f"Loading domains from file {input_path}")

    target_domains = []
    with open(input_path) as f:
        for line in f:
            splits = line.strip().split(",")
            domain = splits[-1]
            target_domains.append(domain)

    # remove unusable domains
    target_domains = [d for d in target_domains if not d.startswith("-")]

    # for each target
    target_count = len(target_domains)
    for i, domain in enumerate(target_domains):
        print(f"[{i + 1}/{target_count}] Scanning domain {domain}...")
        scan_target(domain, args.handshakes_per_target, args.timeout, args.handshake_delay)


def scan_target(domain, handshakes_per_target, timeout, handshake_delay):
    domain_with_port = domain
    if ":" not in domain:
        domain_with_port = f"{domain}:443"
    else:
        domain = domain.split(":")[0]

    openssl_cmd = [
        "openssl",
        "s_client",
        "-cipher", "ECDHE-ECDSA-AES128-SHA256",
        "-tls1_2",
        "-servername", domain,
        "-connect", domain_with_port
    ]
    print(" ".join(openssl_cmd))
    for i in range(handshakes_per_target):
        print(f"[{i + 1}/{handshakes_per_target}] Scanning {domain} ...")
        try:
            _ = subprocess.check_output(openssl_cmd, stdin=subprocess.DEVNULL, timeout=timeout)
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
            print(f"warning: failed to scan target: {domain}")

        time.sleep(handshake_delay)


if __name__ == '__main__':
    main()
