#!/usr/bin/env bash

# extract the signatures, but regenerate them using the private key and use a fixed nonce
poetry run python ../main.py -i localhost.pcap -o localhost.csv --testing-port 8443 --private-key private.der

# sort the output file by public key and then by timestamp
sort localhost.csv --field-separator ';' -k4,4 -k8,8 > sorted-localhost.csv

# Add an extra dummy line at the end with another pubkey,
# just to trigger the attack (this is a workaround and should be fixed)
echo 'r;s;sig_val;pubkey;src_addr;server_name;msg;timestamp' >> sorted-localhost.csv
