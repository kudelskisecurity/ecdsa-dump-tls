# ecdsa-dump-tls

[![Python 3.7+](https://img.shields.io/badge/python-3.7+-green.svg)](https://docs.python.org/3.7/whatsnew/) [![License: GPL v3](https://img.shields.io/badge/license-GPL%20v3-blue.svg)](http://www.gnu.org/licenses/gpl-3.0)

Dump ECDSA signatures, original message from TLS ServerKeyExchange records

# What's in this repository?

* `scan.py`: perform TLS handshakes on some targets
* `main.py`: dump signatures and messages from a pcap file containing TLS handshake traffic

# Requirements

* Python
* Poetry, see [Installation instructions](https://python-poetry.org/docs/#installation)
* OpenSSL
* tcpdump

# Usage

Install the dependencies and set up the virtual environment using poetry:

```
poetry install
```

Generate some TLS traffic on a few targets and capture the traffic at the same time.

In a terminal, run the following command to capture the TLS traffic on port 443 to a file in PCAP format:

```
sudo tcpdump -w tls-handshakes.pcap -i INTERFACE_NAME "tcp port 443"
```

Perform some TLS handshakes on a few targets.
Note that for the attack to have some chances of working,
it is required to perform at least 4 handshakes on each target sequentially.
The provided `scan.py` script can be used for example. Its input file should have one domain per line.

**Note that a test case with instructions is provided in the [tests](tests/README.md) directory, 
that allows for local testing.**

In another terminal, run:

```
poetry run python scan.py -i input-targets.csv
```

When complete, stop capturing the traffic in the first terminal by hitting `Ctrl-C`.

Finally, dump the signatures and messages from the pcap file:

```
poetry run python main.py -i tls-handshakes.pcap -o tls-attack-results.csv
```

The output file will contain, on each line:

```
r;s;signature_value_hex;pubkey_hex;src_addr;server_name;msg_hex;timestamp
```

# License and Copyright

Copyright(c) 2023 Nagravision SA.

This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public
License version 3 as published by the Free Software Foundation.

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied
warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with this program. If not,
see http://www.gnu.org/licenses/.
