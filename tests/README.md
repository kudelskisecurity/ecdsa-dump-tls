# TLS server for testing

* This is a simple TLS server that uses a custom private key and certificate
* This is useful for testing purposes


# How to use this

## Step 1 - Generate the traffic

First, generate the certificate and keys:

```
./generate.sh
```

Then run this server from a terminal. It will listen on port 8443:

```
poetry run python server.py
```

In another terminal, capture the traffic:

```
sudo tcpdump -w localhost.pcap -i lo "tcp port 8443"
```

In a third terminal, run the scan:
```
poetry run python ../scan.py -i localhost-target.csv --handshakes 6
```

Finally, stop the tcpdump process in the 2nd terminal with `Ctrl-C`.

Also stop `server.py` in the first terminal using `Ctrl-C`.


## Step 2 - Extract the signatures (with fixed nonce)

Then, extract the signatures but re-generate them with a fixed nonce.
Sort the output file by public key and then by timestamp.
Run the `extract.sh` script to perform all of that in one command:

```
./extract.sh
```

## Step 3 - Run the attack and check that it reports at least 1 successful attack

Go to the 

Run the attack using the script in the [ecdsa-polynomial-nonce-recurrence-attack](https://github.com/kudelskisecurity/ecdsa-polynomial-nonce-recurrence-attack) repository :

```
~/git/ecdsa-polynomial-nonce-recurrence-attack/attacks/ecdsa_tls_attack.py -n 5 -i sorted-localhost.csv -o localhost-tls-attack-results.csv
```