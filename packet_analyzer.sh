#!/bin/bash

file="test.pcapng"

echo "Checking for SSL/TLS Handshakes:"
tshark -r "$file" -Y "ssl.handshake" -V

echo "Checking for utilized Cipher Suites:"
tshark -r "$file" -Y "ssl.handshake.ciphersuite" -T fields -e ssl.handshake.ciphersuite

echo "Identifying potential clear text data:"
tshark -r "$file" -Y "data" -T fields -e data.data
