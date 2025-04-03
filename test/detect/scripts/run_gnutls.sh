#!/bin/bash

# check if gnutls is installed
if ! command -v certtool &>/dev/null; then
    echo "error: certtool is not installed." >&2
    exit 1
fi

# ensure a certificate file is provided
if [ "$#" -lt 1 ]; then
    echo "usage: $0 <certificate>" >&2
    exit 1
fi

CERT_FILE="$1"

# ensure the provided certificate is in PEM format
if ! grep -q "BEGIN CERTIFICATE" "$CERT_FILE" || ! grep -q "END CERTIFICATE" "$CERT_FILE"; then
    echo "error: the provided file is not a certificate in PEM format." >&2
    exit 1
fi

# count the number of certificates in the file
CERT_COUNT=$(grep -c "BEGIN CERTIFICATE" "$CERT_FILE")

if [ "$CERT_COUNT" -eq 1 ]; then
    # run single certificate parsing
    certtool -i --infile "$CERT_FILE"
else
    # run certificate chain verification
    certtool -e --infile "$CERT_FILE"
fi