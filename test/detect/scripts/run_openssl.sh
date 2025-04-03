#!/bin/bash

# check if openssl is installed
if ! command -v openssl &>/dev/null; then
    echo "error: openssl is not installed." >&2
    exit 1
fi

# ensure a certificate file is provided
if [ "$#" -lt 1 ]; then
    echo "usage: $0 <certificate>" >&2
    exit 1
fi

CERT_FILE="$1"

# check if the file is a public key
if grep -q "BEGIN PUBLIC KEY" "$CERT_FILE" && grep -q "END PUBLIC KEY" "$CERT_FILE"; then
    openssl pkey -pubin -in "$CERT_FILE" -pubcheck
    exit 1
fi

# ensure the provided certificate is in PEM format
if ! grep -q "BEGIN CERTIFICATE" "$CERT_FILE" || ! grep -q "END CERTIFICATE" "$CERT_FILE"; then
    echo "error: the provided file is not a certificate in PEM format." >&2
    exit 1
fi

# count the number of certificates in the file
CERT_COUNT=$(grep -c "BEGIN CERTIFICATE" "$CERT_FILE")

if [ "$CERT_COUNT" -eq 1 ]; then
    # run single certificate parsing
    openssl x509 -in "$CERT_FILE" -text -noout
else

    LEAF_CERT=$(awk '
        /BEGIN CERTIFICATE/ { capture=1; cert="" }
        capture { cert = cert $0 "\n" }
        /END CERTIFICATE/ { capture=0; print cert; exit }
    ' "$CERT_FILE")

    # run certificate chain verification
    openssl verify -policy_check -CAfile "$CERT_FILE" <(echo "$LEAF_CERT")
fi
