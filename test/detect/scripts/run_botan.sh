#!/bin/bash

# check if botan is installed
if ! command -v botan &>/dev/null; then
    echo "error: botan is not installed." >&2
    exit 1
fi

# check if directories exist
TEMP_DIR="$(dirname "$0")/tmp"

if [ ! -d "$TEMP_DIR" ]; then
    mkdir -p "$TEMP_DIR"
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
    botan cert_info "$CERT_FILE"
else
    # split the certificates by "-----END CERTIFICATE-----" and store them in the array
    certs=()

    while IFS= read -r line; do
        if [[ "$line" =~ "-----BEGIN CERTIFICATE-----" ]]; then
            cert=""
        fi

        cert+="$line"$'\n'

        if [[ "$line" =~ "-----END CERTIFICATE-----" ]]; then
            certs+=("$cert")
        fi
    done < "$CERT_FILE"

    # run certificate chain verification
    for i in "${!certs[@]}"; do
        echo "${certs[$i]}" > "$TEMP_DIR/cert_$i.crt"
    done

    # first certificate is the subject, the rest are CA certs
    subject_cert="$TEMP_DIR/cert_0.crt"
    ca_certs=$(for i in $(seq 1 $((${#certs[@]} - 1))); do printf "%s " "${TEMP_DIR}/cert_${i}.crt"; done)

    # verify the certificate chain
    cmd="botan cert_verify $subject_cert $ca_certs"
    eval "$cmd"
fi