#!/bin/bash

# check if crypto++ is installed
if ! dpkg -s libcrypto++-dev &>/dev/null; then
    echo "crypto++ is not installed." >&2
    exit 1
fi

TEMP_DIR="$(dirname "$0")/tmp"

if [ ! -d "$TEMP_DIR" ]; then
    mkdir -p "$TEMP_DIR"
fi

TEMP_FILE="$TEMP_DIR/Main.cpp"

# ensure a certificate file is provided
if [ "$#" -lt 1 ]; then
    echo "usage: $0 <certificate>" >&2
    exit 1
fi

CERT_FILE="$1"
EDITED_CERT_FILE="$TEMP_DIR/test.crt"

# ensure the provided certificate is in PEM format
if ! grep -q "BEGIN CERTIFICATE" "$CERT_FILE" || ! grep -q "END CERTIFICATE" "$CERT_FILE"; then
    echo "error: the provided file is not a certificate in PEM format." >&2
    exit 1
fi

# count the number of certificates in the file
CERT_COUNT=$(grep -c "BEGIN CERTIFICATE" "$CERT_FILE")

if [ "$CERT_COUNT" -gt 1 ]; then
    echo "error: testing certificate chains for crypto++ is not supported currently." >&2
    exit 1
fi

# run the x509dostool commands and determine the type
TYPE=""

if x509dostool edit -in "$CERT_FILE" -outform der -out "$EDITED_CERT_FILE" --pubout tbs spki ecdsa_fp -order 1 &>/dev/null; then
    TYPE="ecdsa_fp"
elif x509dostool edit -in "$CERT_FILE" -outform der -out "$EDITED_CERT_FILE" --pubout tbs spki ecdsa_f2m_tp -order 1  &>/dev/null; then
    TYPE="ecdsa_f2m_tp"
elif x509dostool edit -in "$CERT_FILE" -outform der -out "$EDITED_CERT_FILE" --pubout tbs spki ecdsa_f2m_pp -order 1  &>/dev/null; then
    TYPE="ecdsa_f2m_pp"
else
    echo "error: to facilitate testing for crypto++, only ecdsa public keys with explicitly included curve parameters are supported currently." >&2
    exit 1
fi

# create PUBKEY_FILE by changing the extension to .pubKey
# PUBKEY_FILE="$(realpath "${EDITED_CERT_FILE%.*}.pub")"
PUBKEY_FILE="${EDITED_CERT_FILE%.*}.pub"

# write corresponding code to TEMP_FILE
case "$TYPE" in
    "ecdsa_fp")
        cat <<EOL > "$TEMP_FILE"
#include <cryptopp/cryptlib.h>
#include <cryptopp/eccrypto.h>
#include <cryptopp/files.h>

using namespace std;
using namespace CryptoPP;

int main()
{
    DL_PublicKey_EC<ECP> pubKey;

    FileSource fs("$PUBKEY_FILE", true);

    pubKey.Load(fs);

    return 0;
}
EOL
        ;;
    "ecdsa_f2m_pp" | "ecdsa_f2m_tp")
        cat <<EOL > "$TEMP_FILE"
#include <cryptopp/cryptlib.h>
#include <cryptopp/eccrypto.h>
#include <cryptopp/files.h>

using namespace std;
using namespace CryptoPP;

int main()
{
    DL_PublicKey_EC<EC2N> pubKey;

    FileSource fs("$PUBKEY_FILE", true);

    pubKey.Load(fs);

    return 0;
}
EOL
        ;;
    *)
        echo "error: unsupported type" >&2
        exit 1
        ;;
esac

# compile the C++ code
g++ -o "$TEMP_DIR/Main" "$TEMP_FILE" -lcrypto++
if [ $? -eq 0 ]; then
    # run the compiled executable
    "$TEMP_DIR/Main"
else
    echo "error: compilation failed." >&2
    exit 1
fi