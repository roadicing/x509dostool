#!/bin/bash

# check if crypto++ is installed
if dpkg -s libcrypto++-dev &>/dev/null; then
    version=$(dpkg -s libcrypto++-dev | grep '^Version:' | awk '{print $2}')
    echo "found crypto++ installed: $version"
    installed_libraries+=("cryptopp")
else
    echo "crypto++ is not installed." >&2
    exit 1
fi

TEMP_DIR="$(dirname "$0")/tmp"

echo $TEMP_DIR

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
EDITED_CERT_FILE="test.crt"

# ensure the provided certificate is in PEM format
if ! grep -q "BEGIN CERTIFICATE" "$CERT_FILE" || ! grep -q "END CERTIFICATE" "$CERT_FILE"; then
    echo "error: the provided file is not a certificate in PEM format." >&2
    exit 1
fi

# run the x509dostool commands and determine the type
TYPE=""

if x509dostool edit -in "$CERT_FILE" -outform der -out "$TEMP_DIR/$EDITED_CERT_FILE" --pubout tbs spki ecdsa_fp -order 1 &>/dev/null; then
    TYPE="ecdsa_fp"
elif x509dostool edit -in "$CERT_FILE" -outform der -out "$TEMP_DIR/$EDITED_CERT_FILE" --pubout tbs spki ecdsa_f2m_tp -order 1  &>/dev/null; then
    TYPE="ecdsa_f2m_tp"
elif x509dostool edit -in "$CERT_FILE" -outform der -out "$TEMP_DIR/$EDITED_CERT_FILE" --pubout tbs spki ecdsa_f2m_pp -order 1  &>/dev/null; then
    TYPE="ecdsa_f2m_pp"
else
    echo "error: currently not supported" >&2
    exit 1
fi

echo $TYPE
#echo "$TEMP_DIR/$EDITED_CERT_FILE"

# create PUBKEY_FILE by changing the extension to .pubKey
#PUBKEY_FILE="$(realpath "$TEMP_DIR/${EDITED_CERT_FILE%.*}.pub")"

# PUBKEY_FILE="${EDITED_CERT_FILE%.*}.pub"
CERT_PATH=$(realpath "$EDITED_CERT_FILE")
PUBKEY_FILE="$TEMP_DIR/$(basename "${CERT_PATH%.*}.pub")"
#PUBKEY_FILE="${CERT_PATH%.*}.pub" 
echo $PUBKEY_FILE

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

    FileSource fs("$PUBKEY_FILE", true);  // Write absolute path of PUBKEY_FILE here

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

    FileSource fs("$PUBKEY_FILE", true);  // Write absolute path of PUBKEY_FILE here

    pubKey.Load(fs); // segmentation fault

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