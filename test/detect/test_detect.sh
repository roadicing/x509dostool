#!/bin/bash

# check if x509dostool is installed
if ! command -v x509dostool &>/dev/null; then
    echo "error: x509dostool is not installed." >&2
    exit 1
fi

# specify the directory to store the certificates
cert_path="$(dirname "$0")/certs"

if [ ! -d "$cert_path" ]; then
    # initialize certificates for detecting libraries
    test_commands=(
        "x509dostool generate -out $cert_path/01-a.pem test1 -m 0x7FFFFF --balanced --compressed"
        "x509dostool generate -out $cert_path/01-b.pem test1 -m 0x5FFFFFFF"
        "x509dostool generate -out $cert_path/02.pem test2 -m 74 -t 233 --compressed"
        "x509dostool generate -out $cert_path/03-a.pem test3 --balanced"
        "x509dostool generate -out $cert_path/03-b.pem test3 -p '(2**127-1)**2' --balanced"
        "x509dostool generate -out $cert_path/04-a.pem test4 -p '2**86243-1' -algo rsa"
        "x509dostool edit -in $cert_path/04-a.pem -out $cert_path/04-a.pem --pubout"
        "x509dostool generate -out $cert_path/04-b.pem test4 -p '2**86243-1'"
        "x509dostool generate -out $cert_path/05.pem test5 -sans 60000"
        "x509dostool generate -out $cert_path/06.pem test6"
        "x509dostool generate -out $cert_path/07.pem test7"
        "x509dostool generate -out $cert_path/08.pem test8 -num 4"
        "x509dostool generate -out $cert_path/09.pem test9 -num 32 --mapping"
        "x509dostool generate -out $cert_path/10.pem test10 "
    )

    echo -e "initializing..."
    for cmd in "${test_commands[@]}"; do
        eval "$cmd" > /dev/null 2>&1
        if [ $? -ne 0 ]; then
            echo -e "initialization failed: $cmd\n"
            exit 1
        fi
    done

    echo -e "the certificate to be used has been successfully generated.\n"
else
    echo -e "the \`certs\` directory already exists, skipping the initialization phase.\n"
fi

echo "checking the installation status of the library..."
echo $(printf '%0.s-' {1..80})

# initialize an empty list to store the found libraries
installed_libraries=()

# check if openssl is installed
if ! command -v openssl &>/dev/null; then
    echo -e "openssl is not installed." >&2
else
    openssl_version=$(openssl version)
    echo "found openssl installed: $openssl_version"
    installed_libraries+=("openssl")
fi

# check if botan is installed
if ! command -v botan &>/dev/null; then
    echo "botan is not installed." >&2
else
    botan_version=$(botan version)
    echo "found botan installed: $botan_version"
    installed_libraries+=("botan")
fi

# check if bouncy castle is installed
bcprov_jar_path=$(find / -type f -name "bcprov*.jar" 2>/dev/null | head -n 1)
bcpkix_jar_path=$(find / -type f -name "bcpkix*.jar" 2>/dev/null | head -n 1)

if [[ -n "$bcprov_jar_path" && -f "$bcprov_jar_path" ]]; then
    bc_version=$(unzip -p "$bcprov_jar_path" META-INF/MANIFEST.MF 2>/dev/null | grep -i "Implementation-Version" | cut -d' ' -f2)
    if [[ -n "$bcpkix_jar_path" && -f "$bcpkix_jar_path" ]]; then
        echo "found bouncy castle installed: $bc_version"
        installed_libraries+=("bouncycastle")
    else
        echo "bouncy castle (prov) is not installed." >&2
    fi
else
    echo "bouncy castle (pkix) is not installed." >&2
fi

# check if gnutls is installed
if ! command -v certtool &>/dev/null; then
    echo "gnutls is not installed." >&2
else
    certtool_version=$(certtool --version | head -n 1)
    echo "found gnutls installed: $certtool_version"
    installed_libraries+=("gnutls")
fi

# check if phpseclib is installed
phpseclib_path=$(find / -type f -path "*/phpseclib-*/vendor/autoload.php" 2>/dev/null | head -n 1)

if [[ -n "$phpseclib_path" ]]; then
    version=$(echo "$phpseclib_path" | sed -E 's|.*/phpseclib-([0-9]+\.[0-9]+\.[0-9]+)/vendor/autoload.php|\1|')
    echo "found phpseclib installed: $version"
    installed_libraries+=("phpseclib")
else
    echo "phpseclib is not installed." >&2
fi

# check if crypto++ is installed
if dpkg -s libcrypto++-dev &>/dev/null; then
    version=$(dpkg -s libcrypto++-dev | grep '^Version:' | awk '{print $2}')
    echo "found crypto++ installed: $version"
    installed_libraries+=("cryptopp")
else
    echo "crypto++ is not installed." >&2
fi

# output the list of installed libraries
printf '%.0s-' {1..80} && echo
echo -e "\e[32minstalled libraries:\e[0m ${installed_libraries[@]}"

# execute x509dostool detect for each installed library using the crafted certificates
trap 'echo "exiting..."; exit 0' SIGINT

for x in "${installed_libraries[@]}"; do
    script_path="$(dirname "$0")/scripts/run_${x}.sh"
    printf '%.0s-' {1..80} && echo
    if [[ -f "$script_path" ]]; then
        echo "executing: x509dostool detect -libs $script_path -certs $cert_path"
        x509dostool detect -libs "$script_path" -certs $cert_path
    else
        echo "script not found for library: $script_path"
    fi
done