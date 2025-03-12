#!/bin/bash

echo "checking the installation status of the library..."

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
    botan_version=$(botan --version)
    echo "found botan installed: $botan_version"
    installed_libraries+=("botan")
fi

# check if bouncy castle is installed
bc_jar_path=$(find / -type f -name "bcprov*.jar" 2>/dev/null | head -n 1)

if [[ -n "$bc_jar_path" && -f "$bc_jar_path" ]]; then
    bc_version=$(unzip -p "$bc_jar_path" META-INF/MANIFEST.MF 2>/dev/null | grep -i "Implementation-Version" | cut -d' ' -f2)
    echo "found bouncy castle installed: $bc_version"
    installed_libraries+=("bouncy_castle")
else
    echo "bouncy castle is not installed." >&2
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
cryptopp_header=$(find / -type f -path "*/cryptopp*/cryptlib.h" 2>/dev/null | head -n 1)

if [[ -n "$cryptopp_header" ]]; then
    version=$(echo "$cryptopp_header" | sed -E 's|.*/cryptopp([0-9]+)/cryptlib.h|\1|')
    echo "found crypto++ installed: $version"
    installed_libraries+=("crypto++")
    cryptopp_path=$(dirname "$cryptopp_header")
else
    echo "crypto++ is not installed." >&2
fi

# output the list of installed libraries
echo "installed libraries: ${installed_libraries[@]}"
printf '%.0s-' {1..80} && echo

# check if x509dostool is installed
if ! command -v x509dostool &>/dev/null; then
    echo "error: x509dostool is not installed." >&2
    exit 1
fi

# execute x509dostool detect for each installed library using the crafted certificates
trap 'echo "exiting..."; exit 0' SIGINT

for x in "${installed_libraries[@]}"; do
    script_path="scripts/run_${x}.sh"
    if [[ -f "$script_path" ]]; then
        echo "executing: x509dostool detect -libs $script_path -certs certs/"
        x509dostool detect -libs "$script_path" -certs certs/
    else
        echo "script not found for library: $script_path"
    fi
done