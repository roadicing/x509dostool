#!/bin/bash

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

# check if x509dostool is installed
if ! command -v x509dostool &>/dev/null; then
    echo "error: x509dostool is not installed." >&2
    exit 1
fi

# execute x509dostool detect for each installed library using the crafted certificates
trap 'echo "exiting..."; exit 0' SIGINT

cert_path="$(dirname "$0")/certs"

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