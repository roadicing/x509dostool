#!/bin/bash

# check if x509dostool is installed
if ! command -v x509dostool &>/dev/null; then
    echo "error: x509dostool is not installed." >&2
    exit 1
fi

# specify the directory to store the certificates
cert_path="$(dirname "$0")/certs"

if [ ! -d "$cert_path" ]; then
    # initialize certificates for editing
    test_generate_commands=(
        "x509dostool generate -out $cert_path/test.crt test0"
        "x509dostool generate -out $cert_path/test_rsa.crt test0 -algo rsa"
        "x509dostool generate -out $cert_path/test_dsa.crt test0 -algo dsa"
        "x509dostool generate -out $cert_path/test_ecdsa.crt test0 -algo ecdsa"
        "x509dostool generate -out $cert_path/test_ecdsa_fp.crt test0 -algo ecdsa --explicit"
        "x509dostool generate -out $cert_path/test_ecdsa_f2m_tp.crt test0 -algo ecdsa -name sect233r1 --explicit"
        "x509dostool generate -out $cert_path/test_ecdsa_f2m_pp.crt test0 -algo ecdsa -name sect283r1 --explicit"
    )

    echo -e "initializing..."
    for cmd in "${test_generate_commands[@]}"; do
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

# define the list of commands for editing
test_edit_commands=(
    "x509dostool edit -in $cert_path/test.crt -out edited_test.crt tbs ver -ver 1023"
    "x509dostool edit -in $cert_path/test.crt -out edited_test.crt tbs sn -sn 1023"
    "x509dostool edit -in $cert_path/test.crt -out edited_test.crt tbs sig -algo 1.2.1023"
    "x509dostool edit -in $cert_path/test.crt -out edited_test.crt tbs issuer -types 1.2.1023 1.2.65535 -values test1 test2"
    "x509dostool edit -in $cert_path/test.crt -out edited_test.crt tbs subject -types 1.2.1023 1.2.65535 -values test1 test2"
    "x509dostool edit -in $cert_path/test_rsa.crt -out edited_test.crt tbs spki rsa -algo 1.2.1023 -n 1023 -e 1023"
    "x509dostool edit -in $cert_path/test_dsa.crt -out edited_test.crt tbs spki dsa -algo 1.2.1023 -p 1023 -q 1023 -g 1023 -pub 2**20-1"
    "x509dostool edit -in $cert_path/test_ecdsa.crt -out edited_test.crt tbs spki ecdsa -algo 1.2.1023 -name secp256k1 -P 040102030405060708090A --compressed"
    "x509dostool edit -in $cert_path/test_ecdsa_fp.crt -out edited_test.crt tbs spki ecdsa_fp -algo 1.2.1023 -p 1023 -a 1023 -b 1023 -G 040102030405060708090A -order 1023 -cofactor 1023 -seed 2**50-1 -P 040102030405060708090A --balanced --compressed"
    "x509dostool edit -in $cert_path/test_ecdsa_f2m_tp.crt -out edited_test.crt tbs spki ecdsa_f2m_tp -algo 1.2.1023 -m 1023 -t 1023 -a 1023 -b 1023 -G 040102030405060708090A -order 1023 -cofactor 1023 -seed 2**50-1 -P 040102030405060708090A --balanced --compressed"
    "x509dostool edit -in $cert_path/test_ecdsa_f2m_pp.crt -out edited_test.crt tbs spki ecdsa_f2m_pp -algo 1.2.1023 -m 1023 -t3 1023 -t2 1023 -t1 1023 -a 1023 -b 1023 -G 040102030405060708090A -order 1023 -cofactor 1023 -seed 2**50-1 -P 040102030405060708090A --balanced --compressed"
)

# check for the --verbose flag
verbose=false
if [[ "$1" == "--verbose" ]]; then
    verbose=true
    echo "verbose mode enabled."
fi

# initialize counters for statistics
total_count=0
success_count=0
failure_count=0

# loop through each command in the list
for cmd in "${test_edit_commands[@]}"; do
    total_count=$((total_count + 1))  # increment total command count

    # always output the command in the screen, regardless of verbose
    echo -e "\e[32mrunning\e[0m: $cmd"

    # execute the command to edit the certificate
    if [[ "$verbose" == true ]]; then
        output=$(eval "$cmd" 2>&1)
        echo "$output"
    else
        eval "$cmd" > /dev/null 2>&1
    fi
    
    # check if the command executed successfully
    if [[ $? -ne 0 ]]; then
        failure_count=$((failure_count + 1))  # increment failure count
        echo -e "error: command failed: $cmd\n"
        continue
    fi

    # check if the certificate was successfully edited
    if [[ ! -f "edited_test.crt" ]]; then
        failure_count=$((failure_count + 1))  # increment failure count
        echo -e "error: certificate not edited by command: $cmd\n"
        continue
    fi

    # try to parse the edited certificate with openssl asn1parse for other tests
    echo "parsing the certificate with openssl asn1parse..."
    parse_output=$(openssl asn1parse -in edited_test.crt 2>&1)
    
    if [[ $? -eq 0 ]]; then
        success_count=$((success_count + 1))  # increment success count
        echo "successfully parsed the certificate."
    else
        failure_count=$((failure_count + 1))  # increment failure count
        echo "error: failed to parse the certificate."
    fi

    # output the parse result in verbose mode
    if [[ "$verbose" == true ]]; then
        echo "$parse_output"
    fi

    # add a newline after each test command (for readability)
    echo ""

    # optional: clean up the edited certificate for the next test
    rm -f edited_test.crt
done

# output the final statistics
echo "-----"
echo "total commands: $total_count"
echo "successful commands: $success_count"
echo "failed commands: $failure_count"

# check if all tests passed
if [[ $failure_count -eq 0 ]]; then
    echo "all tests passed"
else
    echo "some tests failed"
fi