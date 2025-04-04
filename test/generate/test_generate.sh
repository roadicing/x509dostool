#!/bin/bash

# check if x509dostool is installed
if ! command -v x509dostool &>/dev/null; then
    echo "error: x509dostool is not installed." >&2
    exit 1
fi

# define the list of commands
test_generate_commands=(
    "x509dostool generate -out test.crt test0 -algo ecdsa -name secp256k1 --explicit --compressed"
    "x509dostool generate -out test.crt test1 -m 1023 --balanced --compressed"
    "x509dostool generate -out test.crt test2 -m 1023 -t 65535 --balanced --compressed"
    "x509dostool generate -out test.crt test3 -p 1023 --balanced"
    "x509dostool generate -out test.crt test4 -p 1023 --balanced --compressed"
    "x509dostool generate -out test.crt test5 -emails 3 -sans 3 -ncs 3 -policies 3"
    "x509dostool generate -out test.crt test6 -length 1023"
    "x509dostool generate -out test.crt test7 -length 1023"
    "x509dostool generate -out test.crt test8 -num 3 -sans 1023 -ncs 1023"
    "x509dostool generate -out test.crt test9 -num 3 -policies 3 --mapping"
    "x509dostool generate -out test.crt test10 -num 3 -repeat 3"
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
for cmd in "${test_generate_commands[@]}"; do
    total_count=$((total_count + 1))  # increment total command count
    test_name=$(echo "$cmd" | grep -oP 'test[0-9]+')  # extract test name correctly (match 'test' followed by digits)

    # always output the command in the screen, regardless of verbose
    echo -e "\e[32mrunning\e[0m: $cmd"

    # execute the command to generate the certificate
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

    # check if the certificate was successfully generated
    if [[ ! -f "test.crt" ]]; then
        failure_count=$((failure_count + 1))  # increment failure count
        echo -e "error: certificate not generated by command: $cmd\n"
        continue
    fi

    # check if it's test6 and handle the special case
    if [[ "$cmd" == *"test6"* ]]; then
        # attempt to parse the generated certificate with openssl asn1parse
        echo "parsing the certificate generated by test6 with openssl asn1parse..."
        parse_output=$(openssl asn1parse -in test.crt 2>&1)
        
        # check if the output contains "header too long"
        if echo "$parse_output" | grep -q "header too long"; then
            success_count=$((success_count + 1))  # count as success for test6
            echo "successfully parsed the certificate generated by test6 (header too long is expected)"
        else
            # if no "header too long" error, handle as normal failure
            echo "error: failed to parse the certificate generated by test6"
            failure_count=$((failure_count + 1))
        fi

        # output the parse result in verbose mode
        if [[ "$verbose" == true ]]; then
            echo "$parse_output"
        fi
    else
        # try to parse the generated certificate with openssl asn1parse for other tests
        echo "parsing the certificate with openssl asn1parse..."
        parse_output=$(openssl asn1parse -in test.crt 2>&1)
        
        if [[ $? -eq 0 ]]; then
            success_count=$((success_count + 1))  # increment success count
            echo "successfully parsed the certificate generated by $test_name"
        else
            failure_count=$((failure_count + 1))  # increment failure count
            echo "error: failed to parse the certificate generated by $test_name"
        fi

        # output the parse result in verbose mode
        if [[ "$verbose" == true ]]; then
            echo "$parse_output"
        fi
    fi

    # add a newline after each test command (for readability)
    echo ""

    # optional: clean up the generated certificate for the next test
    rm -f test.crt
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