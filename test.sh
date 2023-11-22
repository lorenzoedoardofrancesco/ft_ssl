#!/bin/bash

# Array of hash algorithms
hash_algorithms=("md5" "sha224" "sha256" "sha512" "sha384" "sha512-224" "sha512-256" "whirlpool")

# Counters
total_tests=1000
match_count=0
mismatch_count=0

for (( i=1; i<=total_tests; i++ ))
do
    # Clear the screen for each test

    # Generate a random string of a random length (up to 1000 characters)
    random_string=$(tr -dc 'a-zA-Z0-9' < /dev/urandom | head -c $((RANDOM % 1000)))

    # Select a random hash algorithm
    random_algorithm=${hash_algorithms[$RANDOM % ${#hash_algorithms[@]}]}

    # Hash the string using your program
    your_hash=$(./ft_ssl $random_algorithm "$random_string")

    # Hash the string using OpenSSL
    openssl_hash=$(echo -n "$random_string" | openssl dgst -$random_algorithm | awk '{print $2}')

    # Compare the results and update counters
    if [ "$your_hash" = "$openssl_hash" ]; then
        ((match_count++))
    else
        ((mismatch_count++))
    fi

    # Display the current status
    echo "Running test $i of $total_tests"
    echo "Current algorithm: $random_algorithm"
    echo "Current string: $random_string"
    echo "Your hash: $your_hash"
    echo "OpenSSL hash: $openssl_hash"
    echo "Matches: $match_count"
    echo "Mismatches: $mismatch_count"
    echo "--------------------------------------"

    # Optional: Sleep for a short time to make the output readable
    sleep 0.01
done

# Final summary
clear
echo "Testing complete!"
echo "Total tests conducted: $total_tests"
echo "Matches: $match_count"
echo "Mismatches: $mismatch_count"
