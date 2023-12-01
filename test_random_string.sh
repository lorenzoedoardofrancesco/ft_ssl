#!/bin/bash

# Array of hash algorithms
hash_algorithms=("md5" "sha224" "sha256" "sha512" "sha384" "sha512-224" "sha512-256" "whirlpool")

# Counters
total_tests=100
match_count=0
mismatch_count=0

# Arrays to store execution times
your_times=()
openssl_times=()

for (( i=1; i<=total_tests; i++ ))
do
    # Generate a random string of a random length (up to 1000 characters)
    random_string=$(tr -dc 'a-zA-Z0-9' < /dev/urandom | head -c $((RANDOM % 100000000)))

    # Select a random hash algorithm
    random_algorithm=${hash_algorithms[$RANDOM % ${#hash_algorithms[@]}]}

    # Time your hash computation in microseconds
    start_time=$(date +%s%N)
    your_hash=$(echo -n "$random_string" | ./ft_ssl $random_algorithm)
    end_time=$(date +%s%N)
    your_times+=($((end_time - start_time)))

    # Time OpenSSL hash computation in microseconds
    start_time=$(date +%s%N)
    openssl_hash=$(echo -n "$random_string" | openssl dgst -$random_algorithm | awk '{print $2}')
    end_time=$(date +%s%N)
    openssl_times+=($((end_time - start_time)))

    # Compare the results and update counters
    if [ "$your_hash" = "$openssl_hash" ]; then
        ((match_count++))
    else
        ((mismatch_count++))
    fi

done

# Function to calculate median
calculate_median() {
    arr=($(printf '%s\n' "${@}" | sort -n))
    len=${#arr[@]}
    if (( $len % 2 == 0 )); then
        echo "$(( (arr[$len / 2] + arr[$len / 2 - 1]) / 2 ))"
    else
        echo "${arr[$len / 2]}"
    fi
}

# Calculate and print median times
median_your_time=$(calculate_median "${your_times[@]}")
median_openssl_time=$(calculate_median "${openssl_times[@]}")

# Final summary
clear
echo "Testing complete!"
echo "Total tests conducted: $total_tests"
echo "Matches: $match_count"
echo "Mismatches: $mismatch_count"
echo "Median time for your SSL: $median_your_time microseconds"
echo "Median time for OpenSSL : $median_openssl_time microseconds"
echo "% difference: $((100 * ($median_your_time - $median_openssl_time) / $median_openssl_time))%"
