#!/bin/bash

# Array of hash algorithms
hash_algorithms=("md5" "sha224" "sha256" "sha512" "sha384" "sha512-224" "sha512-256" "whirlpool")

# Path to the large file
large_file_path="large_file.txt"

# Arrays to store execution times
your_times=()
openssl_times=()

for algorithm in "${hash_algorithms[@]}"
do
    echo "Testing algorithm: $algorithm"

    # Time your hash computation in microseconds
    start_time=$(date +%s%N)
    your_hash=$(cat "$large_file_path" | ./ft_ssl $algorithm)
    end_time=$(date +%s%N)
    your_time=$((end_time - start_time))
    your_times+=($your_time)

    # Time OpenSSL hash computation in microseconds
    start_time=$(date +%s%N)
    openssl_hash=$(cat "$large_file_path" | openssl dgst -$algorithm)
    end_time=$(date +%s%N)
    openssl_time=$((end_time - start_time))
    openssl_times+=($openssl_time)

    # Display the results
    echo "Your SSL ($algorithm) time: $your_time microseconds"
    echo "OpenSSL ($algorithm)  time: $openssl_time microseconds"
    echo "--------------------------------------"
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
echo "Testing complete!"
echo "Median time for your SSL: $median_your_time microseconds"
echo "Median time for OpenSSL: $median_openssl_time microseconds"
