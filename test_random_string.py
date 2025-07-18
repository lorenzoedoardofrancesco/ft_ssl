import subprocess
import random
import statistics
import time
import argparse

parser = argparse.ArgumentParser(description="Compare ft_ssl and OpenSSL hashing performance on all algorithms")
parser.add_argument('-n', '--tests', type=int, default=10, help='Number of tests per algorithm (default: 10)')
parser.add_argument('--minlen', type=int, default=100000, help='Minimum random string length (default: 100000)')
parser.add_argument('--maxlen', type=int, default=100000, help='Maximum random string length (default: 100000)')
args = parser.parse_args()

hash_algorithms = ["md5", "sha224", "sha256", "sha384", "sha512", "sha512-224", "sha512-256"]

def run_command(cmd, input_data):
    result = subprocess.run(cmd, input=input_data, text=True, capture_output=True)
    return result.stdout.strip()

global_matches = 0
global_mismatches = 0

for alg in hash_algorithms:
    matches = 0
    mismatches = 0
    your_times = []
    openssl_times = []

    print(f"\n--- Testing {alg} ---")
    for _ in range(args.tests):
        rand_len = random.randint(args.minlen, args.maxlen)
        rand_str = ''.join(random.choices('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789', k=rand_len))

        start = time.perf_counter_ns()
        your_hash = run_command(["./ft_ssl", alg], rand_str)
        your_times.append(time.perf_counter_ns() - start)

        start = time.perf_counter_ns()
        openssl_hash = run_command(["openssl", "dgst", f"-{alg}"], rand_str).split()[-1]
        openssl_times.append(time.perf_counter_ns() - start)

        if your_hash == openssl_hash:
            matches += 1
        else:
            mismatches += 1

    median_your = statistics.median(your_times) // 1000  # in microseconds
    median_openssl = statistics.median(openssl_times) // 1000
    delta_percent = 100 * (median_your - median_openssl) / median_openssl if median_openssl else float('inf')

    print(f"Matches: {matches}/{args.tests}   Mismatches: {mismatches}")
    print(f"Median time (µs) — ft_ssl: {median_your}   OpenSSL: {median_openssl}   Δ: {delta_percent:.2f}%")

    global_matches += matches
    global_mismatches += mismatches

print(f"\n=== Summary ===")
print(f"Total tests: {args.tests * len(hash_algorithms)}   Matches: {global_matches}   Mismatches: {global_mismatches}")
