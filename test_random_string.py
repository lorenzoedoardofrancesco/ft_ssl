import subprocess
import random
import statistics
import time
import argparse

parser = argparse.ArgumentParser(description="Compare ft_ssl and OpenSSL hashing performance")
parser.add_argument('-n', '--tests', type=int, default=100, help='Number of tests to run (default: 100)')
parser.add_argument('--minlen', type=int, default=100000, help='Minimum random string length (default: 64)')
parser.add_argument('--maxlen', type=int, default=100000, help='Maximum random string length (default: 100000)')
args = parser.parse_args()

hash_algorithms = ["md5", "sha224", "sha256", "sha384", "sha512", "sha512-224", "sha512-256"]
matches = 0
mismatches = 0
your_times = []
openssl_times = []

def run_command(cmd, input_data):
    return subprocess.run(cmd, input=input_data, text=True, capture_output=True).stdout.strip()

for _ in range(args.tests):
    rand_len = random.randint(args.minlen, args.maxlen)
    rand_str = ''.join(random.choices('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789', k=rand_len))
    alg = random.choice(hash_algorithms)

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

median_your = statistics.median(your_times)
median_openssl = statistics.median(openssl_times)
delta_percent = 100 * (median_your - median_openssl) / median_openssl

print(f"\nTests: {args.tests}  Matches: {matches}  Mismatches: {mismatches}")
print(f"String length: {args.minlen}..{args.maxlen} chars")
print(f"Median time (µs) — ft_ssl: {median_your // 1000}   OpenSSL: {median_openssl // 1000}   Δ: {delta_percent:.2f}%")
