import subprocess

TEST_CASES = [
    ("echo '42 is nice' | openssl md5", "MD5(stdin)= 35f1d6de0302e2086a4e472266efb3a9"),
    ("echo '42 is nice' | md5sum", "35f1d6de0302e2086a4e472266efb3a9  -"),
    ("echo '42 is nice' | ./ft_ssl md5", "MD5(stdin)= 35f1d6de0302e2086a4e472266efb3a9"),
    ("echo '42 is nice' | ./ft_ssl md5 -p", "(\"42 is nice\")= 35f1d6de0302e2086a4e472266efb3a9"),

    ("echo 'Pity the living.' | ./ft_ssl md5 -q -r", "e20c3b973f63482a778f3fd1869b7f25"),

    ("echo 'And above all,' > file", None),  # setup
    ("./ft_ssl md5 file", "MD5(file)= 53d53ea94217b259c11a5a2d104ec58a"),
    ("./ft_ssl md5 -r file", "53d53ea94217b259c11a5a2d104ec58a file"),

    ("./ft_ssl md5 -s \"pity those that aren't following baerista on spotify.\"", "MD5(\"pity those that aren't following baerista on spotify.\")= a3c990a1964705d9bf0e602f44572f5f"),

    ("echo 'be sure to handle edge cases carefully' | ./ft_ssl md5 -p file", 
     "(\"be sure to handle edge cases carefully\")= 3553dc7dc5963b583c056d1b9fa3349c\nMD5(file)= 53d53ea94217b259c11a5a2d104ec58a"),

    ("echo 'some of this will not make sense at first' | ./ft_ssl md5 file", "MD5(file)= 53d53ea94217b259c11a5a2d104ec58a"),

    ("echo 'but eventually you will understand' | ./ft_ssl md5 -p -r file", 
     "(\"but eventually you will understand\")= dcdd84e0f635694d2a943fa8d3905281\n53d53ea94217b259c11a5a2d104ec58a file"),

    ("echo \"GL HF let's go\" | ./ft_ssl md5 -p -s \"foo\" file", 
     "(\"GL HF let's go\")= d1e3cc342b6da09480b27ec57ff243e2\nMD5(\"foo\")= acbd18db4cc2f85cedef654fccc4a4d8\nMD5(file)= 53d53ea94217b259c11a5a2d104ec58a"),

    ("echo 'one more thing' | ./ft_ssl md5 -r -p -s \"foo\" file -s \"bar\"", 
     "(\"one more thing\")= a0bd1876c6f011dd50fae52827f445f5\nacbd18db4cc2f85cedef654fccc4a4d8 \"foo\"\n53d53ea94217b259c11a5a2d104ec58a file\n-s: No such file or directory\nbar: No such file or directory"),

    ("echo 'just to be extra clear' | ./ft_ssl md5 -r -q -p -s \"foo\" file", 
     "just to be extra clear\n3ba35f1ea0d170cb3b9a752e3360286c\nacbd18db4cc2f85cedef654fccc4a4d8\n53d53ea94217b259c11a5a2d104ec58a"),

    ("echo 'https://www.42.fr/' > website", None),  # setup
    ("./ft_ssl sha256 -q website", "1ceb55d2845d9dd98557b50488db12bbf51aaca5aa9c1199eb795607a2457daf"),
    ("sha256sum website", "1ceb55d2845d9dd98557b50488db12bbf51aaca5aa9c1199eb795607a2457daf  website"),

    ("./ft_ssl sha256 -s \"42 is nice\"", "SHA256(\"42 is nice\")= b7e44c7a40c5f80139f0a50f3650fb2bd8d00b0d24667c4c2ca32c88e13b758f"),

    ("echo -n '42 is nice' | sha256sum", "b7e44c7a40c5f80139f0a50f3650fb2bd8d00b0d24667c4c2ca32c88e13b758f  -"),
]

def run_command(cmd):
    result = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    return result.stdout.strip()

def print_diff(expected, got):
    print("  Expected:")
    print(f"    {expected}")
    print("  Got:")
    print(f"    {got}")

def run_tests():
    print("\n[ ft_ssl CLI Strict Output Test ]\n")
    passed = 0
    failed = 0

    for cmd, expected in TEST_CASES:
        if expected is None:
            run_command(cmd)
            print(f"[SETUP] {cmd}")
            continue

        output = run_command(cmd)
        if output == expected:
            print(f"[PASS] {cmd}")
            passed += 1
        else:
            print(f"[FAIL] {cmd}")
            print_diff(expected, output)
            failed += 1

    print(f"\n=== Summary ===\n  Passed: {passed}\n  Failed: {failed}\n")

if __name__ == "__main__":
    run_tests()
