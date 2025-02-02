# https://github.com/Bassmmal | @bosm on discord
# ----------------------------------------------

import argparse
import random
import os
from colorama import *
init()


# --------------
# Encryption Methods
# --------------

def xor_encrypt(data, key):
    return bytes([b ^ key for b in data]), key


def caesar_encrypt(data, shift):
    return bytes([(b + shift) % 256 for b in data]), shift

def rc4_encrypt(data, key):



    S = list(range(256))
    j = 0
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) % 256
        S[i], S[j] = S[j], S[i]

    i = j = 0
    encrypted = []
    for byte in data:
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        encrypted_byte = byte ^ S[(S[i] + S[j]) % 256]
        encrypted.append(encrypted_byte)

    return bytes(encrypted), key


# --------------
# Decryption Code Generation
# --------------

def generate_decryption_code(method, key, payload_data):
    
    if method == "xor":
        c_code = f"""// Encrypted With XOR VIA https://github.com/Bassmmal/PayloadCryptic
#include <windows.h>

BYTE pPayload[] = {{{', '.join(f'0x{b:02x}' for b in payload_data)}}};
SIZE_T sPayloadSize = sizeof(pPayload);
const BYTE xor_key = 0x{key:02x};

VOID decryptPayload() {{
    for(SIZE_T i = 0; i < sPayloadSize; i++) {{
        pPayload[i] ^= xor_key;
    }}
}}
"""

    elif method == "caesar":
        c_code = f"""// Encrypted With Caesar VIA https://github.com/Bassmmal/PayloadCryptic
#include <windows.h>

BYTE pPayload[] = {{{', '.join(f'0x{b:02x}' for b in payload_data)}}};
SIZE_T sPayloadSize = sizeof(pPayload);
const BYTE shift = {key};

VOID decryptPayload() {{
    for(SIZE_T i = 0; i < sPayloadSize; i++) {{
        pPayload[i] = (pPayload[i] - shift) % 256;
    }}
}}
"""

    elif method == "rc4":
        c_code = f"""// Encrypted With RC4 VIA https://github.com/Bassmmal/PayloadCryptic
#include <windows.h>

BYTE pPayload[] = {{{', '.join(f'0x{b:02x}' for b in payload_data)}}};
SIZE_T sPayloadSize = sizeof(pPayload);
const BYTE rc4_key[] = {{{', '.join(f'0x{b:02x}' for b in key)}}};
const SIZE_T rc4_key_size = sizeof(rc4_key);

VOID rc4_decrypt(BYTE* data, SIZE_T data_size, const BYTE* key, SIZE_T key_size) {{
    BYTE S[256];
    for (int i = 0; i < 256; i++) {{
        S[i] = i;
    }}

    int j = 0;
    for (int i = 0; i < 256; i++) {{
        j = (j + S[i] + key[i % key_size]) % 256;
        BYTE temp = S[i];
        S[i] = S[j];
        S[j] = temp;
    }}

    int i = 0;
    j = 0;
    for (SIZE_T k = 0; k < data_size; k++) {{
        i = (i + 1) % 256;
        j = (j + S[i]) % 256;
        BYTE temp = S[i];
        S[i] = S[j];
        S[j] = temp;
        data[k] ^= S[(S[i] + S[j]) % 256];
    }}
}}

VOID decryptPayload() {{
    rc4_decrypt(pPayload, sPayloadSize, rc4_key, rc4_key_size);
}}
"""

    print(Fore.GREEN + "[+] Decryption code generated successfully." + Fore.RESET)
    return c_code


# --------------
# Main Execution
# --------------

def main():
    print(Fore.RED + "[#] Starting...\n" + Fore.RESET)

    parser = argparse.ArgumentParser(description="Shellcode Obfuscator")
    parser.add_argument("-i", "--input", required=True, help="Input .bin file")
    parser.add_argument("-o", "--output", required=True, help="Output file prefix")
    parser.add_argument("-m", "--method", choices=["xor", "caesar", "rc4"], required=True, help="Encryption method")
    parser.add_argument("-k", "--key", help="Optional custom key (hex for XOR, integer for Caesar, hex/string for RC4)")
    args = parser.parse_args()

    with open(args.input, "rb") as f:
        shellcode = f.read()
    print(Fore.GREEN + f"[+] Successfully read {len(shellcode)} bytes from {args.input}." + Fore.RESET)

    key = args.key

    if args.method == 'xor':
        if key:
            try:
                key = int(key, 16)
            except ValueError:
                print(Fore.RED + "[!] Invalid XOR key! provide a hex value (example: 0xAA)." + Fore.RESET)
                return
        else:
            key = random.randint(1, 255)

    elif args.method == 'caesar':
        if key:
            try:
                key = int(key)
            except ValueError:
                print(Fore.RED + "[!] Invalid Caesar key! provide an integer (example: 5)." + Fore.RESET)
                return
        else:
            key = random.randint(1, 255)

    elif args.method == 'rc4':
        if key:
            try:
                if key.startswith("0x"):
                    key = bytes.fromhex(key[2:])
                else:
                    key = key.encode()
            except ValueError:
                print(Fore.RED + "[!] Invalid RC4 key! provide a valid hex or string value (example: 'Key', 0xAA)" + Fore.RESET)
                return
        else:
            key = bytes([random.randint(0, 255) for _ in range(16)])

    print(Fore.GREEN + f'[#] Settings:\n\tEncryption Method: {args.method}\n\tEncryption {"key" if args.method != "caesar" else "shift"}: {key}' + Fore.RESET)



    if args.method == "xor":
        encrypted, key = xor_encrypt(shellcode, key)
    elif args.method == "caesar":
        encrypted, key = caesar_encrypt(shellcode, key)
    elif args.method == "rc4":
        encrypted, key = rc4_encrypt(shellcode, key)

    try: os.mkdir(args.output)
    except: pass


    with open(f"{args.output}/{args.output}.bin", "wb") as f:
        f.write(encrypted)
    print(Fore.GREEN + f"[+] Encrypted payload saved to {args.output}/{args.output}.bin" + Fore.RESET)


    output_code = generate_decryption_code(args.method, key, encrypted)


    with open(f"{args.output}/{args.output}.c", "w") as f:
        f.write(output_code)
    print(Fore.GREEN + f"[+] Decryption code saved to {args.output}/{args.output}.c" + Fore.RESET)

    print(Fore.RED + "\n[+] DONE" + Fore.RESET)


if __name__ == "__main__":
    main()
