## PayloadCryptic

Encrypt your shellcode using various algorithms, such as (XOR, Caesar, RC4) and then generate the code responsible for decryption written in C lang


## Usage

1. Use `PayloadCryptic.py` to encrypt a shellcode using different encryption algorithms (xor, caesar, rc4):
```
usage: PayloadCryptic.py [-h] -i INPUT -o OUTPUT -m {xor,caesar,rc4} [-k KEY]
Shellcode Obfuscator

options:
  -h, --help            show this help message and exit
  -i INPUT, --input INPUT
                        Input .bin file
  -o OUTPUT, --output OUTPUT
                        Output file prefix
  -m {xor,caesar,rc4}, --method {xor,caesar,rc4}
                        Encryption method
  -k KEY, --key KEY     Optional custom key (hex for XOR, integer for Caesar, hex/string for RC4)
```

2. Examples:
- ```python .\PayloadCryptic.py --input .\payload.bin --output Encrypted --method rc4```
- ```python .\PayloadCryptic.py --input .\payload.bin --output Encrypted --method rc4 --key VerySecretKey```

3. Example Output:
```
> python .\PayloadCryptic.py --input .\payload.bin --output Encrypted --method rc4

[#] Starting...

[+] Successfully read 272 bytes from .\payload.bin.
[#] Settings:
        Encryption Method: rc4
        Encryption key: 0xef, 0xd6, 0x7c, 0x7b, 0x9c, 0xfa, 0x47, 0xca, 0xc4, 0x69, 0xd1, 0x0d, 0x1a, 0x87, 0xbf, 0x48
[+] Encrypted payload saved to Encrypted/Encrypted.bin
[+] Decryption code generated successfully.
[+] Decryption code saved to Encrypted/Encrypted.c

[+] DONE
```

