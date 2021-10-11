# TgCrypto

<img src="https://i.imgur.com/JyxrStE.png" width="160" align="right">

> Fast and Portable Cryptography Extension Library for Pyrogram

**TgCrypto** is a Cryptography Library written in C as a Python extension. It is designed to be portable, fast,
easy to install and use. TgCrypto is intended for [Pyrogram](https://github.com/pyrogram/pyrogram) and implements the
cryptographic algorithms Telegram requires, namely:

- **`AES-256-IGE`** - used in [MTProto v2.0](https://core.telegram.org/mtproto).
- **`AES-256-CTR`** - used for [CDN encrypted files](https://core.telegram.org/cdn).
- **`AES-256-CBC`** - used for [encrypted passport credentials](https://core.telegram.org/passport).

## Requirements

- Python 3.6 or higher.

## Installation

``` bash
$ pip3 install -U tgcrypto
```

## API

TgCrypto API consists of these six methods:

```python
def ige256_encrypt(data: bytes, key: bytes, iv: bytes) -> bytes: ...
def ige256_decrypt(data: bytes, key: bytes, iv: bytes) -> bytes: ...

def ctr256_encrypt(data: bytes, key: bytes, iv: bytes, state: bytes) -> bytes: ...
def ctr256_decrypt(data: bytes, key: bytes, iv: bytes, state: bytes) -> bytes: ...

def cbc256_encrypt(data: bytes, key: bytes, iv: bytes) -> bytes: ...
def cbc256_decrypt(data: bytes, key: bytes, iv: bytes) -> bytes: ...
```

## Usage

### IGE Mode

**Note**: Data must be padded to match a multiple of the block size (16 bytes).

``` python
import os

import tgcrypto

data = os.urandom(10 * 1024 * 1024 + 7)  # 10 MB of random data + 7 bytes to show padding
key = os.urandom(32)  # Random Key
iv = os.urandom(32)  # Random IV

# Pad with zeroes: -7 % 16 = 9
data += bytes(-len(data) % 16)

ige_encrypted = tgcrypto.ige256_encrypt(data, key, iv)
ige_decrypted = tgcrypto.ige256_decrypt(ige_encrypted, key, iv)

print(data == ige_decrypted)  # True
```
    
### CTR Mode (single chunk)

``` python
import os

import tgcrypto

data = os.urandom(10 * 1024 * 1024)  # 10 MB of random data

key = os.urandom(32)  # Random Key

enc_iv = bytearray(os.urandom(16))  # Random IV
dec_iv = enc_iv.copy()  # Keep a copy for decryption

ctr_encrypted = tgcrypto.ctr256_encrypt(data, key, enc_iv, bytes(1))
ctr_decrypted = tgcrypto.ctr256_decrypt(ctr_encrypted, key, dec_iv, bytes(1))

print(data == ctr_decrypted)  # True
```

### CTR Mode (stream)

``` python
import os
from io import BytesIO

import tgcrypto

data = BytesIO(os.urandom(10 * 1024 * 1024))  # 10 MB of random data

key = os.urandom(32)  # Random Key

enc_iv = bytearray(os.urandom(16))  # Random IV
dec_iv = enc_iv.copy()  # Keep a copy for decryption

enc_state = bytes(1)  # Encryption state, starts from 0
dec_state = bytes(1)  # Decryption state, starts from 0

encrypted_data = BytesIO()  # Encrypted data buffer
decrypted_data = BytesIO()  # Decrypted data buffer

while True:
    chunk = data.read(1024)

    if not chunk:
        break

    # Write 1K encrypted bytes into the encrypted data buffer
    encrypted_data.write(tgcrypto.ctr256_encrypt(chunk, key, enc_iv, enc_state))

# Reset position. We need to read it now
encrypted_data.seek(0)

while True:
    chunk = encrypted_data.read(1024)

    if not chunk:
        break

    # Write 1K decrypted bytes into the decrypted data buffer
    decrypted_data.write(tgcrypto.ctr256_decrypt(chunk, key, dec_iv, dec_state))

print(data.getvalue() == decrypted_data.getvalue())  # True
```

### CBC Mode

**Note**: Data must be padded to match a multiple of the block size (16 bytes).

``` python
import os

import tgcrypto

data = os.urandom(10 * 1024 * 1024 + 7)  # 10 MB of random data + 7 bytes to show padding
key = os.urandom(32)  # Random Key

enc_iv = bytearray(os.urandom(16))  # Random IV
dec_iv = enc_iv.copy()  # Keep a copy for decryption

# Pad with zeroes: -7 % 16 = 9
data += bytes(-len(data) % 16)

cbc_encrypted = tgcrypto.cbc256_encrypt(data, key, enc_iv)
cbc_decrypted = tgcrypto.cbc256_decrypt(cbc_encrypted, key, dec_iv)

print(data == cbc_decrypted)  # True
```

## Testing

1. Clone this repository: `git clone https://github.com/pyrogram/tgcrypto`.
2. Enter the directory: `cd tgcrypto`.
3. Install `tox`: `pip3 install tox`
4. Run tests: `tox`.

## License

[LGPLv3+](COPYING.lesser) © 2017-2020 [Dan](https://github.com/delivrance)
