|header|

Table of Contents
=================

-   `About`_

-   `Installation`_

-   `API`_

-   `Usage`_

-   `Contribution`_

-   `Feedback`_

-   `License`_

About
=====

**TgCrypto** is a high-performance, easy-to-install Telegram Crypto Library written in C as a Python extension.
TgCrypto is intended for Pyrogram [#f1]_ and implements the crypto algorithms Telegram requires, namely
**AES-IGE 256 bit** (used in MTProto v2.0) and **AES-CTR 256 bit** (used for CDN encrypted files).

Installation
============

.. code-block:: bash

    $ pip3 install --upgrade tgcrypto

**Note:** Being a C extension for Python, TgCrypto is an optional but *highly recommended* Pyrogram_ dependency;
if TgCrypto is not detected in your system, Pyrogram will automatically fall back to the much slower PyAES and will
show you a warning.

The reason about being an optional package is that TgCrypto requires some extra system tools in order to be compiled.
The errors you receive when trying to install TgCrypto are system dependent, but also descriptive enough to understand
what you should do next:

-  **Windows**: Install `Visual C++ 2015 Build Tools <http://landinghub.visualstudio.com/visual-cpp-build-tools>`_.
-  **macOS**: A pop-up will automatically ask you to install the command line developer tools.
-  **Linux**: Install a proper C compiler (``gcc``, ``clang``) and the Python header files (``python3-dev``).
-  **Termux (Android)**: Install ``clang`` and ``python-dev`` packages.

API
===

TgCrypto API consists of these four methods:

.. code-block:: python

    def ige256_encrypt(data: bytes, key: bytes, iv: bytes) -> bytes:

.. code-block:: python

    def ige256_decrypt(data: bytes, key: bytes, iv: bytes) -> bytes:

.. code-block:: python

    def ctr256_encrypt(data: bytes, key: bytes, iv: bytes, state: bytes) -> bytes:

.. code-block:: python

    def ctr256_decrypt(data: bytes, key: bytes, iv: bytes, state: bytes) -> bytes:

Usage
=====

IGE Mode:
---------

**Note**: Data must be padded to match a multiple of the block size (16 bytes).

.. code-block:: python

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
    
CTR Mode (single chunk):
------------------------

.. code-block:: python

    import os
    import tgcrypto

    data = os.urandom(10 * 1024 * 1024)  # 10 MB of random data
    
    key = os.urandom(32)  # Random Key

    enc_iv = bytearray(os.urandom(16))  # Random IV
    dec_iv = enc_iv.copy()  # Keep a copy for decryption

    ctr_encrypted = tgcrypto.ctr256_encrypt(data, key, enc_iv, bytes(1))
    ctr_decrypted = tgcrypto.ctr256_decrypt(ctr_encrypted, key, dec_iv, bytes(1))

    print(data == ctr_decrypted)  # True

CTR Mode (stream):
------------------

.. code-block:: python

    import os
    import tgcrypto
    from io import BytesIO

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

Contribution
============

**You are very welcome to contribute** by either submitting pull requests or
reporting issues/bugs as well as suggesting best practices, ideas, enhancements
on both code and documentation. Any help is appreciated!

Feedback
========

Means for getting in touch:

-   `Community`_
-   `Telegram`_
-   `GitHub`_
-   `Email`_

License
=======

-   Copyright (C) 2017-2018 Dan Tès <https://github.com/delivrance>

-   Licensed under the terms of the
    `GNU Lesser General Public License v3 or later (LGPLv3+)`_

-----

.. [#f1] Although TgCrypto is intended for `Pyrogram`_, it is shipped as a standalone package and can thus be used for
   any other Python project too.

.. _`Community`: https://t.me/PyrogramChat

.. _`Telegram`: https://t.me/haskell

.. _`GitHub`: https://github.com/pyrogram/tgcrypto/issues

.. _`Email`: admin@pyrogram.ml

.. _`GNU Lesser General Public License v3 or later (LGPLv3+)`: COPYING.lesser

.. _`Pyrogram`: https://github.com/pyrogram/pyrogram

.. |header| raw:: html

    <h1 align="center">
        <a href="https://github.com/pyrogram/tgcrypto">
            <div><img src="https://raw.githubusercontent.com/pyrogram/logos/master/logos/tgcrypto_logo2.png" alt="TgCrypto Logo"></div>
        </a>
    </h1>

    <p align="center">
        <b>Fast Telegram Crypto Library for Python</b>

        <br>
        <a href="https://pypi.python.org/pypi/TgCrypto">
            Download
        </a>
        •
        <a href="https://docs.pyrogram.ml/resources/TgCrypto">
            Documentation
        </a>
        •
        <a href="https://t.me/PyrogramChat">
            Community
        </a>
        <br><br>
        <a href="https://github.com/pyrogram/pyrogram">
            <img src="https://img.shields.io/badge/PYROGRAM-V0.8.0-eda738.svg?longCache=true&style=for-the-badge&colorA=262b30"
                alt="TgCrypto">
        </a>
        
        <a href="https://github.com/pyrogram/tgcrypto">
            <img src="https://img.shields.io/badge/TGCRYPTO-V1.1.1-eda738.svg?longCache=true&style=for-the-badge&colorA=262b30"
                alt="TgCrypto">
        </a>
    </p>

.. |logo| image:: https://raw.githubusercontent.com/pyrogram/logos/master/logos/tgcrypto_logo2.png
    :target: https://github.com/pyrogram/tgcrypto
    :alt: TgCrypto

.. |description| replace:: **Fast Telegram Crypto Library for Python**
