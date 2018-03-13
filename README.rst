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

TgCrypto API consists of these four functions:

.. code-block:: python

    def ige_encrypt(data: bytes, key: bytes, iv: bytes) -> bytes:

.. code-block:: python

    def ige_decrypt(data: bytes, key: bytes, iv: bytes) -> bytes:

.. code-block:: python

    def ctr_encrypt(data: bytes, key: bytes, iv: bytes) -> bytes:

.. code-block:: python

    def ctr_decrypt(data: bytes, key: bytes, iv: bytes) -> bytes:

Usage
=====

TgCrypto is as simple as this example:

.. code-block:: python

    import os
    import tgcrypto

    data = os.urandom(10 * 1024 * 1024)  # 10 MB of random data
    key = os.urandom(32)  # Random Key
    iv = os.urandom(32)  # Random IV

    ige_encrypted = tgcrypto.ige_encrypt(data, key, iv)
    ige_decrypted = tgcrypto.ige_decrypt(ige_encrypted, key, iv)

    assert data == ige_decrypted

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
            <div><img src="https://pyrogram.ml/images/icon.png" alt="Pyrogram Icon"></div>
            <div><img src="https://pyrogram.ml/images/tgcrypto.png" alt="TgCrypto Logo"></div>
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
        <a href="https://github.com/pyrogram/tgcrypto">
            <img src="https://www.pyrogram.ml/images/tgcrypto_version.svg"
                alt="TgCrypto">
        </a>
    </p>

.. |logo| image:: https://pyrogram.ml/images/tgcrypto_logo.png
    :target: https://github.com/pyrogram/tgcrypto
    :alt: TgCrypto

.. |description| replace:: **Fast Telegram Crypto Library for Python**
