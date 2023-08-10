#  Pyrogram - Telegram MTProto API Client Library for Python
#  Copyright (C) 2017-present Dan <https://github.com/delivrance>
#
#  This file is part of Pyrogram.
#
#  Pyrogram is free software: you can redistribute it and/or modify
#  it under the terms of the GNU Lesser General Public License as published
#  by the Free Software Foundation, either version 3 of the License, or
#  (at your option) any later version.
#
#  Pyrogram is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU Lesser General Public License for more details.
#
#  You should have received a copy of the GNU Lesser General Public License
#  along with Pyrogram.  If not, see <http://www.gnu.org/licenses/>.

from setuptools import setup, Extension, find_packages

with open("README.md", encoding="utf-8") as f:
    readme = f.read()

setup(
    name="TgCrypto",
    version="1.2.5",
    description="Fast and Portable Cryptography Extension Library for Pyrogram",
    long_description=readme,
    long_description_content_type="text/markdown",
    url="https://github.com/pyrogram",
    download_url="https://github.com/pyrogram/tgcrypto/releases/latest",
    author="Dan",
    author_email="dan@pyrogram.org",
    license="LGPLv3+",
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: GNU Lesser General Public License v3 or later (LGPLv3+)",
        "Operating System :: OS Independent",
        "Programming Language :: C",
        "Programming Language :: Python",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: Implementation",
        "Programming Language :: Python :: Implementation :: CPython",
        "Programming Language :: Python :: Implementation :: PyPy",
        "Topic :: Security",
        "Topic :: Security :: Cryptography",
        "Topic :: Internet",
        "Topic :: Communications",
        "Topic :: Communications :: Chat",
        "Topic :: Software Development :: Libraries",
        "Topic :: Software Development :: Libraries :: Python Modules"
    ],
    keywords="pyrogram telegram crypto cryptography encryption mtproto extension library aes",
    project_urls={
        "Tracker": "https://github.com/pyrogram/tgcrypto/issues",
        "Community": "https://t.me/pyrogram",
        "Source": "https://github.com/pyrogram/tgcrypto",
        "Documentation": "https://docs.pyrogram.org",
    },
    python_requires="~=3.7",
    packages=find_packages(exclude=["tests*"]),
    test_suite="tests",
    zip_safe=False,
    ext_modules=[
        Extension(
            "tgcrypto",
            sources=[
                "tgcrypto/tgcrypto.c",
                "tgcrypto/aes256.c",
                "tgcrypto/ige256.c",
                "tgcrypto/ctr256.c",
                "tgcrypto/cbc256.c"
            ]
        )
    ]
)
