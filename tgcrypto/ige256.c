// Pyrogram - Telegram MTProto API Client Library for Python
// Copyright (C) 2017-2018 Dan Tès <https://github.com/delivrance>
//
// This file is part of Pyrogram.
//
// Pyrogram is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published
// by the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// Pyrogram is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with Pyrogram.  If not, see <http://www.gnu.org/licenses/>.

#include "aes256.h"

uint8_t *ige256(const uint8_t in[], uint32_t length, const uint8_t key[32], const uint8_t iv[32], uint8_t encrypt) {
    uint8_t *out = (uint8_t *) malloc(length * sizeof(uint8_t));
    uint8_t iv_1[AES_BLOCK_SIZE], iv_2[AES_BLOCK_SIZE];
    uint8_t chunk[AES_BLOCK_SIZE], buffer[AES_BLOCK_SIZE];
    uint32_t key_schedule[KEY_SCHEDULE_SIZE];

    memcpy(encrypt ? iv_1 : iv_2, (uint8_t *) iv, AES_BLOCK_SIZE);
    memcpy(encrypt ? iv_2 : iv_1, (uint8_t *) iv + AES_BLOCK_SIZE, AES_BLOCK_SIZE);
    aes256_key_expansion(key, key_schedule);

    uint32_t i, j;
    for (i = 0; i < length; i += AES_BLOCK_SIZE) {
        memcpy(chunk, &in[i], AES_BLOCK_SIZE);

        for (j = 0; j < AES_BLOCK_SIZE; ++j)
            buffer[j] = in[i + j] ^ iv_1[j];

        (encrypt ? aes256_encrypt : aes256_decrypt)((uint8_t *) &buffer, &out[i], key_schedule);

        for (j = 0; j < AES_BLOCK_SIZE; ++j)
            out[i + j] ^= iv_2[j];

        memcpy(iv_1, &out[i], AES_BLOCK_SIZE);
        memcpy(iv_2, chunk, AES_BLOCK_SIZE);
    }

    return out;
}

uint8_t *ige256_encrypt(const uint8_t in[], uint32_t length, const uint8_t key[32], const uint8_t iv[32]) {
    return ige256(in, length, key, iv, 1);
}

uint8_t *ige256_decrypt(const uint8_t in[], uint32_t length, const uint8_t key[32], const uint8_t iv[32]) {
    return ige256(in, length, key, iv, 0);
}
