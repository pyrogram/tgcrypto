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

uint8_t *ctr256(const uint8_t in[], uint32_t length, const uint8_t key[32], const uint8_t iv[16]) {
    uint8_t *out = (uint8_t *) malloc(length * sizeof(uint8_t));
    uint8_t iv_buf[AES_BLOCK_SIZE], out_buf[AES_BLOCK_SIZE];
    uint32_t key_schedule[KEY_SCHEDULE_SIZE];

    memcpy(out, in, length);
    memcpy(iv_buf, iv, AES_BLOCK_SIZE);
    aes256_key_expansion(key, key_schedule);

    uint32_t i = 0, j;
    if (length > AES_BLOCK_SIZE)
        for (i = 0; i < length - AES_BLOCK_SIZE; i += AES_BLOCK_SIZE) {
            aes256_encrypt(iv_buf, out_buf, key_schedule);

            for (j = 0; j < AES_BLOCK_SIZE; ++j)
                out[i + j] ^= out_buf[j];

            for (j = AES_BLOCK_SIZE - 1; j >= 0; --j)
                if (++iv_buf[j])
                    break;
        }

    aes256_encrypt(iv_buf, out_buf, key_schedule);

    for (j = 0; j < length - i; ++j)
        out[i + j] ^= out_buf[j];

    return out;
}

uint8_t *ctr256_encrypt(uint8_t *in, uint32_t length, uint8_t *key, uint8_t *iv) {
    return ctr256(in, length, key, iv);
}

uint8_t *ctr256_decrypt(uint8_t *in, uint32_t length, uint8_t *key, uint8_t *iv) {
    return ctr256(in, length, key, iv);
}
