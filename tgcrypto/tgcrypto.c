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

#include <Python.h>
#include "aes256.h"
#include "ige256.h"
#include "ctr256.h"

static PyObject* tgcrypto(PyObject *args, uint8_t mode, uint8_t encrypt) {
    Py_buffer data, key, iv;
    uint8_t *(*fn)(), *buf;
    PyObject* out;

    PyArg_ParseTuple(args, "y*y*y*", &data, &key, &iv);
    fn = encrypt? mode? ctr256_encrypt: ige256_encrypt: mode? ctr256_decrypt: ige256_decrypt;
    buf = fn(data.buf, data.len, key.buf, iv.buf);

    PyBuffer_Release(&data);
    PyBuffer_Release(&key);
    PyBuffer_Release(&iv);

    out = Py_BuildValue("y#", buf, data.len);
    free(buf);

    return out;
}

static PyObject* ige_encrypt(PyObject *self, PyObject *args) {
    return tgcrypto(args, 0, 1);
}


static PyObject* ige_decrypt(PyObject *self, PyObject *args) {
    return tgcrypto(args, 0, 0);
}

static PyObject* ctr_encrypt(PyObject *self, PyObject *args) {
    return tgcrypto(args, 1, 1);
}


static PyObject* ctr_decrypt(PyObject *self, PyObject *args) {
    return tgcrypto(args, 1, 0);
}

static PyMethodDef methods[] = {
    {"ige_encrypt", (PyCFunction) ige_encrypt, METH_VARARGS, "AES-256-IGE Encryption"},
    {"ige_decrypt", (PyCFunction) ige_decrypt, METH_VARARGS, "AES-256-IGE Decryption"},
    {"ctr_encrypt", (PyCFunction) ctr_encrypt, METH_VARARGS, "AES-256-CTR Encryption"},
    {"ctr_decrypt", (PyCFunction) ctr_decrypt, METH_VARARGS, "AES-256-CTR Decryption"},
    {NULL,      NULL,                      0,            NULL}
};

static struct PyModuleDef module = {
    PyModuleDef_HEAD_INIT,
    "tgcrypto",
    "Telegram Crypto for Pyrogram",
    -1,
    methods
};

PyMODINIT_FUNC PyInit_tgcrypto(void) {
    return PyModule_Create(&module);
}
