/*
 * Pyrogram - Telegram MTProto API Client Library for Python
 * Copyright (C) 2017-2020 Dan <https://github.com/delivrance>
 *
 * This file is part of Pyrogram.
 *
 * Pyrogram is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published
 * by the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * Pyrogram is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with Pyrogram.  If not, see <http://www.gnu.org/licenses/>.
 */

#define PY_SSIZE_T_CLEAN
#include <Python.h>

#include "aes256.h"
#include "ige256.h"
#include "ctr256.h"
#include "cbc256.h"

static PyObject *ige(PyObject *args, uint8_t encrypt) {
    Py_buffer data, key, iv;
    uint8_t *buf;
    PyObject *out;

    if (!PyArg_ParseTuple(args, "y*y*y*", &data, &key, &iv))
        return NULL;

    if (data.len == 0) {
        PyErr_SetString(PyExc_ValueError, "Data must not be empty");
        return NULL;
    }

    if (data.len % 16 != 0) {
        PyErr_SetString(PyExc_ValueError, "Data size must match a multiple of 16 bytes");
        return NULL;
    }

    if (key.len != 32) {
        PyErr_SetString(PyExc_ValueError, "Key size must be exactly 32 bytes");
        return NULL;
    }

    if (iv.len != 32) {
        PyErr_SetString(PyExc_ValueError, "IV size must be exactly 32 bytes");
        return NULL;
    }

    Py_BEGIN_ALLOW_THREADS
    buf = ige256(data.buf, data.len, key.buf, iv.buf, encrypt);
    Py_END_ALLOW_THREADS

    PyBuffer_Release(&data);
    PyBuffer_Release(&key);
    PyBuffer_Release(&iv);

    out = Py_BuildValue("y#", buf, data.len);
    free(buf);

    return out;
}

static PyObject *ige256_encrypt(PyObject *self, PyObject *args) {
    return ige(args, 1);
}

static PyObject *ige256_decrypt(PyObject *self, PyObject *args) {
    return ige(args, 0);
}

static PyObject *ctr256_encrypt(PyObject *self, PyObject *args) {
    Py_buffer data, key, iv, state;
    uint8_t *buf;
    PyObject *out;

    if (!PyArg_ParseTuple(args, "y*y*y*y*", &data, &key, &iv, &state))
        return NULL;

    if (data.len == 0) {
        PyErr_SetString(PyExc_ValueError, "Data must not be empty");
        return NULL;
    }

    if (key.len != 32) {
        PyErr_SetString(PyExc_ValueError, "Key size must be exactly 32 bytes");
        return NULL;
    }

    if (iv.len != 16) {
        PyErr_SetString(PyExc_ValueError, "IV size must be exactly 16 bytes");
        return NULL;
    }

    if (state.len != 1) {
        PyErr_SetString(PyExc_ValueError, "State size must be exactly 1 byte");
        return NULL;
    }

    if (*(uint8_t *) state.buf > 15) {
        PyErr_SetString(PyExc_ValueError, "State value must be in the range [0, 15]");
        return NULL;
    }

    Py_BEGIN_ALLOW_THREADS
    buf = ctr256(data.buf, data.len, key.buf, iv.buf, state.buf);
    Py_END_ALLOW_THREADS

    PyBuffer_Release(&data);
    PyBuffer_Release(&key);
    PyBuffer_Release(&iv);

    out = Py_BuildValue("y#", buf, data.len);
    free(buf);

    return out;
}

static PyObject *cbc(PyObject *args, uint8_t encrypt) {
    Py_buffer data, key, iv;
    uint8_t *buf;
    PyObject *out;

    if (!PyArg_ParseTuple(args, "y*y*y*", &data, &key, &iv))
        return NULL;

    if (data.len == 0) {
        PyErr_SetString(PyExc_ValueError, "Data must not be empty");
        return NULL;
    }

    if (data.len % 16 != 0) {
        PyErr_SetString(PyExc_ValueError, "Data size must match a multiple of 16 bytes");
        return NULL;
    }

    if (key.len != 32) {
        PyErr_SetString(PyExc_ValueError, "Key size must be exactly 32 bytes");
        return NULL;
    }

    if (iv.len != 16) {
        PyErr_SetString(PyExc_ValueError, "IV size must be exactly 16 bytes");
        return NULL;
    }

    Py_BEGIN_ALLOW_THREADS
    buf = cbc256(data.buf, data.len, key.buf, iv.buf, encrypt);
    Py_END_ALLOW_THREADS

    PyBuffer_Release(&data);
    PyBuffer_Release(&key);
    PyBuffer_Release(&iv);

    out = Py_BuildValue("y#", buf, data.len);
    free(buf);

    return out;
}

static PyObject *cbc256_encrypt(PyObject *self, PyObject *args) {
    return cbc(args, 1);
}

static PyObject *cbc256_decrypt(PyObject *self, PyObject *args) {
    return cbc(args, 0);
}

static PyMethodDef methods[] = {
    {"ige256_encrypt", (PyCFunction) ige256_encrypt, METH_VARARGS, "AES256-IGE Encryption"},
    {"ige256_decrypt", (PyCFunction) ige256_decrypt, METH_VARARGS, "AES256-IGE Decryption"},
    {"ctr256_encrypt", (PyCFunction) ctr256_encrypt, METH_VARARGS, "AES256-CTR Encryption"},
    {"ctr256_decrypt", (PyCFunction) ctr256_encrypt, METH_VARARGS, "AES256-CTR Decryption"},
    {"cbc256_encrypt", (PyCFunction) cbc256_encrypt, METH_VARARGS, "AES256-CBC Encryption"},
    {"cbc256_decrypt", (PyCFunction) cbc256_decrypt, METH_VARARGS, "AES256-CBC Decryption"},
    {NULL,             NULL,                         0,            NULL}
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
