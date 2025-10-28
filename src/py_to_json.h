#pragma once

#define PY_SSIZE_T_CLEAN
#include <Python.h>

#include <turbob64.h>

static char const int_to_hex_k[16] = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'};

static void char_to_hex(uint8_t const c, uint8_t* hex) {
    hex[0] = int_to_hex_k[c >> 4];
    hex[1] = int_to_hex_k[c & 0x0F];
}

static int to_string(PyObject* obj, char* data, size_t* len) {
    if (obj == Py_None)
        *len = sprintf(data, "%s", "null");
    else if (PyBool_Check(obj))
        *len = sprintf(data, "%s", obj == Py_False ? "false" : "true");
    else if (PyLong_Check(obj))
        *len = sprintf(data, "%li", PyLong_AsLong(obj));
    else if (PyFloat_Check(obj))
        *len = sprintf(data, "%f", PyFloat_AsDouble(obj));
    else if (PyBytes_Check(obj)) {
        char* src = NULL;
        size_t src_len = 0;
        PyBytes_AsStringAndSize(obj, &src, &src_len);
        char* begin = data;
        *(begin++) = '"';
        begin += tb64enc(src, src_len, begin);
        *(begin++) = '"';
        *len = begin - data;
    } else if (PyUnicode_Check(obj)) {
        Py_ssize_t size;
        char const* char_ptr = PyUnicode_AsUTF8AndSize(obj, &size);
        char* begin = data;
        *(begin++) = '"';
        for (size_t i = 0; i != size; ++i) {
            uint8_t c = char_ptr[i];
            switch (c) {
            case 34:
                memcpy(begin, "\\\"", 2);
                begin += 2;
                break;
            case 92:
                memcpy(begin, "\\\\", 2);
                begin += 2;
                break;
            case 8:
                memcpy(begin, "\\b", 2);
                begin += 2;
                break;
            case 9:
                memcpy(begin, "\\t", 2);
                begin += 2;
                break;
            case 10:
                memcpy(begin, "\\n", 2);
                begin += 2;
                break;
            case 12:
                memcpy(begin, "\\f", 2);
                begin += 2;
                break;
            case 13:
                memcpy(begin, "\\r", 2);
                begin += 2;
                break;
            case 0:
            case 1:
            case 2:
            case 3:
            case 4:
            case 5:
            case 6:
            case 7:
            case 11:
            case 14:
            case 15:
            case 16:
            case 17:
            case 18:
            case 19:
            case 20:
            case 21:
            case 22:
            case 23:
            case 24:
            case 25:
            case 26:
            case 27:
            case 28:
            case 29:
            case 30:
            case 31: {
                memcpy(begin, "\\u0000", 6);
                begin += 6;
                char_to_hex(c, begin - 2);
                break;
            }
            default:
                *(begin++) = char_ptr[i];
            }
        }
        *(begin++) = '"';
        *len = begin - data;
    } else if (PySequence_Check(obj)) {
        char* begin = data;
        *(begin++) = '[';
        if (!PySequence_Length(obj)) {
            *(begin++) = ']';
        } else {
            for (Py_ssize_t i = 0; i < PySequence_Length(obj); i++) {
                size_t n_len = 0;
                to_string(PySequence_GetItem(obj, i), begin, &n_len);
                begin += n_len;
                *(begin++) = ',';
            }
            *(begin - 1) = ']';
        }
        *len = begin - data;
    } else if (PyDict_Check(obj)) {
        char* begin = data;
        *(begin++) = '{';
        if (!PyDict_Size(obj)) {
            *(begin++) = '}';
        } else {
            PyObject *key, *value;
            Py_ssize_t pos = 0;
            while (PyDict_Next(obj, &pos, &key, &value)) {
                size_t n_len = 0;
                to_string(key, begin, &n_len);
                begin += n_len;
                (*begin++) = ':';
                n_len = 0;
                to_string(value, &begin[*len], &n_len);
                begin += n_len;
                (*begin++) = ',';
            }
            *(begin - 1) = '}';
        }
        *len = begin - data;
    } else
        return -1;
    return 0;
}

static Py_ssize_t calculate_size_as_str(PyObject* obj) {
    if (obj == Py_None)
        return 4;
    else if (PyBool_Check(obj))
        return obj == Py_False ? 5 : 4;
    else if (PyLong_Check(obj))
        return snprintf(NULL, 0, "%li", PyLong_AsLong(obj));
    else if (PyFloat_Check(obj))
        return snprintf(NULL, 0, "%f", PyFloat_AsDouble(obj));
    else if (PyBytes_Check(obj)) {
        size_t len = 0;
        char* data_ptr = NULL;
        PyBytes_AsStringAndSize(obj, &data_ptr, &len);
        return tb64enclen(len) + 2;
    } else if (PyUnicode_Check(obj)) {
        Py_ssize_t byte_size = 0;
        PyUnicode_AsUTF8AndSize(obj, &byte_size);
        return byte_size + 2;
    } else if (PySequence_Check(obj)) {
        size_t size = 2;
        if (PySequence_Length(obj)) {
            for (Py_ssize_t i = 0; i < PySequence_Length(obj); i++)
                size += calculate_size_as_str(PySequence_GetItem(obj, i)) + 1;
            --size;
        }
        return size;
    } else if (PyDict_Check(obj)) {
        size_t size = 2;
        if (PyDict_Size(obj)) {
            PyObject *key, *value;
            Py_ssize_t pos = 0;
            while (PyDict_Next(obj, &pos, &key, &value)) {
                size += calculate_size_as_str(key) + 1;
                size += calculate_size_as_str(value) + 1;
            }
            --size;
        }
        return size;
    } else
        return -1;
    return 0;
}
