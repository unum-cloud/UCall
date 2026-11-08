/**
 *  @file python/json.c
 *  @author Ash Vardanian
 *  @date November 8, 2026
 *  @brief JSON values as Python objects through yyjson, for typed handlers and client calls.
 */
#include "lib.h"

#pragma region Reading

/** Reads a number too wide for 64 bits, kept as its digits, as the int or float they spell. */
static PyObject* object_from_digits(yyjson_val* value) {
    char const* const digits = yyjson_get_raw(value);
    size_t const length = yyjson_get_len(value);
    int integral = length != 0;
    for (size_t index = 0; index != length; ++index)
        integral &= (digits[index] >= '0' && digits[index] <= '9') || (index == 0 && digits[index] == '-');
    PyObject* const text = PyUnicode_DecodeASCII(digits, (Py_ssize_t)length, "strict");
    if (!text) return NULL;
    PyObject* const number = integral ? PyLong_FromUnicodeObject(text, 10) : PyFloat_FromString(text);
    Py_DECREF(text);
    return number;
}

/** Builds the list of @p value, converting every element. */
static PyObject* list_from_json(yyjson_val* value) {
    PyObject* const list = PyList_New((Py_ssize_t)yyjson_arr_size(value));
    if (!list) return NULL;
    size_t index = 0, count = 0;
    yyjson_val* element = NULL;
    yyjson_arr_foreach(value, index, count, element) {
        PyObject* const item = ucall_py_object_from_json(element);
        if (!item) {
            Py_DECREF(list);
            return NULL;
        }
        PyList_SET_ITEM(list, (Py_ssize_t)index, item);
    }
    return list;
}

/** Builds the dict of @p value, converting every member; a repeated key keeps its last value. */
static PyObject* dict_from_json(yyjson_val* value) {
    PyObject* const dict = PyDict_New();
    if (!dict) return NULL;
    size_t index = 0, count = 0;
    yyjson_val* key = NULL;
    yyjson_val* member = NULL;
    yyjson_obj_foreach(value, index, count, key, member) {
        PyObject* const name = PyUnicode_DecodeUTF8(yyjson_get_str(key), (Py_ssize_t)yyjson_get_len(key), "strict");
        PyObject* const item = name ? ucall_py_object_from_json(member) : NULL;
        int const added = item ? PyDict_SetItem(dict, name, item) : -1;
        Py_XDECREF(name);
        Py_XDECREF(item);
        if (added != 0) {
            Py_DECREF(dict);
            return NULL;
        }
    }
    return dict;
}

PyObject* ucall_py_object_from_json(yyjson_val* value) {
    switch (yyjson_get_type(value)) {
    case YYJSON_TYPE_NULL: Py_RETURN_NONE;
    case YYJSON_TYPE_BOOL: return PyBool_FromLong(yyjson_get_bool(value));
    case YYJSON_TYPE_NUM:
        switch (yyjson_get_subtype(value)) {
        case YYJSON_SUBTYPE_UINT: return PyLong_FromUnsignedLongLong(yyjson_get_uint(value));
        case YYJSON_SUBTYPE_SINT: return PyLong_FromLongLong(yyjson_get_sint(value));
        default: return PyFloat_FromDouble(yyjson_get_real(value));
        }
    case YYJSON_TYPE_RAW: return object_from_digits(value);
    case YYJSON_TYPE_STR:
        return PyUnicode_DecodeUTF8(yyjson_get_str(value), (Py_ssize_t)yyjson_get_len(value), "strict");
    case YYJSON_TYPE_ARR:
    case YYJSON_TYPE_OBJ: {
        // A document nests as deep as its text, so the C stack is guarded like Python recursion.
        if (Py_EnterRecursiveCall(" while reading a JSON document") != 0) return NULL;
        PyObject* const container = yyjson_is_arr(value) ? list_from_json(value) : dict_from_json(value);
        Py_LeaveRecursiveCall();
        return container;
    }
    default: return PyErr_Format(PyExc_ValueError, "the document holds a value JSON has no type for");
    }
}

#pragma endregion Reading

#pragma region Writing

static int json_from_value(PyObject* object, yyjson_mut_doc* document, yyjson_mut_val** value);

/** Serializes an integer, keeping one past 64 bits as its digits, which JSON holds at any width. */
static int json_from_integer(PyObject* object, yyjson_mut_doc* document, yyjson_mut_val** value) {
    int overflow = 0;
    long long const narrow = PyLong_AsLongLongAndOverflow(object, &overflow);
    if (narrow == -1 && PyErr_Occurred()) return -1;
    unsigned long long wide = 0;
    if (!overflow) *value = yyjson_mut_sint(document, narrow);
    else if (overflow > 0 && (wide = PyLong_AsUnsignedLongLong(object)) != (unsigned long long)-1)
        *value = yyjson_mut_uint(document, wide);
    else {
        if (PyErr_Occurred() && !PyErr_ExceptionMatches(PyExc_OverflowError)) return -1;
        PyErr_Clear();
        PyObject* const digits = PyNumber_ToBase(object, 10);
        if (!digits) return -1;
        Py_ssize_t length = 0;
        char const* const text = PyUnicode_AsUTF8AndSize(digits, &length);
        *value = text ? yyjson_mut_rawncpy(document, text, (size_t)length) : NULL;
        Py_DECREF(digits);
        if (!text) return -1;
    }
    if (*value) return 0;
    PyErr_NoMemory();
    return -1;
}

/** Serializes a dict, whose keys must be strings, as JSON objects' keys are. */
static int json_from_dict(PyObject* object, yyjson_mut_doc* document, yyjson_mut_val** value) {
    yyjson_mut_val* const members = yyjson_mut_obj(document);
    if (!members) {
        PyErr_NoMemory();
        return -1;
    }
    int failed = 0;
    Py_ssize_t position = 0;
    PyObject* name = NULL;
    PyObject* member = NULL;
    ucall_py_section_t section;
    ucall_py_section_begin(&section, object);
    while (!failed && PyDict_Next(object, &position, &name, &member)) {
        if (!PyUnicode_Check(name)) {
            PyErr_Format(PyExc_TypeError, "a JSON object's keys are strings, not %s", Py_TYPE(name)->tp_name);
            failed = 1;
            break;
        }
        Py_ssize_t length = 0;
        char const* const text = PyUnicode_AsUTF8AndSize(name, &length);
        yyjson_mut_val* const key = text ? yyjson_mut_strncpy(document, text, (size_t)length) : NULL;
        // Held, since a nested critical section may let another thread change this dict.
        PyObject* const held = Py_NewRef(member);
        yyjson_mut_val* item = NULL;
        failed = !key || json_from_value(held, document, &item) != 0 || !yyjson_mut_obj_add(members, key, item);
        Py_DECREF(held);
        if (failed && !PyErr_Occurred()) PyErr_NoMemory();
    }
    ucall_py_section_end(&section);
    *value = members;
    return failed ? -1 : 0;
}

/** Serializes a list or a tuple as a JSON array. */
static int json_from_sequence(PyObject* object, yyjson_mut_doc* document, yyjson_mut_val** value) {
    yyjson_mut_val* const items = yyjson_mut_arr(document);
    if (!items) {
        PyErr_NoMemory();
        return -1;
    }
    int failed = 0;
    ucall_py_section_t section;
    ucall_py_section_begin(&section, object);
    for (Py_ssize_t index = 0; !failed && index < PySequence_Fast_GET_SIZE(object); ++index) {
        PyObject* const held = Py_NewRef(PySequence_Fast_GET_ITEM(object, index));
        yyjson_mut_val* item = NULL;
        failed = json_from_value(held, document, &item) != 0 || !yyjson_mut_arr_append(items, item);
        Py_DECREF(held);
        if (failed && !PyErr_Occurred()) PyErr_NoMemory();
    }
    ucall_py_section_end(&section);
    *value = items;
    return failed ? -1 : 0;
}

static int json_from_value(PyObject* object, yyjson_mut_doc* document, yyjson_mut_val** value) {
    // A bool is an int too, so it is told apart first.
    if (object == Py_None) *value = yyjson_mut_null(document);
    else if (PyBool_Check(object)) *value = yyjson_mut_bool(document, object == Py_True);
    else if (PyLong_Check(object)) return json_from_integer(object, document, value);
    else if (PyFloat_Check(object)) *value = yyjson_mut_real(document, PyFloat_AS_DOUBLE(object));
    else if (PyUnicode_Check(object)) {
        Py_ssize_t length = 0;
        char const* const text = PyUnicode_AsUTF8AndSize(object, &length);
        if (!text) return -1;
        *value = yyjson_mut_strncpy(document, text, (size_t)length);
    }
    else if (PyDict_Check(object) || PyList_Check(object) || PyTuple_Check(object)) {
        if (Py_EnterRecursiveCall(" while writing a JSON document") != 0) return -1;
        int const serialized = PyDict_Check(object) ? json_from_dict(object, document, value)
                                                    : json_from_sequence(object, document, value);
        Py_LeaveRecursiveCall();
        return serialized;
    }
    else {
        PyErr_Format(PyExc_TypeError, "yyjson writes dicts, lists, strings, numbers, booleans and None, not %s",
                     Py_TYPE(object)->tp_name);
        return -1;
    }
    if (*value) return 0;
    PyErr_NoMemory();
    return -1;
}

PyObject* ucall_py_json_from_object(PyObject* object) {
    yyjson_mut_doc* const document = yyjson_mut_doc_new(NULL);
    if (!document) return PyErr_NoMemory();
    yyjson_mut_val* root = NULL;
    size_t length = 0;
    // NaN and the infinities are written as Python's own `json` writes them.
    char* const text = json_from_value(object, document, &root) != 0
                           ? NULL
                           : yyjson_mut_val_write_opts(root, YYJSON_WRITE_ALLOW_INF_AND_NAN, NULL, &length, NULL);
    yyjson_mut_doc_free(document);
    if (text) {
        PyObject* const bytes = PyBytes_FromStringAndSize(text, (Py_ssize_t)length);
        free(text);
        return bytes;
    }
    if (!PyErr_Occurred()) return PyErr_NoMemory();
    if (!PyErr_ExceptionMatches(PyExc_TypeError) && !PyErr_ExceptionMatches(PyExc_ValueError)) return NULL;
    // What only `json.dumps` spells, like numeric keys or lone surrogates, takes its slower path.
    PyErr_Clear();
    PyObject* const dumped = PyObject_CallOneArg(ucall_py_json_dumps, object);
    PyObject* const bytes = dumped ? PyUnicode_AsUTF8String(dumped) : NULL;
    Py_XDECREF(dumped);
    return bytes;
}

#pragma endregion Writing
