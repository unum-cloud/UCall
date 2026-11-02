/**
 *  @file python/lib.c
 *  @author Ash Vardanian
 *  @date January 30, 2023
 *  @brief The module glue of `ucall.lib`: argument parsing, enum mirrors, errors and `PyInit_lib`.
 */
#include "lib.h"

#pragma region Arguments

/** Binds keyword @p name to its slot at or after @p first, refusing unknown and repeated names. */
static int bind_keyword(char const* verb, PyObject* name, PyObject* value, Py_ssize_t first,
                        ucall_py_argument_t const* arguments, size_t count) {
    size_t position = (size_t)first;
    while (position != count && PyUnicode_CompareWithASCIIString(name, arguments[position].name) != 0) ++position;
    if (position == count) {
        PyErr_Format(PyExc_TypeError, "%s() got an unexpected keyword argument %R", verb, name);
        return -1;
    }
    if (*arguments[position].value) {
        PyErr_Format(PyExc_TypeError, "%s() got multiple values for argument '%s'", verb, arguments[position].name);
        return -1;
    }
    *arguments[position].value = value;
    return 0;
}

/** Binds positional values, refusing more than @p positional_max of them. */
static int bind_positional(char const* verb, PyObject* const* values, Py_ssize_t values_count,
                           Py_ssize_t positional_max, ucall_py_argument_t const* arguments, size_t count) {
    if (values_count > positional_max) {
        PyErr_Format(PyExc_TypeError, "%s() takes at most %zd positional arguments, received %zd", verb, positional_max,
                     values_count);
        return -1;
    }
    for (size_t position = 0; position != count; ++position) *arguments[position].value = NULL;
    for (Py_ssize_t position = 0; position != values_count; ++position) *arguments[position].value = values[position];
    return 0;
}

static int check_required(char const* verb, Py_ssize_t required, ucall_py_argument_t const* arguments) {
    for (Py_ssize_t position = 0; position != required; ++position)
        if (!*arguments[position].value) {
            PyErr_Format(PyExc_TypeError, "%s() missing required argument '%s'", verb, arguments[position].name);
            return -1;
        }
    return 0;
}

int ucall_py_parse_fast(char const* verb, PyObject* const* values, Py_ssize_t values_count, PyObject* names,
                        Py_ssize_t required, Py_ssize_t positional_max, ucall_py_argument_t const* arguments,
                        size_t count) {
    Py_ssize_t const positional_count = PyVectorcall_NARGS(values_count);
    if (bind_positional(verb, values, positional_count, positional_max, arguments, count) != 0) return -1;
    Py_ssize_t const names_count = names ? PyTuple_GET_SIZE(names) : 0;
    for (Py_ssize_t index = 0; index != names_count; ++index)
        if (bind_keyword(verb, PyTuple_GET_ITEM(names, index), values[positional_count + index], required, arguments,
                         count) != 0)
            return -1;
    return check_required(verb, required, arguments);
}

int ucall_py_parse_tuple(char const* verb, PyObject* positional, PyObject* keywords, Py_ssize_t required,
                         Py_ssize_t positional_max, ucall_py_argument_t const* arguments, size_t count) {
    Py_ssize_t const positional_count = positional ? PyTuple_GET_SIZE(positional) : 0;
    PyObject* const* const values = positional_count ? &PyTuple_GET_ITEM(positional, 0) : NULL;
    if (bind_positional(verb, values, positional_count, positional_max, arguments, count) != 0) return -1;
    Py_ssize_t cursor = 0;
    PyObject *name = NULL, *value = NULL;
    while (keywords && PyDict_Next(keywords, &cursor, &name, &value))
        if (bind_keyword(verb, name, value, required, arguments, count) != 0) return -1;
    return check_required(verb, required, arguments);
}

int ucall_py_size_from_object(PyObject* object, char const* field, size_t* output) {
    if (!object) return 0;
    if (!PyLong_Check(object)) {
        PyErr_Format(PyExc_TypeError, "'%s' must be a non-negative int, got %s", field, Py_TYPE(object)->tp_name);
        return -1;
    }
    size_t const value = PyLong_AsSize_t(object);
    if (value == (size_t)-1 && PyErr_Occurred()) return -1;
    *output = value;
    return 0;
}

int ucall_py_text_from_object(PyObject* object, char const* field, ucall_bytes_view_t* view) {
    if (PyUnicode_Check(object)) {
        Py_ssize_t length = 0;
        char const* data = PyUnicode_AsUTF8AndSize(object, &length);
        if (!data) return -1;
        view->data = (ucall_byte_t const*)data;
        view->length = (size_t)length;
        return 0;
    }
    if (PyBytes_Check(object)) {
        view->data = (ucall_byte_t const*)PyBytes_AS_STRING(object);
        view->length = (size_t)PyBytes_GET_SIZE(object);
        return 0;
    }
    PyErr_Format(PyExc_TypeError, "'%s' must be str or bytes, got %s", field, Py_TYPE(object)->tp_name);
    return -1;
}

int ucall_py_key_from_object(PyObject* object, char const* field, ucall_noise_key_t key) {
    if (!PyBytes_Check(object) || PyBytes_GET_SIZE(object) != (Py_ssize_t)sizeof(ucall_noise_key_t)) {
        PyErr_Format(PyExc_ValueError, "'%s' must be %zu bytes, got %R", field, sizeof(ucall_noise_key_t), object);
        return -1;
    }
    memcpy(key, PyBytes_AS_STRING(object), sizeof(ucall_noise_key_t));
    return 0;
}

void ucall_py_header_lines_release(ucall_py_header_lines_t* lines) {
    PyMem_Free(lines->views);
    Py_CLEAR(lines->sequence);
    lines->views = NULL;
    lines->count = 0;
}

int ucall_py_header_lines_from_object(PyObject* object, ucall_py_header_lines_t* lines) {
    lines->sequence = NULL;
    lines->views = NULL;
    lines->count = 0;
    if (!object) return 0;
    lines->sequence = PySequence_Fast(object, "'headers' must be a sequence of \"name: value\" lines");
    if (!lines->sequence) return -1;
    Py_ssize_t const count = PySequence_Fast_GET_SIZE(lines->sequence);
    if (!count) return 0;
    lines->views = PyMem_Calloc((size_t)count, sizeof(ucall_bytes_view_t));
    if (!lines->views) {
        ucall_py_header_lines_release(lines);
        PyErr_NoMemory();
        return -1;
    }
    lines->count = (size_t)count;
    for (Py_ssize_t index = 0; index != count; ++index)
        if (ucall_py_text_from_object(PySequence_Fast_GET_ITEM(lines->sequence, index), "headers",
                                      &lines->views[index]) != 0) {
            ucall_py_header_lines_release(lines);
            return -1;
        }
    return 0;
}

PyObject* ucall_py_text_to_object(ucall_bytes_view_t view) {
    return PyUnicode_DecodeUTF8((char const*)view.data, (Py_ssize_t)view.length, "surrogateescape");
}

PyObject* ucall_py_get_optional(PyObject* self, void* closure) {
    PyObject* const value = *(PyObject**)((char*)self + (size_t)closure);
    return Py_NewRef(value ? value : Py_None);
}

#pragma endregion Arguments

#pragma region Enums and Errors

/** The C spelling of @p value, or NULL when the gap between named values has no member. */
static char const* enum_spelling(ucall_py_enum_mirror_t const* mirror, long value) {
    if (value < mirror->first || value > mirror->last) return NULL;
    char const* const spelled = mirror->spell((int)value);
    return strcmp(spelled, "unrecognized") == 0 ? NULL : spelled;
}

/** Writes the member name of @p spelled to @p member, "out-of-memory" becoming "OUT_OF_MEMORY". */
static void enum_member_name(char const* spelled, char* member, size_t capacity) {
    size_t length = 0;
    for (; spelled[length] && length + 1 != capacity; ++length) {
        char const letter = spelled[length];
        member[length] = letter == '-' ? '_' : letter >= 'a' && letter <= 'z' ? (char)(letter - 'a' + 'A') : letter;
    }
    member[length] = '\0';
}

static int enum_register(PyObject* module, PyObject* int_enum, PyObject* keywords, ucall_py_enum_mirror_t* mirror) {
    PyObject* members = PyDict_New();
    for (long value = mirror->first; members && value <= mirror->last; ++value) {
        char const* const spelled = enum_spelling(mirror, value);
        if (!spelled) continue;
        char member[32];
        enum_member_name(spelled, member, sizeof(member));
        PyObject* const number = PyLong_FromLong(value);
        if (!number || PyDict_SetItemString(members, member, number) != 0) Py_CLEAR(members);
        Py_XDECREF(number);
    }
    PyObject* const arguments = members ? Py_BuildValue("(sO)", mirror->name, members) : NULL;
    mirror->type = arguments ? PyObject_Call(int_enum, arguments, keywords) : NULL;
    Py_XDECREF(arguments);
    Py_XDECREF(members);
    PyObject* const doc = mirror->type ? PyUnicode_FromString(mirror->doc) : NULL;
    int const documented = doc ? PyObject_SetAttrString(mirror->type, "__doc__", doc) : -1;
    Py_XDECREF(doc);
    return documented == 0 ? PyModule_AddObjectRef(module, mirror->name, mirror->type) : -1;
}

int ucall_py_enums_register(PyObject* module) {
    ucall_py_enum_mirror_t* const mirrors[] = {
        &ucall_py_status_enum, &ucall_py_backend_enum,       &ucall_py_cpu_class_enum, &ucall_py_security_enum,
        &ucall_py_verb_enum,   &ucall_py_body_delivery_enum, &ucall_py_log_level_enum};
    PyObject* const enum_module = PyImport_ImportModule("enum");
    PyObject* const int_enum = enum_module ? PyObject_GetAttrString(enum_module, "IntEnum") : NULL;
    PyObject* const keywords = int_enum ? Py_BuildValue("{ss}", "module", "ucall") : NULL;
    int registered = keywords ? 0 : -1;
    for (size_t row = 0; registered == 0 && row != sizeof(mirrors) / sizeof(mirrors[0]); ++row)
        registered = enum_register(module, int_enum, keywords, mirrors[row]);
    Py_XDECREF(keywords);
    Py_XDECREF(int_enum);
    Py_XDECREF(enum_module);
    return registered;
}

int ucall_py_enum_from_object(PyObject* object, char const* field, ucall_py_enum_mirror_t const* mirror, int* value) {
    if (!object) return 0;
    PyObject* named = NULL;
    if (PyUnicode_Check(object)) {
        char const* const spelled = PyUnicode_AsUTF8(object);
        if (!spelled) return -1;
        char member[32];
        enum_member_name(spelled, member, sizeof(member));
        PyObject* const key = PyUnicode_FromString(member);
        named = key ? PyObject_GetItem(mirror->type, key) : NULL;
        Py_XDECREF(key);
        if (!named) {
            if (PyErr_ExceptionMatches(PyExc_KeyError)) {
                PyErr_Clear();
                PyErr_Format(PyExc_ValueError, "'%s' takes a ucall.%s, and %R names none", field, mirror->name, object);
            }
            return -1;
        }
        object = named;
    }
    if (!PyLong_Check(object) || PyBool_Check(object)) {
        Py_XDECREF(named);
        PyErr_Format(PyExc_TypeError, "'%s' takes a ucall.%s, got %s", field, mirror->name, Py_TYPE(object)->tp_name);
        return -1;
    }
    int overflow = 0;
    long const read = PyLong_AsLongAndOverflow(object, &overflow);
    Py_XDECREF(named);
    if (read == -1 && PyErr_Occurred()) return -1;
    if (overflow || !enum_spelling(mirror, read)) {
        PyErr_Format(PyExc_ValueError, "'%s' takes a ucall.%s, and %ld is none", field, mirror->name, read);
        return -1;
    }
    *value = (int)read;
    return 0;
}

PyObject* ucall_py_enum_to_object(ucall_py_enum_mirror_t const* mirror, long value) {
    PyObject* const number = PyLong_FromLong(value);
    if (!number || !enum_spelling(mirror, value)) return number;
    PyObject* const member = PyObject_CallOneArg(mirror->type, number);
    Py_DECREF(number);
    return member;
}

PyObject* ucall_py_raise_status(ucall_status_t status, char const* message) {
    PyObject* const member = ucall_py_enum_to_object(&ucall_py_status_enum, (long)status);
    PyObject* const text = member ? PyUnicode_FromString(message ? message : ucall_status_name(status)) : NULL;
    PyObject* const error = text ? PyObject_CallFunctionObjArgs((PyObject*)&ErrorType, member, text, NULL) : NULL;
    if (error) PyErr_SetObject((PyObject*)&ErrorType, error);
    Py_XDECREF(error);
    Py_XDECREF(text);
    Py_XDECREF(member);
    return NULL;
}

int ucall_py_raise_outcome(ucall_outcome_t const* outcome) {
    if (outcome->status == ucall_status_success_k) return 0;
    ucall_py_raise_status(outcome->status, outcome->message);
    return -1;
}

void ucall_py_report_handler_failure(PyObject* handler) {
    if (PyErr_ExceptionMatches(PyExc_KeyboardInterrupt)) {
        PyErr_Clear();
        PyErr_SetInterrupt();
        return;
    }
    PyErr_WriteUnraisable(handler);
}

#pragma endregion Enums and Errors

#pragma region Module

PyObject* ucall_py_json_dumps = NULL;
PyObject* ucall_py_json_loads = NULL;

static char const doc_module[] =                                                                     //
    "Native HTTP and Noise networking with caller-owned polling and request batching.\n"             //
    "\n"                                                                                             //
    "A `Server` answers on one or more `Interface`s, and a `Client` calls other servers. Neither\n"  //
    "starts a thread: the application polls each event loop with `Server.take_calls`, drains each\n" //
    "`BatchEndpoint` with `take_batches`, and drives each `Client` from the thread that made it.\n"  //
    "Handlers registered with `Server.get` and its siblings bind typed parameters from the path,\n"  //
    "the query and a JSON body, and what they return becomes the reply.\n"                           //
    "\n"                                                                                             //
    "Example:\n"                                                                                     //
    "  >>> import threading, ucall\n"                                                                //
    "  >>> server = ucall.Server(ucall.Interface(\"127.0.0.1:0\"))\n"                                //
    "  >>> @server.get(\"/sum\")\n"                                                                  //
    "  ... def sum(a: int, b: int):\n"                                                               //
    "  ...     return a + b\n"                                                                       //
    "  >>> thread = threading.Thread(target=server.run)\n"                                           //
    "  >>> thread.start()\n"                                                                         //
    "  >>> client = ucall.Client(connections=1)\n"                                                   //
    "  >>> bytes(client.get(f\"http://{server.addresses[0]}/sum?a=1&b=2\").body)\n"                  //
    "  b'3'\n"                                                                                       //
    "  >>> server.stop()\n"                                                                          //
    "  >>> thread.join()";

/** Every type the module readies and its name there; a nameless row stays internal. */
static struct {

    /** The attribute the type answers to on the module, or NULL to leave it unnamed. */
    char const* name;

    /** The type to ready. */
    PyTypeObject* type;
} const module_types[] = {
    {"Error", &ErrorType},
    {"Interface", &InterfaceType},
    {"Metrics", &MetricsType},
    {"Server", &ServerType},
    {"Request", &RequestType},
    {"DetachedRequest", &DetachedRequestType},
    {"RequestPart", &RequestPartType},
    {"BodyChunks", &BodyChunksType},
    {"File", &FileType},
    {"Path", &PathType},
    {"Deferred", &DeferredType},
    {"ReplyStream", &ReplyStreamType},
    {"BatchEndpoint", &BatchEndpointType},
    {"Client", &ClientType},
    {"Completed", &CompletedType},
    {"Response", &ResponseType},
    {NULL, &EndpointType},
    {NULL, &RequestBytesType},
};

/** The module, named as the extension is built, so @c lib.__name__ agrees with its file. */
static PyModuleDef module_definition = {
    PyModuleDef_HEAD_INIT,
    .m_name = "ucall.lib",
    .m_doc = doc_module,
    .m_size = -1,
};

/** Imports `json.dumps` and `json.loads` once, for replies, typed handlers and client calls. */
static int json_import(void) {
    PyObject* const json = PyImport_ImportModule("json");
    if (!json) return -1;
    ucall_py_json_dumps = PyObject_GetAttrString(json, "dumps");
    ucall_py_json_loads = ucall_py_json_dumps ? PyObject_GetAttrString(json, "loads") : NULL;
    Py_DECREF(json);
    return ucall_py_json_loads ? 0 : -1;
}

PyMODINIT_FUNC PyInit_lib(void) {
    ErrorType.tp_base = (PyTypeObject*)PyExc_RuntimeError;
    size_t const types_count = sizeof(module_types) / sizeof(module_types[0]);
    for (size_t type_index = 0; type_index != types_count; ++type_index)
        if (PyType_Ready(module_types[type_index].type) < 0) return NULL;
    if (json_import() != 0) return NULL;

    PyObject* const module = PyModule_Create(&module_definition);
    if (!module) return NULL;
    if (ucall_py_enums_register(module) < 0 || PyModule_AddFunctions(module, ucall_py_noise_methods) < 0 ||
        PyModule_AddStringConstant(module, "__version__", ucall_version_name()) < 0 ||
        PyModule_AddStringConstant(module, "DEFAULT_ADDRESS", ucall_py_default_address_k) < 0)
        goto failed;
    for (size_t type_index = 0; type_index != types_count; ++type_index) {
        char const* const name = module_types[type_index].name;
        if (name && PyModule_AddObjectRef(module, name, (PyObject*)module_types[type_index].type) < 0) goto failed;
    }
    return module;

failed:
    Py_DECREF(module);
    return NULL;
}

#pragma endregion Module
