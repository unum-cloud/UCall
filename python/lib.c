/**
 *  @brief  Pure CPython bindings for UCall.
 *  @author Ash Vardanian
 *  @file   lib.c
 *  @date   2023-01-30
 *
 *  @copyright Copyright (c) 2023
 *
 *  @see Reading Materials
 *  https://pythoncapi.readthedocs.io/type_object.html
 *  https://numpy.org/doc/stable/reference/c-api/types-and-structures.html
 *  https://pythonextensionpatterns.readthedocs.io/en/latest/refcount.html
 *  https://docs.python.org/3/extending/newtypes_tutorial.html#adding-data-and-methods-to-the-basic-example
 */
#include <time.h>

#define PY_SSIZE_T_CLEAN
#include <Python.h>

#include <turbob64.h>

#include "helpers/py_to_json.h"
#include "ucall/ucall.h"

#define stringify_value_m(a) stringify_m(a)
#define stringify_m(a) #a
#define concat_m(A, B) A##B
#define macro_concat_m(A, B) concat_m(A, B)
#define pyinit_f_m macro_concat_m(PyInit_, UCALL_PYTHON_MODULE_NAME)

#define get_attr_safe_m(name, obj, attr)                                                                               \
    PyObject* name = PyObject_GetAttrString(obj, attr);                                                                \
    if (!name) {                                                                                                       \
        PyErr_SetString(PyExc_TypeError, "Failed to extract attribute: " attr);                                        \
        return -1;                                                                                                     \
    }

typedef enum {
    POSITIONAL_ONLY,       //
    POSITIONAL_OR_KEYWORD, //
    VAR_POSITIONAL,        //
    KEYWORD_ONLY,          //
    VAR_KEYWORD            //
} py_param_kind_t;

typedef struct {
    char const* name;     // Name or NULL
    Py_ssize_t name_len;  // Name Length
    PyObject* value;      // Any or NULL
    PyTypeObject* type;   // Type or NULL
    py_param_kind_t kind; // Kind
} py_param_t;

typedef struct {
    py_param_t* u_params;
    size_t params_cnt;
    PyObject* callable;
} py_wrapper_t;

typedef struct {
    PyObject_HEAD
    ucall_config_t config;
    ucall_server_t server;
    size_t count_threads;
    py_wrapper_t* wrappers;
    size_t wrapper_capacity;
    size_t count_added;
    bool quiet;
} py_server_t;

static int prepare_wrapper(PyObject* callable, py_wrapper_t* wrap) {

    if (PyObject_HasAttrString(callable, "__signature__")) {
        get_attr_safe_m(py_signature, callable, "__signature__");
        get_attr_safe_m(params, py_signature, "parameters");
        PyObject* items = PyMapping_Items(params);
        long total_params = PyList_Size(items);
        py_param_t* parameters = (py_param_t*)malloc(total_params * sizeof(py_param_t));

        for (Py_ssize_t i = 0; i < total_params; i++) {
            PyObject* item = PyList_GetItem(items, i);
            PyObject* py_param = PyTuple_GetItem(item, 1);
            PyObject* name = PyTuple_GetItem(item, 0);
            PyObject* type = PyObject_GetAttrString(py_param, "annotation");
            PyObject* kind = PyObject_GetAttrString(py_param, "_kind");
            PyObject* def = PyObject_GetAttrString(py_param, "default");

            py_param_t param;
            param.name = PyUnicode_AsUTF8AndSize(name, &param.name_len);
            param.value = def;
            param.type = (PyTypeObject*)type;
            param.kind = PyLong_AsLong(kind);
            parameters[i] = param;
        }

        Py_INCREF(callable); // Cause this is a partial wrapper around the original function.
        wrap->u_params = parameters;
        wrap->params_cnt = total_params;
        return 0;
    }

    get_attr_safe_m(func_code, callable, "__code__");
    get_attr_safe_m(arg_names, func_code, "co_varnames");
    get_attr_safe_m(co_flags, func_code, "co_flags");
    get_attr_safe_m(co_argcount, func_code, "co_argcount");
    get_attr_safe_m(co_posonlyargcount, func_code, "co_posonlyargcount");
    get_attr_safe_m(co_kwonlyargcount, func_code, "co_kwonlyargcount");

    long flags = PyLong_AsLong(co_flags);
    long pos_count = PyLong_AsLong(co_argcount);
    long posonly_count = PyLong_AsLong(co_posonlyargcount);
    long keyword_only_count = PyLong_AsLong(co_kwonlyargcount);
    long pos_default_count = 0;

    PyObject* annotations = PyFunction_GetAnnotations(callable); // Dict

    get_attr_safe_m(defaults, callable, "__defaults__");
    get_attr_safe_m(kwdefaults, callable, "__kwdefaults__");

    if (PyTuple_CheckExact(defaults))
        pos_default_count = PyTuple_Size(defaults);

    if (PyMethod_Check(callable)) {
        // When this is a class method...
        // TODO: What?
    }

    long non_default_count = abs(pos_count - pos_default_count);
    long posonly_left = posonly_count;

    // if (posonly_count != pos_count) {
    //     PyErr_SetString(PyExc_TypeError, "Strictly positional or Keyword arguments are allowed.");
    //     return -1;
    // }
    bool const has_vararg = flags & CO_VARARGS;
    bool const has_varkeyarg = flags & CO_VARKEYWORDS;
    long total_params = pos_count + has_vararg + keyword_only_count + has_varkeyarg;
    py_param_t* parameters = (py_param_t*)malloc(total_params * sizeof(py_param_t));

    size_t param_i = 0;

    // Non-keyword-only parameters w/o defaults.
    for (Py_ssize_t i = 0; i < non_default_count; ++i) {
        py_param_t param;
        param.name = PyUnicode_AsUTF8AndSize(PyTuple_GetItem(arg_names, i), &param.name_len);
        param.value = NULL;
        param.type = (PyTypeObject*)PyDict_GetItemString(annotations, param.name);
        param.kind = posonly_left-- > 0 ? POSITIONAL_ONLY : POSITIONAL_OR_KEYWORD;
        parameters[param_i++] = param;
    }

    //... w / defaults.
    for (Py_ssize_t i = non_default_count; i < pos_count; ++i) {
        py_param_t param;
        param.name = PyUnicode_AsUTF8AndSize(PyTuple_GetItem(arg_names, i), &param.name_len);
        param.value = PyTuple_GetItem(defaults, i - non_default_count);
        param.type = (PyTypeObject*)PyDict_GetItemString(annotations, param.name);
        param.kind = posonly_left-- > 0 ? POSITIONAL_ONLY : POSITIONAL_OR_KEYWORD;
        parameters[param_i++] = param;
    }

    if (has_vararg) {
        py_param_t param;
        param.name =
            PyUnicode_AsUTF8AndSize(PyTuple_GetItem(arg_names, pos_count + keyword_only_count), &param.name_len);
        param.value = NULL;
        param.type = (PyTypeObject*)PyDict_GetItemString(annotations, param.name);
        param.kind = VAR_POSITIONAL;
        parameters[param_i++] = param;
    }

    // Keyword - only parameters.
    for (Py_ssize_t i = pos_count; i < pos_count + keyword_only_count; ++i) {
        py_param_t param;
        param.name = PyUnicode_AsUTF8AndSize(PyTuple_GetItem(arg_names, i), &param.name_len);
        param.value = PyDict_GetItemString(kwdefaults, param.name);
        param.type = (PyTypeObject*)PyDict_GetItemString(annotations, param.name);
        param.kind = KEYWORD_ONLY;
        parameters[param_i++] = param;
    }

    if (has_varkeyarg) {
        py_param_t param;
        param.name = PyUnicode_AsUTF8AndSize(PyTuple_GetItem(arg_names, pos_count + keyword_only_count + has_vararg),
                                             &param.name_len);
        param.value = NULL;
        param.type = (PyTypeObject*)PyDict_GetItemString(annotations, param.name);
        param.kind = VAR_KEYWORD;
        parameters[param_i++] = param;
    }

    wrap->u_params = parameters;
    wrap->params_cnt = total_params;
    return 0;
}

static void wrapper(ucall_call_t call, ucall_callback_tag_t callback_tag) {
    py_wrapper_t* wrap = (py_wrapper_t*)(callback_tag);
    PyObject* args = PyTuple_New(wrap->params_cnt);

    for (size_t i = 0; i < wrap->params_cnt; ++i) {
        PyTypeObject* type = wrap->u_params[i].type;
        py_param_kind_t kind = wrap->u_params[i].kind;
        bool may_have_name = (kind & POSITIONAL_OR_KEYWORD) | (kind & KEYWORD_ONLY) | (kind & VAR_KEYWORD);
        bool may_have_pos = (kind & POSITIONAL_OR_KEYWORD) | (kind & POSITIONAL_ONLY) | (kind & VAR_POSITIONAL);
        bool got_named = false;
        Py_ssize_t name_len = wrap->u_params[i].name_len;
        ucall_str_t name = wrap->u_params[i].name;

        if (PyType_IsSubtype(type, &PyBool_Type)) {
            bool res;
            if (may_have_name && name_len > 0)
                got_named = ucall_param_named_bool(call, name, name_len, &res);

            if ((may_have_pos && !got_named) && //
                !ucall_param_positional_bool(call, i, &res))
                return ucall_call_reply_error_invalid_params(call);

            PyTuple_SetItem(args, i, res ? Py_True : Py_False);
        } else if (PyType_IsSubtype(type, &PyLong_Type)) {
            Py_ssize_t res;
            if (may_have_name && name_len > 0)
                got_named = ucall_param_named_i64(call, name, name_len, &res);

            if ((may_have_pos && !got_named) && //
                !ucall_param_positional_i64(call, i, &res))
                return ucall_call_reply_error_invalid_params(call);

            PyTuple_SetItem(args, i, PyLong_FromSsize_t(res));
        } else if (PyType_IsSubtype(type, &PyFloat_Type)) {
            double res;
            if (may_have_name && name_len > 0)
                got_named = ucall_param_named_f64(call, name, name_len, &res);

            if ((may_have_pos && !got_named) && //
                !ucall_param_positional_f64(call, i, &res))
                return ucall_call_reply_error_invalid_params(call);

            PyTuple_SetItem(args, i, PyFloat_FromDouble(res));
        } else if (PyType_IsSubtype(type, &PyUnicode_Type)) {
            ucall_str_t res;
            size_t len;
            if (may_have_name && name_len > 0)
                got_named = ucall_param_named_str(call, name, name_len, &res, &len);

            if ((may_have_pos && !got_named) && //
                !ucall_param_positional_str(call, i, &res, &len))
                return ucall_call_reply_error_invalid_params(call);

            PyTuple_SetItem(args, i, PyUnicode_FromStringAndSize(res, len));
        } else {
            // For non native type, assume binary.
            ucall_str_t res;
            size_t len;
            if (may_have_name && name_len > 0)
                got_named = ucall_param_named_str(call, name, name_len, &res, &len);

            if ((may_have_pos && !got_named) && //
                !ucall_param_positional_str(call, i, &res, &len))
                return ucall_call_reply_error_invalid_params(call);

            len = tb64dec((unsigned char const*)res, len, (unsigned char*)res);
            PyTuple_SetItem(args, i, PyBytes_FromStringAndSize(res, len));
        }
    }

    PyObject* response = PyObject_CallObject(wrap->callable, args);
    if (response == NULL) {
        PyObject *ptype, *pvalue, *ptraceback;
        PyErr_Fetch(&ptype, &pvalue, &ptraceback);
        if (ptype != NULL) {
            PyObject* pvalue_str = PyObject_Str(pvalue);
            size_t sz = 0;
            ucall_str_t error_str = PyUnicode_AsUTF8AndSize(pvalue_str, &sz);
            ucall_call_reply_error(call, 500, error_str, sz);
            Py_DECREF(pvalue_str);
        } else
            ucall_call_reply_error_unknown(call);
        Py_XDECREF(ptype);
        Py_XDECREF(pvalue);
        Py_XDECREF(ptraceback);
        return;
    }

    size_t sz = calculate_size_as_str(response);
    char* parsed_response = (char*)(malloc(sz * sizeof(char)));
    if (!parsed_response)
        return ucall_call_reply_error_out_of_memory(call);
    size_t len = 0;
    int res = to_string(response, &parsed_response[0], &len);
    ucall_call_reply_content(call, &parsed_response[0], len);
}

static PyObject* server_add_procedure(py_server_t* self, PyObject* args) {
    // Take a function object, introspect its arguments,
    // register them inside of a higher-level function,
    // which on every call requests them via `ucall_param_named_...`
    // from the `ucall_call_t` context, then wraps them into native
    // Python objects and passes to the original function.
    // The result of that function call must then be returned via
    // the `ucall_call_send_content` call.
    py_wrapper_t wrap;
    if (!PyArg_ParseTuple(args, "O", &wrap.callable) || !PyCallable_Check(wrap.callable)) {
        PyErr_SetString(PyExc_TypeError, "Need a callable object!");
        return NULL;
    }

    if (prepare_wrapper(wrap.callable, &wrap) != 0)
        return NULL;

    if (self->count_added >= self->wrapper_capacity) {
        self->wrapper_capacity *= 2;
        self->wrappers = (py_wrapper_t*)realloc(self->wrappers, self->wrapper_capacity);
    }

    self->wrappers[self->count_added] = wrap;

    ucall_add_procedure(self->server, PyUnicode_AsUTF8(PyObject_GetAttrString(wrap.callable, "__name__")), wrapper,
                        &self->wrappers[self->count_added]);

    ++self->count_added;
    Py_INCREF(wrap.callable);
    return wrap.callable;
}

static bool pycheck_take_call(py_server_t* self, uint16_t thread_idx) {
    if (PyErr_CheckSignals() != 0) { // Must be called from the main thread only!
        PyGILState_STATE gstate = PyGILState_Ensure();
        PyErr_SetString(PyExc_KeyboardInterrupt, "Server Stopped");
        PyGILState_Release(gstate);
        return false;
    }
    ucall_take_call(self->server, thread_idx);
    return true;
}

static PyObject* server_run(py_server_t* self, PyObject* args) {
    Py_ssize_t max_cycles = -1;
    double max_seconds = -1;
    // If none are provided, it is wiser to use the `ucall_take_calls`,
    // as it has a more efficient busy-waiting loop implementation.
    if (!PyArg_ParseTuple(args, "|nd", &max_cycles, &max_seconds)) {
        PyErr_SetString(PyExc_TypeError, "Expecting a cycle count and timeout.");
        return NULL;
    }
    if (max_cycles == -1 && max_seconds == -1) {
        while (pycheck_take_call(self, 0))
            ;
    } else if (max_seconds == -1) {
        while (max_cycles > 0 && pycheck_take_call(self, 0))
            --max_cycles;
    } else if (max_cycles == -1) {
        time_t start, end;
        time(&start);
        while (max_seconds > 0 && pycheck_take_call(self, 0)) {
            time(&end);
            max_seconds -= difftime(end, start);
            start = end;
        }
    } else {
        time_t start, end;
        time(&start);
        while (max_cycles > 0 && max_seconds > 0 && pycheck_take_call(self, 0)) {
            --max_cycles;
            time(&end);
            max_seconds -= difftime(end, start);
            start = end;
        }
    }

    return NULL;
}

static Py_ssize_t server_callbacks_count(py_server_t* self, PyObject* _) { return self->count_added; }
static PyObject* server_port(py_server_t* self, PyObject* _) { return PyLong_FromLong(self->config.port); }
static PyObject* server_queue_depth(py_server_t* self, PyObject* _) {
    return PyLong_FromLong(self->config.queue_depth);
}
static PyObject* server_max_lifetime(py_server_t* self, PyObject* _) {
    return PyLong_FromLong(self->config.max_lifetime_micro_seconds);
}

static PyMethodDef server_methods[] = {
    {"route", (PyCFunction)&server_add_procedure, METH_VARARGS, PyDoc_STR("Append a procedure callback")},
    {"run", (PyCFunction)&server_run, METH_VARARGS,
     PyDoc_STR("Runs the server for N calls or T seconds, before returning")},
    {NULL},
};

static PyGetSetDef server_computed_properties[] = {
    {"port", (getter)&server_port, NULL, PyDoc_STR("On which port the server listens")},
    {"queue_depth", (getter)&server_queue_depth, NULL, PyDoc_STR("Max number of concurrent users")},
    {"max_lifetime", (getter)&server_max_lifetime, NULL, PyDoc_STR("Max lifetime of connections in microseconds")},
    {NULL},
};

static PyMappingMethods server_mapping_methods = {
    .mp_length = (lenfunc)server_callbacks_count,
    .mp_subscript = NULL,
    .mp_ass_subscript = NULL,
};

static void server_dealloc(py_server_t* self) {
    free(self->wrappers);
    ucall_free(self->server);
    Py_TYPE(self)->tp_free((PyObject*)self);
}

static PyObject* server_new(PyTypeObject* type, PyObject* args, PyObject* keywords) {
    py_server_t* self = (py_server_t*)type->tp_alloc(type, 0);
    return (PyObject*)self;
}

static int server_init(py_server_t* self, PyObject* args, PyObject* keywords) {
    static char const const* keywords_list[] = {
        "hostname",      "port",  "queue_depth", "max_callbacks", "max_threads",
        "count_threads", "quiet", "ssl_pk",      "ssl_certs",     NULL,
    };
    self->config.hostname = "0.0.0.0";
    self->config.port = 8545;
    self->config.queue_depth = 4096;
    self->config.max_callbacks = UINT16_MAX;
    self->config.max_threads = 16;
    self->config.max_concurrent_connections = 1024;
    self->config.max_lifetime_exchanges = UINT32_MAX;
    self->count_threads = 1;
    self->quiet = false;

    PyObject* certs_path = NULL;

    if (!PyArg_ParseTupleAndKeywords(args, keywords, "|snnnnnp", (char**)keywords_list, //
                                     &self->config.hostname, &self->config.port, &self->config.queue_depth,
                                     &self->config.max_callbacks, &self->config.max_threads, &self->count_threads,
                                     &self->quiet))
        return -1;

    self->wrapper_capacity = 16;
    self->wrappers = (py_wrapper_t*)malloc(self->wrapper_capacity * sizeof(py_wrapper_t));

    // Initialize the server
    ucall_init(&self->config, &self->server);
    if (self->server == NULL) {
        PyErr_SetString(PyExc_RuntimeError, "Server Initialization");
        return -1;
    }

    if (!self->quiet) {
        printf("Initialized server: %s:%i\n", self->config.hostname, self->config.port);
        printf("- %i threads\n", self->config.max_threads);
        printf("- %u max concurrent connections\n", self->config.max_concurrent_connections);
    }
    return 0;
}

// Order: https://docs.python.org/3/c-api/typeobj.html#quick-reference
static PyTypeObject ucall_type = {
    PyVarObject_HEAD_INIT(NULL, 0).tp_name = "ucall." stringify_value_m(UCALL_PYTHON_MODULE_NAME) ".Server",
    .tp_basicsize = sizeof(py_server_t),
    .tp_itemsize = 0,
    .tp_dealloc = (destructor)server_dealloc,
    // TODO:
    // .tp_vectorcall_offset = 0,
    // .tp_repr = NULL,
    .tp_as_mapping = &server_mapping_methods,
    .tp_flags = Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE,
    .tp_doc = PyDoc_STR("Server class for Remote Procedure Calls implemented in Python"),
    .tp_methods = server_methods,
    .tp_call = (ternaryfunc)&server_add_procedure,
    .tp_getset = server_computed_properties,
    .tp_init = (initproc)server_init,
    .tp_new = server_new,
};

static PyModuleDef server_module = {
    PyModuleDef_HEAD_INIT,
    .m_name = "ucall." stringify_value_m(UCALL_PYTHON_MODULE_NAME),
    .m_doc = "Uninterrupted JSON Remote Procedure Calls library.",
    .m_size = -1,
};

PyMODINIT_FUNC pyinit_f_m(void) {
    if (PyType_Ready(&ucall_type) < 0)
        return NULL;

    PyObject* m = PyModule_Create(&server_module);
    if (!m)
        return NULL;

    Py_INCREF(&ucall_type);
    if (PyModule_AddObject(m, "Server", (PyObject*)&ucall_type) < 0) {
        Py_DECREF(&ucall_type);
        Py_DECREF(m);
        return NULL;
    }

    return m;
}

int main(int argc, char* argv[]) {
    wchar_t* program = Py_DecodeLocale(argv[0], NULL);
    if (!program) {
        fprintf(stderr, "Fatal error: cannot decode argv[0]\n");
        exit(1);
    }

    // Add a built-in module, before Py_Initialize
    if (PyImport_AppendInittab("ucall." stringify_value_m(UCALL_PYTHON_MODULE_NAME), pyinit_f_m) == -1) {
        fprintf(stderr, "Error: could not extend in-built modules table\n");
        exit(1);
    }

    // Pass argv[0] to the Python interpreter
    PyConfig config;
    PyConfig_InitPythonConfig(&config);
    config.program_name = program;

    // Initialize the Python interpreter.  Required.
    // If this step fails, it will be a fatal error.
    PyStatus status = Py_InitializeFromConfig(&config);
    if (PyStatus_Exception(status)) {
        fprintf(stderr, "Couldn't initialize from config\n");
        exit(1);
    }
    PyConfig_Clear(&config);

    // Optionally import the module; alternatively, import can be deferred
    // until the embedded script imports it.
    PyObject* pmodule = PyImport_ImportModule("ucall." stringify_value_m(UCALL_PYTHON_MODULE_NAME));
    if (!pmodule) {
        PyErr_Print();
        fprintf(stderr, "Error: could not import module 'ucall'\n");
    }

    // Add version metadata
    {
        char version_str[50];
        sprintf(version_str, "%d.%d.%d", UCALL_VERSION_MAJOR, UCALL_VERSION_MINOR, UCALL_VERSION_PATCH);
        PyModule_AddStringConstant(pmodule, "__version__", version_str);
    }

    PyMem_RawFree(program);
    return 0;
}