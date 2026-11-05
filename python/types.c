/**
 *  @file python/types.c
 *  @author Ash Vardanian
 *  @date January 30, 2023
 *  @brief The shared vocabulary of `ucall.lib`: statuses and enums, `Error`, and Noise keys.
 */
#include "lib.h"

#pragma region Enums

static char const* spell_status(int value) { return ucall_status_name((ucall_status_t)value); }
static char const* spell_backend(int value) { return ucall_io_backend_name((ucall_io_backend_t)value); }
static char const* spell_cpu_class(int value) { return ucall_cpu_class_name((ucall_cpu_class_t)value); }

/** The C interface spells neither security modes nor verbs, so this module does, in value order. */
static char const* spell_security(int value) {
    static char const* const names[] = {"none", "noise-xx", "noise-ik", "noise-kk"};
    return names[value];
}

static char const* spell_verb(int value) {
    static char const* const names[] = {"unknown", "get", "post", "put", "delete", "patch", "head", "options", "any"};
    return names[value];
}

static char const* spell_body_delivery(int value) {
    static char const* const names[] = {"buffered", "streamed"};
    return names[value];
}

static char const* spell_log_level(int value) {
    static char const* const names[] = {"debug", "info", "warning", "error", "fatal"};
    return names[value];
}

static char const* spell_log_format(int value) {
    static char const* const names[] = {"human", "json"};
    return names[value];
}

static char const doc_Status[] =                                                  //
    "Status(value)\n"                                                             //
    "\n"                                                                          //
    "The outcome of a verb, which `Error.status` and `Completed.status` carry.\n" //
    "\n"                                                                          //
    "Example:\n"                                                                  //
    "  >>> ucall.Status.CONTENDED.name\n"                                         //
    "  'CONTENDED'";

static char const doc_Backend[] =                                                                  //
    "Backend(value)\n"                                                                             //
    "\n"                                                                                           //
    "An I/O implementation for `Server` and `Client`; `AUTOMATIC` picks the best one available.\n" //
    "\n"                                                                                           //
    "Example:\n"                                                                                   //
    "  >>> ucall.Server(ucall.Interface(\"127.0.0.1:0\"), backend=ucall.Backend.POSIX).backend\n"  //
    "  <Backend.POSIX: 1>";

static char const doc_CPUClass[] =                                                                    //
    "CPUClass(value)\n"                                                                               //
    "\n"                                                                                              //
    "A bundle of CPU kernels for `Server` and `Client`; `UNKNOWN` picks the initializing thread's.\n" //
    "\n"                                                                                              //
    "Example:\n"                                                                                      //
    "  >>> ucall.Server(ucall.Interface(\"127.0.0.1:0\"), cpu_class=\"serial\").cpu_class\n"          //
    "  <CPUClass.SERIAL: 1>";

static char const doc_Security[] =                                                             //
    "Security(value)\n"                                                                        //
    "\n"                                                                                       //
    "Transport encryption of an `Interface` or a client call: plaintext or a Noise pattern.\n" //
    "\n"                                                                                       //
    "Example:\n"                                                                               //
    "  >>> ucall.Security[\"NOISE_XX\"]\n"                                                     //
    "  <Security.NOISE_XX: 1>";

static char const doc_Verb[] =                                                                 //
    "Verb(value)\n"                                                                            //
    "\n"                                                                                       //
    "An HTTP method; `ANY` registers an endpoint for every method and never arrives itself.\n" //
    "\n"                                                                                       //
    "Example:\n"                                                                               //
    "  >>> ucall.Verb.POST == 2\n"                                                             //
    "  True";

static char const doc_BodyDelivery[] =                                                          //
    "BodyDelivery(value)\n"                                                                     //
    "\n"                                                                                        //
    "When an endpoint's handler runs: once the body is buffered, or at headers time with the\n" //
    "body pulled through `DetachedRequest.body_chunks`.\n"                                      //
    "\n"                                                                                        //
    "Example:\n"                                                                                //
    "  >>> @server.post(\"/upload\", body=ucall.BodyDelivery.STREAMED)\n"                       //
    "  ... def upload(request: ucall.Request):\n"                                               //
    "  ...     workers.submit(store, request.detach())";

static char const doc_LogFormat[] =                                                         //
    "LogFormat(value)\n"                                                                    //
    "\n"                                                                                    //
    "How the library spells a log line: as human-readable fields, or as one JSON object.\n" //
    "\n"                                                                                    //
    "Example:\n"                                                                            //
    "  >>> ucall.LogFormat.JSON\n"                                                          //
    "  <LogFormat.JSON: 1>";

static char const doc_LogLevel[] =                                                           //
    "LogLevel(value)\n"                                                                      //
    "\n"                                                                                     //
    "The severity of a line the `Server` log callback receives, from the most verbose up.\n" //
    "\n"                                                                                     //
    "Example:\n"                                                                             //
    "  >>> ucall.LogLevel.WARNING > ucall.LogLevel.INFO\n"                                   //
    "  True";

ucall_py_enum_mirror_t ucall_py_status_enum = {
    "Status", doc_Status, ucall_status_success_k, ucall_status_would_block_k, spell_status, NULL,
};
ucall_py_enum_mirror_t ucall_py_backend_enum = {
    "Backend", doc_Backend, ucall_io_backend_automatic_k, ucall_io_backend_windows_iocp_k, spell_backend, NULL,
};
ucall_py_enum_mirror_t ucall_py_cpu_class_enum = {
    "CPUClass", doc_CPUClass, ucall_cpu_class_unknown_k, ucall_cpu_class_monoversioned_k, spell_cpu_class, NULL,
};
ucall_py_enum_mirror_t ucall_py_security_enum = {
    "Security", doc_Security, ucall_security_none_k, ucall_security_noise_kk_k, spell_security, NULL,
};
ucall_py_enum_mirror_t ucall_py_verb_enum = {
    "Verb", doc_Verb, ucall_verb_unknown_k, ucall_verb_any_k, spell_verb, NULL,
};
ucall_py_enum_mirror_t ucall_py_body_delivery_enum = {
    "BodyDelivery",
    doc_BodyDelivery,
    ucall_body_delivery_buffered_k,
    ucall_body_delivery_streamed_k,
    spell_body_delivery,
    NULL,
};
ucall_py_enum_mirror_t ucall_py_log_level_enum = {
    "LogLevel", doc_LogLevel, ucall_log_level_debug_k, ucall_log_level_fatal_k, spell_log_level, NULL,
};
ucall_py_enum_mirror_t ucall_py_log_format_enum = {
    "LogFormat", doc_LogFormat, ucall_log_format_human_k, ucall_log_format_json_k, spell_log_format, NULL,
};

#pragma endregion Enums

#pragma region Errors

static char const doc_Error[] =                                                     //
    "Error(status, message, /)\n"                                                   //
    "\n"                                                                            //
    "A failed verb, raised with the `Status` it reported and a static detail.\n"    //
    "\n"                                                                            //
    "Args:\n"                                                                       //
    "  status (Status): The failure, such as `Status.CONTENDED`.\n"                 //
    "  message (str): The detail of the failure, or the status name without one.\n" //
    "\n"                                                                            //
    "Example:\n"                                                                    //
    "  >>> error = ucall.Error(ucall.Status.TIMEOUT, \"no reply\")\n"               //
    "  >>> error.status, error.message, str(error)\n"                               //
    "  (<Status.TIMEOUT: 22>, 'no reply', 'TIMEOUT: no reply')";

static PyObject* Error_get_status(PyBaseExceptionObject* self, void* closure) {
    (void)closure;
    if (!self->args || PyTuple_GET_SIZE(self->args) < 1) Py_RETURN_NONE;
    return Py_NewRef(PyTuple_GET_ITEM(self->args, 0));
}

static PyObject* Error_get_message(PyBaseExceptionObject* self, void* closure) {
    (void)closure;
    if (!self->args || PyTuple_GET_SIZE(self->args) < 2) Py_RETURN_NONE;
    return Py_NewRef(PyTuple_GET_ITEM(self->args, 1));
}

static PyObject* Error_str(PyBaseExceptionObject* self) {
    if (!self->args || PyTuple_GET_SIZE(self->args) != 2) return PyObject_Str(self->args ? self->args : Py_None);
    PyObject* const status = PyTuple_GET_ITEM(self->args, 0);
    PyObject* const name = PyLong_Check(status) ? PyObject_GetAttrString(status, "name") : NULL;
    if (!name) PyErr_Clear();
    PyObject* const text = PyUnicode_FromFormat("%S: %S", name ? name : status, PyTuple_GET_ITEM(self->args, 1));
    Py_XDECREF(name);
    return text;
}

static PyGetSetDef Error_getset[] = {
    {"status", (getter)Error_get_status, NULL, "The `Status` of the failure.", NULL},
    {"message", (getter)Error_get_message, NULL, "The detail of the failure.", NULL},
    {NULL, NULL, NULL, NULL, NULL},
};

PyTypeObject ErrorType = {
    PyVarObject_HEAD_INIT(NULL, 0).tp_name = "ucall.Error",
    .tp_basicsize = sizeof(PyBaseExceptionObject),
    // Collection support and its traversal are inherited from `RuntimeError` when readied.
    .tp_flags = Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE,
    .tp_doc = doc_Error,
    .tp_str = (reprfunc)Error_str,
    .tp_getset = Error_getset,
};

#pragma endregion Errors

#pragma region Noise Keys

ucall_status_t ucall_py_authorize_peer(ucall_noise_key_t const* peer_static_key, void* context) {
    PyGILState_STATE const state = PyGILState_Ensure();
    PyObject* const authorizer = (PyObject*)context;
    PyObject* const key = PyBytes_FromStringAndSize((char const*)*peer_static_key, sizeof(ucall_noise_key_t));
    PyObject* const verdict = key ? PyObject_CallOneArg(authorizer, key) : NULL;
    int const admitted = verdict ? PyObject_IsTrue(verdict) : -1;
    if (admitted < 0) ucall_py_report_handler_failure(authorizer);
    Py_XDECREF(verdict);
    Py_XDECREF(key);
    PyGILState_Release(state);
    return admitted == 1 ? ucall_status_success_k : ucall_status_peer_rejected_k;
}

static char const doc_generate_noise_keypair[] =                                          //
    "generate_noise_keypair() -> tuple[bytes, bytes]\n"                                   //
    "\n"                                                                                  //
    "Draws a fresh Noise identity from the operating system's entropy.\n"                 //
    "\n"                                                                                  //
    "Returns:\n"                                                                          //
    "  tuple[bytes, bytes]: The 32-byte private key, for `Interface` and `Client`, and\n" //
    "    the 32-byte public key that peer authorizers compare.\n"                         //
    "\n"                                                                                  //
    "Raises:\n"                                                                           //
    "  Error: The operating system refused the entropy.\n"                                //
    "\n"                                                                                  //
    "Example:\n"                                                                          //
    "  >>> private_key, public_key = ucall.generate_noise_keypair()\n"                    //
    "  >>> len(private_key), len(public_key)\n"                                           //
    "  (32, 32)";

static PyObject* api_generate_noise_keypair(PyObject* module, PyObject* unused) {
    (void)module, (void)unused;
    ucall_noise_key_t private_key, public_key;
    ucall_outcome_t outcome = {0};
    ucall_noise_key_generate_t generate = {&outcome, &private_key, &public_key};
    ucall_noise_key_generate(&generate);
    if (ucall_py_raise_outcome(&outcome) != 0) return NULL;
    PyObject* const private_bytes = PyBytes_FromStringAndSize((char const*)private_key, sizeof(private_key));
    memset(private_key, 0, sizeof(private_key));
    PyObject* const public_bytes = PyBytes_FromStringAndSize((char const*)public_key, sizeof(public_key));
    PyObject* const pair = private_bytes && public_bytes ? PyTuple_Pack(2, private_bytes, public_bytes) : NULL;
    Py_XDECREF(private_bytes);
    Py_XDECREF(public_bytes);
    return pair;
}

static char const doc_derive_noise_public_key[] =                                        //
    "derive_noise_public_key(private_key, /) -> bytes\n"                                 //
    "\n"                                                                                 //
    "Recovers the public half of a stored Noise private key.\n"                          //
    "\n"                                                                                 //
    "Args:\n"                                                                            //
    "  private_key (bytes): The 32-byte private key.\n"                                  //
    "\n"                                                                                 //
    "Returns:\n"                                                                         //
    "  bytes: The 32-byte public key, as a peer authorizer on the other side sees it.\n" //
    "\n"                                                                                 //
    "Raises:\n"                                                                          //
    "  ValueError: `private_key` is not 32 bytes long.\n"                                //
    "\n"                                                                                 //
    "Example:\n"                                                                         //
    "  >>> private_key, public_key = ucall.generate_noise_keypair()\n"                   //
    "  >>> ucall.derive_noise_public_key(private_key) == public_key\n"                   //
    "  True";

static PyObject* api_derive_noise_public_key(PyObject* module, PyObject* private_key) {
    (void)module;
    ucall_noise_key_t private_bytes, public_key;
    if (ucall_py_key_from_object(private_key, "private_key", private_bytes) != 0) return NULL;
    ucall_outcome_t outcome = {0};
    ucall_noise_key_derive_t derive = {&outcome, (ucall_noise_key_t const*)&private_bytes, &public_key};
    ucall_noise_key_derive(&derive);
    memset(private_bytes, 0, sizeof(private_bytes));
    if (ucall_py_raise_outcome(&outcome) != 0) return NULL;
    return PyBytes_FromStringAndSize((char const*)public_key, sizeof(public_key));
}

PyMethodDef ucall_py_noise_methods[] = {
    {"generate_noise_keypair", api_generate_noise_keypair, METH_NOARGS, doc_generate_noise_keypair},
    {"derive_noise_public_key", api_derive_noise_public_key, METH_O, doc_derive_noise_public_key},
    {NULL, NULL, 0, NULL},
};

#pragma endregion Noise Keys
