/**
 *  @file python/server.c
 *  @author Ash Vardanian
 *  @date January 30, 2023
 *  @brief The serving half of `ucall.lib`: `Interface`, `Server`, `Request` and `BatchEndpoint`.
 */
#include "lib.h"

char const ucall_py_default_address_k[] = "127.0.0.1:8545";

#pragma region Interface

typedef struct Interface {
    PyObject ob_base;

    /** The "host:port" to listen on, a @c str. */
    PyObject* address;

    /** The device to pin to, a @c str, or NULL. */
    PyObject* device_name;

    /** The 32-byte Noise identity, a @c bytes, or NULL. */
    PyObject* private_key;

    /** The callable vetting Noise peers, or NULL. */
    PyObject* peer_authorizer;

    /** The encryption of accepted connections. */
    ucall_security_mode_t security;

    /** The requested loops; zero lets the library choose. */
    Py_ssize_t event_loops;

    /** The open-connection budget. */
    Py_ssize_t connections;

    /** The requests one connection carries at once; zero means one. */
    Py_ssize_t pipelined_requests;
} Interface;

static char const doc_Interface[] =                                                                 //
    "Interface(address, *, device_name=None, security=Security.NONE, private_key=None,\n"           //
    "    peer_authorizer=None, event_loops=0, connections=1024, pipelined_requests=0)\n"            //
    "\n"                                                                                            //
    "One address a server answers on, with the security and admission of what arrives there.\n"     //
    "\n"                                                                                            //
    "Args:\n"                                                                                       //
    "  address (str): The \"host:port\" to listen on; port 0 takes a free one, which\n"             //
    "    `Server.addresses` reports.\n"                                                             //
    "  device_name (str, optional): A network device to pin the socket to, such as \"eth0\";\n"     //
    "    None binds by address alone.\n"                                                            //
    "  security (Security, optional): Encryption of accepted connections. Defaults to\n"            //
    "    `Security.NONE`; `Security.NOISE_KK` is refused, as a server cannot name its callers.\n"   //
    "  private_key (bytes, optional): The 32-byte Noise identity, required under Noise.\n"          //
    "  peer_authorizer (Callable[[bytes], bool], optional): Admits a Noise peer by its 32-byte\n"   //
    "    static key, required under `Security.NOISE_XX`; None admits every peer.\n"                 //
    "  event_loops (int, optional): Loops accepting here; 0 takes one for an address and one per\n" //
    "    receive queue for a device.\n"                                                             //
    "  connections (int, optional): Connections open at once. Defaults to 1024.\n"                  //
    "  pipelined_requests (int, optional): Requests one connection carries before the server\n"     //
    "    stops reading from it; 0 means one.\n"                                                     //
    "\n"                                                                                            //
    "Raises:\n"                                                                                     //
    "  TypeError: An argument of the wrong type.\n"                                                 //
    "  ValueError: A `private_key` other than 32 bytes long, or an unknown `security`.\n"           //
    "\n"                                                                                            //
    "Example:\n"                                                                                    //
    "  >>> interface = ucall.Interface(\"127.0.0.1:0\", connections=64, pipelined_requests=16)\n"   //
    "  >>> interface.connections, interface.security\n"                                             //
    "  (64, <Security.NONE: 0>)";

static PyObject* Interface_new(PyTypeObject* type, PyObject* positional, PyObject* keywords) {
    PyObject *address = NULL, *device_name = NULL, *security = NULL, *private_key = NULL, *peer_authorizer = NULL,
             *event_loops = NULL, *connections = NULL, *pipelined_requests = NULL;
    ucall_py_argument_t const arguments[] = {
        {"address", &address},
        {"device_name", &device_name},
        {"security", &security},
        {"private_key", &private_key},
        {"peer_authorizer", &peer_authorizer},
        {"event_loops", &event_loops},
        {"connections", &connections},
        {"pipelined_requests", &pipelined_requests},
    };
    if (ucall_py_parse_tuple("Interface", positional, keywords, 1, 1, arguments,
                             sizeof(arguments) / sizeof(arguments[0])) != 0)
        return NULL;
    if (!PyUnicode_Check(address))
        return PyErr_Format(PyExc_TypeError, "'address' must be str, got %s", Py_TYPE(address)->tp_name);
    if (device_name == Py_None) device_name = NULL;
    if (device_name && !PyUnicode_Check(device_name))
        return PyErr_Format(PyExc_TypeError, "'device_name' must be str or None, got %s",
                            Py_TYPE(device_name)->tp_name);
    if (private_key == Py_None) private_key = NULL;
    ucall_noise_key_t key_check;
    if (private_key && ucall_py_key_from_object(private_key, "private_key", key_check) != 0) return NULL;
    if (peer_authorizer == Py_None) peer_authorizer = NULL;
    if (peer_authorizer && !PyCallable_Check(peer_authorizer))
        return PyErr_Format(PyExc_TypeError, "'peer_authorizer' must be callable, got %s",
                            Py_TYPE(peer_authorizer)->tp_name);
    int security_mode = ucall_security_mode_none_k;
    size_t loops = 0, budget = 1024, pipelined = 0;
    if (ucall_py_enum_from_object(security, "security", &ucall_py_security_enum, &security_mode) != 0 ||
        ucall_py_size_from_object(event_loops, "event_loops", &loops) != 0 ||
        ucall_py_size_from_object(connections, "connections", &budget) != 0 ||
        ucall_py_size_from_object(pipelined_requests, "pipelined_requests", &pipelined) != 0)
        return NULL;

    Interface* const self = (Interface*)type->tp_alloc(type, 0);
    if (!self) return NULL;
    self->address = Py_NewRef(address);
    self->device_name = Py_XNewRef(device_name);
    self->private_key = Py_XNewRef(private_key);
    self->peer_authorizer = Py_XNewRef(peer_authorizer);
    self->security = (ucall_security_mode_t)security_mode;
    self->event_loops = (Py_ssize_t)loops;
    self->connections = (Py_ssize_t)budget;
    self->pipelined_requests = (Py_ssize_t)pipelined;
    return (PyObject*)self;
}

static int Interface_traverse(Interface* self, visitproc visit, void* arg) {
    Py_VISIT(self->peer_authorizer);
    return 0;
}

static int Interface_clear(Interface* self) {
    Py_CLEAR(self->peer_authorizer);
    return 0;
}

static void Interface_dealloc(Interface* self) {
    PyObject_GC_UnTrack(self);
    Interface_clear(self);
    Py_CLEAR(self->address);
    Py_CLEAR(self->device_name);
    Py_CLEAR(self->private_key);
    Py_TYPE(self)->tp_free((PyObject*)self);
}

static PyObject* Interface_get_security(Interface* self, void* closure) {
    (void)closure;
    return ucall_py_enum_to_object(&ucall_py_security_enum, self->security);
}

static PyMemberDef Interface_members[] = {
    {"address", Py_T_OBJECT_EX, offsetof(Interface, address), Py_READONLY, "The \"host:port\" to listen on."},
    {"event_loops", Py_T_PYSSIZET, offsetof(Interface, event_loops), Py_READONLY, "Requested loops; 0 chooses."},
    {"connections", Py_T_PYSSIZET, offsetof(Interface, connections), Py_READONLY, "Connections open at once."},
    {"pipelined_requests", Py_T_PYSSIZET, offsetof(Interface, pipelined_requests), Py_READONLY,
     "Requests one connection carries at once; 0 means one."},
    {NULL, 0, 0, 0, NULL},
};

static PyGetSetDef Interface_getset[] = {
    {"security", (getter)Interface_get_security, NULL, "Encryption of accepted connections.", NULL},
    {"device_name", ucall_py_get_optional, NULL, "The pinned device, or None.",
     (void*)offsetof(Interface, device_name)},
    {"private_key", ucall_py_get_optional, NULL, "The 32-byte Noise identity, or None.",
     (void*)offsetof(Interface, private_key)},
    {"peer_authorizer", ucall_py_get_optional, NULL, "The Noise peer vetting, or None.",
     (void*)offsetof(Interface, peer_authorizer)},
    {NULL, NULL, NULL, NULL, NULL},
};

PyTypeObject InterfaceType = {
    PyVarObject_HEAD_INIT(NULL, 0).tp_name = "ucall.Interface",
    .tp_basicsize = sizeof(Interface),
    .tp_flags = Py_TPFLAGS_DEFAULT | Py_TPFLAGS_HAVE_GC,
    .tp_doc = doc_Interface,
    .tp_new = Interface_new,
    .tp_traverse = (traverseproc)Interface_traverse,
    .tp_clear = (inquiry)Interface_clear,
    .tp_dealloc = (destructor)Interface_dealloc,
    .tp_members = Interface_members,
    .tp_getset = Interface_getset,
};

#pragma endregion Interface

#pragma region Requests

/** Whether `stop()` was asked, which `run()` checks between its polling slices. */
typedef enum server_stage_t {
    server_serving_k = 0,
    server_stopping_k,
} server_stage_t;

typedef struct Server {
    PyObject ob_base;
    ucall_server_t handle;

    /** Every default filled in; the arrays it points at belong to @c handle. */
    ucall_server_config_t resolved;

    /** The largest resolved @c event_loops among the interfaces: the server's parallelism. */
    size_t event_loops;

    /** The @c Interface tuple, keeping each authorizer the C interface borrows alive. */
    PyObject* interfaces;

    /** Every endpoint context the C interface borrows, an @c Endpoint or @c BatchEndpoint. */
    PyObject* endpoints;

    /** Advanced by `stop()`, under the interpreter lock like every read of it. */
    server_stage_t stage;
} Server;

typedef struct Request {
    PyObject ob_base;

    /** The retained C request, NULL once a reply consumed it. */
    ucall_received_http_request_t handle;

    /** The server that received it, kept alive as long as the request. */
    Server* server;

    /** Live buffer exports over the body, each of which a reply would leave dangling. */
    Py_ssize_t exports;
} Request;

static char const reply_dropped_k[] = "The endpoint released the request without a reply";
static char const reply_failed_k[] = "The endpoint handler raised an exception";

/** The content type of a reply, chosen by what the handler returned. */
static char const binary_header_text_k[] = "content-type: application/octet-stream";
static char const text_header_text_k[] = "content-type: text/plain; charset=utf-8";
static char const json_header_text_k[] = "content-type: application/json";

static ucall_bytes_view_t const binary_header_k = {(ucall_byte_t const*)binary_header_text_k,
                                                   sizeof(binary_header_text_k) - 1};
static ucall_bytes_view_t const text_header_k = {(ucall_byte_t const*)text_header_text_k,
                                                 sizeof(text_header_text_k) - 1};
static ucall_bytes_view_t const json_header_k = {(ucall_byte_t const*)json_header_text_k,
                                                 sizeof(json_header_text_k) - 1};

/** Answers @p request with an error and @p message where no Python caller is left to raise to. */
static ucall_status_t reply_failure(ucall_server_t server, ucall_received_http_request_t request,
                                    ucall_http_status_t status, char const* message, size_t length) {
    ucall_outcome_t outcome = {0};
    ucall_server_reply_error_t reply = {server, &outcome, request, status, {(ucall_byte_t const*)message, length}};
    ucall_server_reply_error(&reply);
    return outcome.status;
}

/** Answers @p request with @p body: 0 when sent or its peer left, -1 with an error raised. */
static int reply_content(ucall_server_t server, ucall_received_http_request_t request, ucall_http_status_t status,
                         ucall_bytes_view_t const* headers, size_t headers_count, ucall_bytes_view_t body) {
    ucall_outcome_t outcome = {0};
    ucall_server_reply_content_t reply = {server, &outcome, request, headers, headers_count, body, status};
    ucall_server_reply_content(&reply);
    return outcome.status == ucall_status_connection_closed_k ? 0 : ucall_py_raise_outcome(&outcome);
}

/**
 *  @brief Serializes a handler's return value: bytes-like as is, @c str as UTF-8, the rest as JSON.
 *  @param[out] body Receives a new reference to a bytes-like object holding the reply body.
 *  @param[out] header Receives the content type line matching the body.
 *  @return 0 on success, -1 with an exception set otherwise.
 */
static int serialize_result(PyObject* result, PyObject** body, ucall_bytes_view_t const** header) {
    if (PyBytes_Check(result) || PyByteArray_Check(result) || PyMemoryView_Check(result)) {
        *body = Py_NewRef(result);
        *header = &binary_header_k;
        return 0;
    }
    int const textual = PyUnicode_Check(result);
    PyObject* const text = textual ? Py_NewRef(result) : PyObject_CallOneArg(ucall_py_json_dumps, result);
    *header = textual ? &text_header_k : &json_header_k;
    *body = text ? PyUnicode_AsUTF8String(text) : NULL;
    Py_XDECREF(text);
    return *body ? 0 : -1;
}

static PyObject* request_new(Server* server, ucall_received_http_request_t handle) {
    Request* const request = PyObject_New(Request, &RequestType);
    if (!request) return NULL;
    request->handle = handle;
    request->server = (Server*)Py_NewRef(server);
    request->exports = 0;
    return (PyObject*)request;
}

/** Answers @p request with an error unless it was replied to or views over its body are alive. */
static void request_fail(Request* request, ucall_http_status_t status, char const* message) {
    if (!request->handle || request->exports) return;
    ucall_status_t const replied = reply_failure(request->server->handle, request->handle, status, message,
                                                 strlen(message));
    if (replied == ucall_status_success_k || replied == ucall_status_connection_closed_k) request->handle = NULL;
}

static int request_live(Request* self) {
    if (self->handle) return 0;
    ucall_py_raise_status(ucall_status_uninitialized_k, "the request was already replied to");
    return -1;
}

static void Request_dealloc(Request* self) {
    request_fail(self, ucall_http_status_internal_error_k, reply_dropped_k);
    Py_CLEAR(self->server);
    PyObject_Free(self);
}

static int Request_getbuffer(Request* self, Py_buffer* view, int flags) {
    if (!self->handle) {
        view->obj = NULL;
        PyErr_SetString(PyExc_BufferError, "the request was already replied to");
        return -1;
    }
    static ucall_byte_t const empty_k[1] = {0};
    ucall_outcome_t outcome = {0};
    ucall_bytes_view_t body = {0};
    ucall_server_request_body_t extract = {self->server->handle, &outcome, self->handle, &body};
    ucall_server_request_body(&extract);
    if (ucall_py_raise_outcome(&outcome) != 0) {
        view->obj = NULL;
        return -1;
    }
    if (PyBuffer_FillInfo(view, (PyObject*)self, (void*)(body.data ? body.data : empty_k), (Py_ssize_t)body.length, 1,
                          flags) != 0)
        return -1;
    ++self->exports;
    return 0;
}

static void Request_releasebuffer(Request* self, Py_buffer* view) {
    (void)view;
    --self->exports;
}

static PyBufferProcs Request_buffer = {(getbufferproc)Request_getbuffer, (releasebufferproc)Request_releasebuffer};

static PyObject* Request_get_body(Request* self, void* closure) {
    (void)closure;
    return PyMemoryView_FromObject((PyObject*)self);
}

static PyObject* Request_get_verb(Request* self, void* closure) {
    (void)closure;
    if (request_live(self) != 0) return NULL;
    return ucall_py_enum_to_object(&ucall_py_verb_enum, ucall_server_request_verb(self->server->handle, self->handle));
}

static PyObject* Request_get_path(Request* self, void* closure) {
    (void)closure;
    if (request_live(self) != 0) return NULL;
    ucall_outcome_t outcome = {0};
    ucall_bytes_view_t path = {0};
    ucall_server_request_path_t extract = {self->server->handle, &outcome, self->handle, &path};
    ucall_server_request_path(&extract);
    if (ucall_py_raise_outcome(&outcome) != 0) return NULL;
    return ucall_py_text_to_object(path);
}

/** The shape every named accessor of a request shares. */
typedef void (*request_lookup_t)(ucall_server_t, ucall_outcome_t*, ucall_received_http_request_t, ucall_bytes_view_t,
                                 ucall_bytes_view_t*);

static void lookup_header(ucall_server_t server, ucall_outcome_t* outcome, ucall_received_http_request_t request,
                          ucall_bytes_view_t name, ucall_bytes_view_t* value) {
    ucall_server_request_header_t arguments = {server, outcome, request, name, value};
    ucall_server_request_header(&arguments);
}

static void lookup_query(ucall_server_t server, ucall_outcome_t* outcome, ucall_received_http_request_t request,
                         ucall_bytes_view_t name, ucall_bytes_view_t* value) {
    ucall_server_request_query_parameter_t arguments = {server, outcome, request, name, value};
    ucall_server_request_query_parameter(&arguments);
}

static void lookup_path_parameter(ucall_server_t server, ucall_outcome_t* outcome,
                                  ucall_received_http_request_t request, ucall_bytes_view_t name,
                                  ucall_bytes_view_t* value) {
    ucall_server_request_path_parameter_t arguments = {server, outcome, request, name, value};
    ucall_server_request_path_parameter(&arguments);
}

/** Looks @p name up with @p lookup: 1 when found, 0 when absent, -1 with an error raised. */
static int find_text(request_lookup_t lookup, ucall_server_t server, ucall_received_http_request_t request,
                     ucall_bytes_view_t name, ucall_bytes_view_t* value) {
    ucall_outcome_t outcome = {0};
    lookup(server, &outcome, request, name, value);
    if (outcome.status == ucall_status_not_found_k) return 0;
    return ucall_py_raise_outcome(&outcome) == 0 ? 1 : -1;
}

static PyObject* request_lookup(Request* self, PyObject* name, request_lookup_t lookup) {
    if (request_live(self) != 0) return NULL;
    ucall_bytes_view_t name_view, value = {0};
    if (ucall_py_text_from_object(name, "name", &name_view) != 0) return NULL;
    int const found = find_text(lookup, self->server->handle, self->handle, name_view, &value);
    if (found < 0) return NULL;
    return found ? ucall_py_text_to_object(value) : Py_NewRef(Py_None);
}

static char const doc_Request_header[] =                                              //
    "header(name, /) -> str | None\n"                                                 //
    "\n"                                                                              //
    "Looks up a header of the request by its case-insensitive name.\n"                //
    "\n"                                                                              //
    "Args:\n"                                                                         //
    "  name (str | bytes): The header name, such as \"Content-Type\".\n"              //
    "\n"                                                                              //
    "Returns:\n"                                                                      //
    "  str | None: The value as sent, or None when the request has no such header.\n" //
    "\n"                                                                              //
    "Example:\n"                                                                      //
    "  >>> @server.get(\"/agent\")\n"                                                 //
    "  ... def agent(request: ucall.Request):\n"                                      //
    "  ...     return request.header(\"user-agent\") or \"unknown\"";

static PyObject* Request_header(Request* self, PyObject* name) { return request_lookup(self, name, lookup_header); }

static char const doc_Request_query[] =                                                  //
    "query(name, /) -> str | None\n"                                                     //
    "\n"                                                                                 //
    "Looks up a query parameter of the request by its case-sensitive name.\n"            //
    "\n"                                                                                 //
    "Args:\n"                                                                            //
    "  name (str | bytes): The parameter name.\n"                                        //
    "\n"                                                                                 //
    "Returns:\n"                                                                         //
    "  str | None: The value still percent-encoded, which `urllib.parse.unquote_plus`\n" //
    "    decodes, or None when the query has no such parameter.\n"                       //
    "\n"                                                                                 //
    "Example:\n"                                                                         //
    "  >>> @server.get(\"/search\")\n"                                                   //
    "  ... def search(request: ucall.Request):\n"                                        //
    "  ...     return urllib.parse.unquote_plus(request.query(\"q\") or \"\")";

static PyObject* Request_query(Request* self, PyObject* name) { return request_lookup(self, name, lookup_query); }

static char const doc_Request_path_parameter[] =                                             //
    "path_parameter(name, /) -> str | None\n"                                                //
    "\n"                                                                                     //
    "Looks up a placeholder the endpoint's URI template captured.\n"                         //
    "\n"                                                                                     //
    "Args:\n"                                                                                //
    "  name (str | bytes): The placeholder name without braces, \"path\" for \"{*path}\".\n" //
    "\n"                                                                                     //
    "Returns:\n"                                                                             //
    "  str | None: The captured text as sent, or None when the template has no such\n"       //
    "    placeholder.\n"                                                                     //
    "\n"                                                                                     //
    "Example:\n"                                                                             //
    "  >>> @server.get(\"/files/{*path}\")\n"                                                //
    "  ... def files(request: ucall.Request):\n"                                             //
    "  ...     return request.path_parameter(\"path\")";

static PyObject* Request_path_parameter(Request* self, PyObject* name) {
    return request_lookup(self, name, lookup_path_parameter);
}

static PyObject* Request_get_peer(Request* self, void* closure) {
    (void)closure;
    if (request_live(self) != 0) return NULL;
    ucall_outcome_t outcome = {0};
    size_t interface_index = 0;
    ucall_noise_key_t static_key = {0};
    ucall_server_request_peer_t query = {self->server->handle, &outcome, self->handle, &interface_index, &static_key};
    ucall_server_request_peer(&query);
    if (ucall_py_raise_outcome(&outcome) != 0) return NULL;
    return Py_BuildValue("(nN)", (Py_ssize_t)interface_index,
                         PyBytes_FromStringAndSize((char const*)static_key, sizeof(ucall_noise_key_t)));
}

/**
 *  @brief Claims the reply: refuses a consumed request, releases @p body when it is this request's
 *      own memoryview, and refuses while any other view over the body would outlive the reply.
 *  @param[out] own Receives the body bytes when @p body was the request's own view, else empty.
 */
static int request_claim_reply(Request* self, PyObject* body, ucall_bytes_view_t* own) {
    own->data = NULL;
    own->length = 0;
    if (!self->handle) {
        ucall_py_raise_status(ucall_status_already_exists_k, "the request was already replied to");
        return -1;
    }
    if (body && PyMemoryView_Check(body) && PyMemoryView_GET_BASE(body) == (PyObject*)self) {
        Py_buffer const* const view = PyMemoryView_GET_BUFFER(body);
        if (!PyBuffer_IsContiguous(view, 'C')) {
            PyErr_SetString(PyExc_BufferError, "a strided view of the request body must be copied before replying");
            return -1;
        }
        own->data = (ucall_byte_t const*)view->buf;
        own->length = (size_t)view->len;
        PyObject* const released = PyObject_CallMethod(body, "release", NULL);
        if (!released) return -1;
        Py_DECREF(released);
    }
    if (self->exports) {
        PyErr_Format(PyExc_BufferError,
                     "%zd views over the request body are alive, and the reply would free their bytes; "
                     "drop them or copy with bytes() first",
                     self->exports);
        return -1;
    }
    return 0;
}

/** Marks the request consumed after a reply that delivered it or found its connection closed. */
static PyObject* request_finish_reply(Request* self, ucall_outcome_t const* outcome) {
    if (outcome->status == ucall_status_success_k || outcome->status == ucall_status_connection_closed_k) {
        self->handle = NULL;
        Py_RETURN_NONE;
    }
    ucall_py_raise_outcome(outcome);
    return NULL;
}

/** Answers @p self with @p body, any bytes-like object or NULL for none, and consumes it. */
static PyObject* request_send(Request* self, PyObject* body, ucall_http_status_t status,
                              ucall_bytes_view_t const* headers, size_t headers_count) {
    ucall_bytes_view_t own;
    if (request_claim_reply(self, body, &own) != 0) return NULL;
    Py_buffer buffer = {0};
    if (body && !own.data && PyObject_GetBuffer(body, &buffer, PyBUF_SIMPLE) != 0) return NULL;
    ucall_bytes_view_t const content = own.data ? own : (ucall_bytes_view_t) {buffer.buf, (size_t)buffer.len};
    ucall_outcome_t outcome = {0};
    ucall_server_reply_content_t reply = {self->server->handle, &outcome, self->handle, headers,
                                          headers_count,        content,  status};
    ucall_server_reply_content(&reply);
    if (buffer.obj) PyBuffer_Release(&buffer);
    return request_finish_reply(self, &outcome);
}

/** Answers @p self with what a handler returned, serialized by @c serialize_result. */
static int request_send_result(Request* self, PyObject* result) {
    PyObject* body = NULL;
    ucall_bytes_view_t const* header = NULL;
    if (serialize_result(result, &body, &header) != 0) return -1;
    PyObject* const sent = request_send(self, body, ucall_http_status_ok_k, header, 1);
    Py_DECREF(body);
    Py_XDECREF(sent);
    return sent ? 0 : -1;
}

static char const doc_Request_reply[] =                                                            //
    "reply(body=b\"\", status=200, headers=()) -> None\n"                                          //
    "\n"                                                                                           //
    "Answers the request, once, from any thread; a peer that disconnected consumes it silently.\n" //
    "\n"                                                                                           //
    "Args:\n"                                                                                      //
    "  body (Buffer, optional): Any bytes-like object, copied before the call returns; the\n"      //
    "    request's own `body` passes without a copy and is released by the reply.\n"               //
    "  status (int, optional): The HTTP status. Defaults to 200.\n"                                //
    "  headers (Sequence[str | bytes], optional): \"name: value\" lines; the server adds\n"        //
    "    Content-Length, Date and Server itself.\n"                                                //
    "\n"                                                                                           //
    "Raises:\n"                                                                                    //
    "  BufferError: A view over `body`, other than the one passed, is still alive.\n"              //
    "  Error: The request was already answered, with `Status.ALREADY_EXISTS`.\n"                   //
    "\n"                                                                                           //
    "Example:\n"                                                                                   //
    "  >>> @server.post(\"/echo\")\n"                                                              //
    "  ... def echo(request: ucall.Request):\n"                                                    //
    "  ...     request.reply(request.body, headers=(\"content-type: application/octet-stream\",))";

static PyObject* Request_reply(Request* self, PyObject* const* values, Py_ssize_t count, PyObject* names) {
    PyObject *body = NULL, *status = NULL, *headers = NULL;
    ucall_py_argument_t const arguments[] = {{"body", &body}, {"status", &status}, {"headers", &headers}};
    if (ucall_py_parse_fast("reply", values, count, names, 0, 3, arguments, 3) != 0) return NULL;
    size_t http_status = ucall_http_status_ok_k;
    if (ucall_py_size_from_object(status, "status", &http_status) != 0) return NULL;
    ucall_py_header_lines_t lines;
    if (ucall_py_header_lines_from_object(headers, &lines) != 0) return NULL;
    PyObject* const sent = request_send(self, body, (ucall_http_status_t)http_status, lines.views, lines.count);
    ucall_py_header_lines_release(&lines);
    return sent;
}

static char const doc_Request_reply_error[] =                                    //
    "reply_error(status, message) -> None\n"                                     //
    "\n"                                                                         //
    "Answers the request with an error status and a plain-text message, once.\n" //
    "\n"                                                                         //
    "Args:\n"                                                                    //
    "  status (int): The HTTP status, 400 or above.\n"                           //
    "  message (str | bytes): The body, sent as text/plain.\n"                   //
    "\n"                                                                         //
    "Raises:\n"                                                                  //
    "  BufferError: A view over `body` is still alive.\n"                        //
    "  Error: The request was already answered, with `Status.ALREADY_EXISTS`.\n" //
    "\n"                                                                         //
    "Example:\n"                                                                 //
    "  >>> @server.get(\"/teapot\")\n"                                           //
    "  ... def teapot(request: ucall.Request):\n"                                //
    "  ...     request.reply_error(418, \"short and stout\\n\")";

static PyObject* Request_reply_error(Request* self, PyObject* const* values, Py_ssize_t count, PyObject* names) {
    PyObject *status = NULL, *message = NULL;
    ucall_py_argument_t const arguments[] = {{"status", &status}, {"message", &message}};
    if (ucall_py_parse_fast("reply_error", values, count, names, 2, 2, arguments, 2) != 0) return NULL;
    size_t http_status = 0;
    ucall_bytes_view_t text;
    if (ucall_py_size_from_object(status, "status", &http_status) != 0 ||
        ucall_py_text_from_object(message, "message", &text) != 0)
        return NULL;
    ucall_bytes_view_t own;
    if (request_claim_reply(self, NULL, &own) != 0) return NULL;
    ucall_outcome_t outcome = {0};
    ucall_server_reply_error_t reply = {self->server->handle, &outcome, self->handle, (ucall_http_status_t)http_status,
                                        text};
    ucall_server_reply_error(&reply);
    return request_finish_reply(self, &outcome);
}

static PyMethodDef Request_methods[] = {
    {"header", (PyCFunction)Request_header, METH_O, doc_Request_header},
    {"query", (PyCFunction)Request_query, METH_O, doc_Request_query},
    {"path_parameter", (PyCFunction)Request_path_parameter, METH_O, doc_Request_path_parameter},
    {"reply", (PyCFunction)(void (*)(void))Request_reply, ucall_py_method_flags_k, doc_Request_reply},
    {"reply_error", (PyCFunction)(void (*)(void))Request_reply_error, ucall_py_method_flags_k, doc_Request_reply_error},
    {NULL, NULL, 0, NULL},
};

static PyGetSetDef Request_getset[] = {
    {"verb", (getter)Request_get_verb, NULL, "The `Verb` it arrived with, never `Verb.ANY`.", NULL},
    {"path", (getter)Request_get_path, NULL, "The path as sent, still percent-encoded, without the query.", NULL},
    {"body", (getter)Request_get_body, NULL, "A read-only memoryview of the body, valid until the reply.", NULL},
    {"peer", (getter)Request_get_peer, NULL,
     "The index of the interface it arrived on and the peer's 32-byte Noise key, zeros on plaintext.", NULL},
    {NULL, NULL, NULL, NULL, NULL},
};

static char const doc_Request[] =                                                                       //
    "One received HTTP request, retained until a reply consumes it.\n"                                  //
    "\n"                                                                                                //
    "A handler taking one parameter annotated `Request` receives it on the polling thread, and may\n"   //
    "keep it to answer later from any thread, once. `body` and the buffer protocol view the received\n" //
    "bytes without a copy until the reply, which is refused while such a view is alive, except the\n"   //
    "`body` passed as the reply body itself. A request released without a reply answers 500.\n"         //
    "\n"                                                                                                //
    "Example:\n"                                                                                        //
    "  >>> @server.put(\"/echo/{name}\")\n"                                                             //
    "  ... def echo(request: ucall.Request):\n"                                                         //
    "  ...     interface_index, static_key = request.peer\n"                                            //
    "  ...     greeting = f\"{request.verb.name} {request.path_parameter('name')}\"\n"                  //
    "  ...     request.reply(request.body, headers=(f\"x-greeting: {greeting}\",))";

PyTypeObject RequestType = {
    PyVarObject_HEAD_INIT(NULL, 0).tp_name = "ucall.Request",
    .tp_basicsize = sizeof(Request),
    .tp_flags = Py_TPFLAGS_DEFAULT,
    .tp_doc = doc_Request,
    .tp_dealloc = (destructor)Request_dealloc,
    .tp_as_buffer = &Request_buffer,
    .tp_methods = Request_methods,
    .tp_getset = Request_getset,
};

#pragma endregion Requests

#pragma region Typed Handlers

/** The scalar a parameter's annotation names, which request text and JSON values convert to. */
typedef enum scalar_kind_t {
    any_k = 0,
    text_k,
    integer_k,
    real_k,
    boolean_k,
    bytes_k,
} scalar_kind_t;

/** Where a parameter is looked up first: a template placeholder, or the query. */
typedef enum parameter_origin_t {
    origin_query_k = 0,
    origin_path_k,
} parameter_origin_t;

/** One handler parameter, resolved once at registration and read by every request. */
typedef struct parameter_t {

    /** UTF-8 of the interned name the @c Endpoint keeps, for the path and query lookups. */
    ucall_bytes_view_t name;

    /** The value a request without one binds, or NULL when the request must supply it. */
    PyObject* default_value;

    /** The annotated type the value converts to. */
    scalar_kind_t kind;

    /** Whether a placeholder of the URI template is looked up before the query. */
    parameter_origin_t origin;
} parameter_t;

/** The parameters a typed handler may take, laid out inline in its @c Endpoint. */
enum { max_parameters_k = 16 };

typedef struct Endpoint {
    PyObject ob_base;

    /** The server that registered the route, kept alive while its callbacks may run. */
    Server* server;

    /** The registered function. */
    PyObject* handler;

    /** Every parameter's interned name in signature order, a tuple, or NULL for a raw handler. */
    PyObject* names;

    /** The vectorcall names tuple, the tail of @c names after the positional-only ones, or NULL. */
    PyObject* keywords;

    /** The positional-only parameters, which lead the signature and are passed by position. */
    size_t positional_count;

    /** Entries of @c parameters in use. */
    size_t parameters_count;

    /** The parameter table, in signature order. */
    parameter_t parameters[max_parameters_k];
} Endpoint;

/** The Python type a scalar kind checks JSON values against, or NULL for any value. */
static PyTypeObject* scalar_type(scalar_kind_t kind) {
    switch (kind) {
    case text_k: return &PyUnicode_Type;
    case integer_k: return &PyLong_Type;
    case real_k: return &PyFloat_Type;
    case boolean_k: return &PyBool_Type;
    case bytes_k: return &PyBytes_Type;
    default: return NULL;
    }
}

/** Whether @p data spells @p spelling in any ASCII case. */
static int spells_as(char const* data, size_t length, char const* spelling) {
    size_t index = 0;
    for (; index != length && spelling[index]; ++index) {
        char const letter = data[index];
        if ((letter >= 'A' && letter <= 'Z' ? (char)(letter - 'A' + 'a') : letter) != spelling[index]) return 0;
    }
    return index == length && !spelling[index];
}

/** Converts request text to @p kind as `int` and `float` do, decoding UTF-8 with @p errors. */
static PyObject* scalar_from_text(char const* data, size_t length, scalar_kind_t kind, char const* errors) {
    if (kind == bytes_k) return PyBytes_FromStringAndSize(data, (Py_ssize_t)length);
    if (kind == boolean_k) {
        static char const* const true_spellings[] = {"1", "true", "yes", "on"};
        static char const* const false_spellings[] = {"0", "false", "no", "off"};
        for (size_t index = 0; index != sizeof(true_spellings) / sizeof(true_spellings[0]); ++index) {
            if (spells_as(data, length, true_spellings[index])) Py_RETURN_TRUE;
            if (spells_as(data, length, false_spellings[index])) Py_RETURN_FALSE;
        }
    }
    PyObject* const text = PyUnicode_DecodeUTF8(data, (Py_ssize_t)length, errors);
    if (!text || kind == any_k || kind == text_k) return text;
    PyObject* const value = kind == integer_k ? PyLong_FromUnicodeObject(text, 10)
                            : kind == real_k  ? PyFloat_FromString(text)
                                              : PyErr_Format(PyExc_ValueError, "expected a boolean, got %R", text);
    Py_DECREF(text);
    return value;
}

static int hex_digit(ucall_byte_t character) {
    if (character >= '0' && character <= '9') return character - '0';
    if (character >= 'a' && character <= 'f') return character - 'a' + 10;
    if (character >= 'A' && character <= 'F') return character - 'A' + 10;
    return -1;
}

/** Converts a query value to @p kind, percent-decoded with "+" as a space as by `unquote_plus`. */
static PyObject* scalar_from_query(ucall_bytes_view_t text, scalar_kind_t kind) {
    char inline_buffer[256];
    char* const decoded = text.length <= sizeof(inline_buffer) ? inline_buffer : PyMem_Malloc(text.length);
    if (!decoded) return PyErr_NoMemory();
    size_t length = 0;
    for (size_t index = 0; index != text.length; ++index) {
        ucall_byte_t const character = text.data[index];
        int const high = character == '%' && index + 2 < text.length ? hex_digit(text.data[index + 1]) : -1;
        int const low = high >= 0 ? hex_digit(text.data[index + 2]) : -1;
        if (low >= 0) decoded[length++] = (char)(high * 16 + low), index += 2;
        else decoded[length++] = character == '+' ? ' ' : (char)character;
    }
    PyObject* const value = scalar_from_text(decoded, length, kind, "replace");
    if (decoded != inline_buffer) PyMem_Free(decoded);
    return value;
}

/** Checks a JSON field against @p kind, widening integers to floats and text to bytes. */
static PyObject* scalar_from_json(PyObject* value, scalar_kind_t kind) {
    PyTypeObject* const type = scalar_type(kind);
    if (!type) return Py_NewRef(value);
    if (kind == real_k && PyLong_Check(value) && !PyBool_Check(value)) return PyNumber_Float(value);
    if (kind == bytes_k && PyUnicode_Check(value)) return PyUnicode_AsUTF8String(value);
    if (Py_TYPE(value) != type)
        return PyErr_Format(PyExc_ValueError, "expected %s, got %s", type->tp_name, Py_TYPE(value)->tp_name);
    return Py_NewRef(value);
}

/** Parses the request body once as a JSON object, an empty body reading as an empty one. */
static PyObject* request_document(ucall_server_t server, ucall_received_http_request_t request) {
    ucall_outcome_t outcome = {0};
    ucall_bytes_view_t body = {0};
    ucall_server_request_body_t extract = {server, &outcome, request, &body};
    ucall_server_request_body(&extract);
    if (ucall_py_raise_outcome(&outcome) != 0) return NULL;
    if (!body.length) return PyDict_New();
    PyObject* const bytes = PyBytes_FromStringAndSize((char const*)body.data, (Py_ssize_t)body.length);
    PyObject* document = bytes ? PyObject_CallOneArg(ucall_py_json_loads, bytes) : NULL;
    Py_XDECREF(bytes);
    if (document && !PyDict_Check(document)) {
        Py_CLEAR(document);
        PyErr_SetString(PyExc_ValueError, "expected a JSON object body");
    }
    return document;
}

/** Binds parameter @p index of @p endpoint from @p request, parsing @p document on first need. */
static PyObject* bind_parameter(Endpoint const* endpoint, size_t index, ucall_received_http_request_t request,
                                PyObject** document) {
    parameter_t const* const parameter = &endpoint->parameters[index];
    ucall_server_t const server = endpoint->server->handle;
    ucall_bytes_view_t text = {0};
    int found = parameter->origin == origin_path_k
                    ? find_text(lookup_path_parameter, server, request, parameter->name, &text)
                    : 0;
    if (found)
        return found > 0 ? scalar_from_text((char const*)text.data, text.length, parameter->kind, "surrogateescape")
                         : NULL;
    found = find_text(lookup_query, server, request, parameter->name, &text);
    if (found) return found > 0 ? scalar_from_query(text, parameter->kind) : NULL;
    if (!*document && !(*document = request_document(server, request))) return NULL;
    PyObject* const name = PyTuple_GET_ITEM(endpoint->names, (Py_ssize_t)index);
    PyObject* const field = PyDict_GetItemWithError(*document, name);
    if (field) return scalar_from_json(field, parameter->kind);
    if (PyErr_Occurred()) return NULL;
    if (parameter->default_value) return Py_NewRef(parameter->default_value);
    return PyErr_Format(PyExc_ValueError, "missing parameter %R", name);
}

/** Answers 400 with the text of the pending binding failure, which it clears. */
static void reply_refusal(ucall_server_t server, ucall_received_http_request_t request) {
    PyObject* const error = PyErr_GetRaisedException();
    PyObject* const text = PyUnicode_FromFormat("%S\n", error);
    Py_ssize_t length = 0;
    char const* const message = text ? PyUnicode_AsUTF8AndSize(text, &length) : NULL;
    if (!message) PyErr_Clear();
    reply_failure(server, request, ucall_http_status_bad_request_k, message ? message : "", (size_t)length);
    Py_XDECREF(text);
    Py_DECREF(error);
}

/** Answers a typed handler's request with what it returned, None answering 204. */
static int reply_result(ucall_server_t server, ucall_received_http_request_t request, PyObject* result) {
    if (result == Py_None)
        return reply_content(server, request, ucall_http_status_no_content_k, NULL, 0, (ucall_bytes_view_t) {0});
    PyObject* body = NULL;
    ucall_bytes_view_t const* header = NULL;
    if (serialize_result(result, &body, &header) != 0) return -1;
    Py_buffer buffer;
    int replied = PyObject_GetBuffer(body, &buffer, PyBUF_SIMPLE);
    if (replied == 0) {
        replied = reply_content(server, request, ucall_http_status_ok_k, header, 1,
                                (ucall_bytes_view_t) {buffer.buf, (size_t)buffer.len});
        PyBuffer_Release(&buffer);
    }
    Py_DECREF(body);
    return replied;
}

/** Runs a handler taking the `Request` itself on the polling thread. */
static void call_request_endpoint(ucall_received_http_request_t handle, void* context) {
    PyGILState_STATE const state = PyGILState_Ensure();
    Endpoint* const endpoint = (Endpoint*)context;
    PyObject* const request = request_new(endpoint->server, handle);
    if (!request) {
        ucall_py_report_handler_failure(endpoint->handler);
        reply_failure(endpoint->server->handle, handle, ucall_http_status_service_unavailable_k, reply_failed_k,
                      strlen(reply_failed_k));
        PyGILState_Release(state);
        return;
    }
    PyObject* const result = PyObject_CallOneArg(endpoint->handler, request);
    if (!result || (result != Py_None && request_send_result((Request*)request, result) != 0)) {
        ucall_py_report_handler_failure(endpoint->handler);
        request_fail((Request*)request, ucall_http_status_internal_error_k, reply_failed_k);
    }
    Py_XDECREF(result);
    Py_DECREF(request);
    PyGILState_Release(state);
}

/** Binds a typed handler's parameters, runs it on the polling thread, and replies. */
static void call_typed_endpoint(ucall_received_http_request_t request, void* context) {
    PyGILState_STATE const state = PyGILState_Ensure();
    Endpoint* const endpoint = (Endpoint*)context;
    ucall_server_t const server = endpoint->server->handle;
    // One leading slot lets the callee borrow it, as `PY_VECTORCALL_ARGUMENTS_OFFSET` allows.
    PyObject* arguments[1 + max_parameters_k] = {NULL};
    PyObject** const values = arguments + 1;
    PyObject* document = NULL;
    size_t bound = 0;
    while (bound != endpoint->parameters_count && (values[bound] = bind_parameter(endpoint, bound, request, &document)))
        ++bound;
    Py_XDECREF(document);
    if (bound != endpoint->parameters_count) {
        if (PyErr_ExceptionMatches(PyExc_ValueError) || PyErr_ExceptionMatches(PyExc_TypeError))
            reply_refusal(server, request);
        else {
            ucall_py_report_handler_failure(endpoint->handler);
            reply_failure(server, request, ucall_http_status_internal_error_k, reply_failed_k, strlen(reply_failed_k));
        }
    }
    else {
        PyObject* const result = PyObject_Vectorcall(
            endpoint->handler, values, endpoint->positional_count | PY_VECTORCALL_ARGUMENTS_OFFSET, endpoint->keywords);
        if (!result || reply_result(server, request, result) != 0) {
            ucall_py_report_handler_failure(endpoint->handler);
            reply_failure(server, request, ucall_http_status_internal_error_k, reply_failed_k, strlen(reply_failed_k));
        }
        Py_XDECREF(result);
    }
    for (size_t index = 0; index != bound; ++index) Py_DECREF(values[index]);
    PyGILState_Release(state);
}

/** Whether the URI template @p path captures @p name, as "{name}" or "{*name}". */
static int template_captures(ucall_bytes_view_t path, ucall_bytes_view_t name) {
    for (size_t index = 0; index != path.length; ++index) {
        if (path.data[index] != '{') continue;
        size_t start = index + 1;
        if (start != path.length && path.data[start] == '*') ++start;
        size_t end = start;
        while (end != path.length && path.data[end] != '}') ++end;
        if (end != path.length && end - start == name.length && memcmp(path.data + start, name.data, name.length) == 0)
            return 1;
        index = end == path.length ? end - 1 : end;
    }
    return 0;
}

/** The scalar kind @p annotation names, or -1 for any type but the five scalars. */
static int scalar_from_annotation(PyObject* annotation) {
    for (int kind = text_k; kind <= bytes_k; ++kind)
        if (annotation == (PyObject*)scalar_type((scalar_kind_t)kind)) return kind;
    return -1;
}

/** Fills one parameter from an `inspect.Parameter`, or refuses it with a @c TypeError. */
static int endpoint_resolve_parameter(Endpoint* endpoint, PyObject* parameter, PyObject* hints, PyObject* empty,
                                      PyObject* qualname, ucall_bytes_view_t path) {
    size_t const index = endpoint->parameters_count;
    PyObject* name = PyObject_GetAttrString(parameter, "name");
    if (!name) return -1;
    PyUnicode_InternInPlace(&name);
    PyTuple_SET_ITEM(endpoint->names, (Py_ssize_t)index, name);
    PyObject* const kind_object = PyObject_GetAttrString(parameter, "kind");
    long const kind = kind_object ? PyLong_AsLong(kind_object) : -1;
    Py_XDECREF(kind_object);
    if (kind == -1 && PyErr_Occurred()) return -1;
    // `inspect.Parameter.kind` is 0 for positional-only, 2 for `*args` and 4 for `**kwargs`.
    if (kind == 2 || kind == 4) {
        PyErr_Format(PyExc_TypeError, "%S cannot bind *%U from a request", qualname, name);
        return -1;
    }
    PyObject* const annotation = PyDict_GetItemWithError(hints, name);
    if (!annotation && PyErr_Occurred()) return -1;
    int const scalar = annotation ? scalar_from_annotation(annotation) : any_k;
    if (scalar < 0) {
        PyErr_Format(PyExc_TypeError, "%S annotates %U as %S, not a scalar or Request", qualname, name, annotation);
        return -1;
    }
    PyObject* const default_value = PyObject_GetAttrString(parameter, "default");
    if (!default_value) return -1;
    Py_ssize_t length = 0;
    char const* const spelled = PyUnicode_AsUTF8AndSize(name, &length);
    if (!spelled) {
        Py_DECREF(default_value);
        return -1;
    }
    parameter_t* const target = &endpoint->parameters[index];
    target->name = (ucall_bytes_view_t) {(ucall_byte_t const*)spelled, (size_t)length};
    target->kind = (scalar_kind_t)scalar;
    target->origin = template_captures(path, target->name) ? origin_path_k : origin_query_k;
    target->default_value = default_value == empty ? NULL : Py_NewRef(default_value);
    Py_DECREF(default_value);
    endpoint->parameters_count = index + 1;
    if (kind == 0) ++endpoint->positional_count;
    return 0;
}

/**
 *  @brief Resolves the handler's signature once, choosing the callback that serves its requests.
 *  @param[in] path The URI template, whose placeholders bind before the query.
 *  @param[out] callback Receives @c call_request_endpoint or @c call_typed_endpoint.
 *  @return 0 on success, -1 with an exception set otherwise.
 */
static int endpoint_resolve(Endpoint* endpoint, ucall_bytes_view_t path,
                            ucall_received_http_request_callback_t* callback) {
    PyObject* const handler = endpoint->handler;
    PyObject *inspect = NULL, *typing = NULL, *signature = NULL, *hints = NULL, *parameters = NULL, *empty = NULL,
             *qualname = NULL;
    int resolved = -1;
    inspect = PyImport_ImportModule("inspect");
    typing = inspect ? PyImport_ImportModule("typing") : NULL;
    signature = typing ? PyObject_CallMethod(inspect, "signature", "O", handler) : NULL;
    hints = signature ? PyObject_CallMethod(typing, "get_type_hints", "O", handler) : NULL;
    if (!hints) goto finished;
    PyObject* const mapping = PyObject_GetAttrString(signature, "parameters");
    PyObject* const listed = mapping ? PyObject_CallMethod(mapping, "values", NULL) : NULL;
    parameters = listed ? PySequence_List(listed) : NULL;
    Py_XDECREF(listed);
    Py_XDECREF(mapping);
    PyObject* const parameter_type = parameters ? PyObject_GetAttrString(inspect, "Parameter") : NULL;
    empty = parameter_type ? PyObject_GetAttrString(parameter_type, "empty") : NULL;
    Py_XDECREF(parameter_type);
    if (!empty) goto finished;
    qualname = PyObject_GetAttrString(handler, "__qualname__");
    if (!qualname) {
        PyErr_Clear();
        qualname = PyObject_Repr(handler);
        if (!qualname) goto finished;
    }

    Py_ssize_t const count = PyList_GET_SIZE(parameters);
    if (count == 1) {
        PyObject* const name = PyObject_GetAttrString(PyList_GET_ITEM(parameters, 0), "name");
        PyObject* const annotation = name ? PyDict_GetItemWithError(hints, name) : NULL;
        Py_XDECREF(name);
        if (annotation == (PyObject*)&RequestType) {
            *callback = call_request_endpoint;
            resolved = 0;
            goto finished;
        }
        if (PyErr_Occurred()) goto finished;
    }
    if (count > max_parameters_k) {
        PyErr_Format(PyExc_TypeError, "%S takes %zd parameters, more than the %d a request binds", qualname, count,
                     (int)max_parameters_k);
        goto finished;
    }
    endpoint->names = PyTuple_New(count);
    if (!endpoint->names) goto finished;
    for (Py_ssize_t index = 0; index != count; ++index)
        if (endpoint_resolve_parameter(endpoint, PyList_GET_ITEM(parameters, index), hints, empty, qualname, path) != 0)
            goto finished;
    if (endpoint->positional_count != (size_t)count) {
        endpoint->keywords = PyTuple_GetSlice(endpoint->names, (Py_ssize_t)endpoint->positional_count, count);
        if (!endpoint->keywords) goto finished;
    }
    *callback = call_typed_endpoint;
    resolved = 0;

finished:
    Py_XDECREF(qualname);
    Py_XDECREF(empty);
    Py_XDECREF(parameters);
    Py_XDECREF(hints);
    Py_XDECREF(signature);
    Py_XDECREF(typing);
    Py_XDECREF(inspect);
    return resolved;
}

static int Endpoint_traverse(Endpoint* self, visitproc visit, void* arg) {
    Py_VISIT(self->server);
    Py_VISIT(self->handler);
    for (size_t index = 0; index != self->parameters_count; ++index) Py_VISIT(self->parameters[index].default_value);
    return 0;
}

static int Endpoint_clear(Endpoint* self) {
    Py_CLEAR(self->server);
    Py_CLEAR(self->handler);
    for (size_t index = 0; index != self->parameters_count; ++index) Py_CLEAR(self->parameters[index].default_value);
    return 0;
}

static void Endpoint_dealloc(Endpoint* self) {
    PyObject_GC_UnTrack(self);
    Endpoint_clear(self);
    Py_CLEAR(self->keywords);
    Py_CLEAR(self->names);
    PyObject_GC_Del(self);
}

PyTypeObject EndpointType = {
    PyVarObject_HEAD_INIT(NULL, 0).tp_name = "ucall.Endpoint",
    .tp_basicsize = sizeof(Endpoint),
    .tp_flags = Py_TPFLAGS_DEFAULT | Py_TPFLAGS_HAVE_GC,
    .tp_doc = "One plain route: its handler and the parameters it binds from each request.",
    .tp_traverse = (traverseproc)Endpoint_traverse,
    .tp_clear = (inquiry)Endpoint_clear,
    .tp_dealloc = (destructor)Endpoint_dealloc,
};

#pragma endregion Typed Handlers

#pragma region Batch Endpoints

typedef struct BatchEndpoint {
    PyObject ob_base;

    /** The endpoint the draining verbs address. */
    ucall_http_batch_endpoint_t handle;

    /** The server that registered it, NULL once a collection cleared it. */
    Server* server;

    /** The function handed each batch as a list of requests. */
    PyObject* handler;
} BatchEndpoint;

/** Runs a batch endpoint's Python handler on the draining thread with a list of its requests. */
static void call_batch_endpoint(ucall_received_http_request_t const* handles, size_t count, void* context) {
    PyGILState_STATE const state = PyGILState_Ensure();
    BatchEndpoint* const endpoint = (BatchEndpoint*)context;
    PyObject* const held = PyTuple_New((Py_ssize_t)count);
    size_t created = 0;
    for (; held && created != count; ++created) {
        PyObject* const request = request_new(endpoint->server, handles[created]);
        if (!request) break;
        PyTuple_SET_ITEM(held, (Py_ssize_t)created, request);
    }
    PyObject* const requests = held && created == count ? PySequence_List(held) : NULL;
    PyObject* const result = requests ? PyObject_CallOneArg(endpoint->handler, requests) : NULL;
    if (!result) {
        ucall_py_report_handler_failure(endpoint->handler);
        for (size_t index = 0; index != created; ++index)
            request_fail((Request*)PyTuple_GET_ITEM(held, (Py_ssize_t)index), ucall_http_status_internal_error_k,
                         reply_failed_k);
        for (size_t index = created; index != count; ++index)
            reply_failure(endpoint->server->handle, handles[index], ucall_http_status_service_unavailable_k,
                          reply_failed_k, strlen(reply_failed_k));
    }
    Py_XDECREF(result);
    Py_XDECREF(requests);
    Py_XDECREF(held);
    PyGILState_Release(state);
}

static int BatchEndpoint_traverse(BatchEndpoint* self, visitproc visit, void* arg) {
    Py_VISIT(self->server);
    Py_VISIT(self->handler);
    return 0;
}

static int BatchEndpoint_clear(BatchEndpoint* self) {
    Py_CLEAR(self->server);
    Py_CLEAR(self->handler);
    return 0;
}

static void BatchEndpoint_dealloc(BatchEndpoint* self) {
    PyObject_GC_UnTrack(self);
    BatchEndpoint_clear(self);
    PyObject_GC_Del(self);
}

static int batch_endpoint_live(BatchEndpoint* self) {
    if (self->server) return 0;
    ucall_py_raise_status(ucall_status_uninitialized_k, "the server was released");
    return -1;
}

static char const doc_BatchEndpoint_take_batch[] =                                               //
    "take_batch(timeout_us=0) -> None\n"                                                         //
    "\n"                                                                                         //
    "Runs the handler on this thread if a batch is due, waiting for one at most `timeout_us`.\n" //
    "\n"                                                                                         //
    "Each batch endpoint has one draining owner, and the wait polls no event loop.\n"            //
    "\n"                                                                                         //
    "Args:\n"                                                                                    //
    "  timeout_us (int, optional): The longest wait in microseconds; 0 checks once.\n"           //
    "\n"                                                                                         //
    "Raises:\n"                                                                                  //
    "  Error: The server failed, or was released.\n"                                             //
    "\n"                                                                                         //
    "Example:\n"                                                                                 //
    "  >>> endpoint.take_batch(timeout_us=1_000)";

static PyObject* BatchEndpoint_take_batch(BatchEndpoint* self, PyObject* const* values, Py_ssize_t count,
                                          PyObject* names) {
    PyObject* timeout = NULL;
    ucall_py_argument_t const arguments[] = {{"timeout_us", &timeout}};
    if (ucall_py_parse_fast("take_batch", values, count, names, 0, 1, arguments, 1) != 0) return NULL;
    size_t microseconds = 0;
    if (ucall_py_size_from_object(timeout, "timeout_us", &microseconds) != 0 || batch_endpoint_live(self) != 0)
        return NULL;
    ucall_outcome_t outcome = {0};
    ucall_server_take_batch_t take = {self->server->handle, &outcome, self->handle, microseconds};
    Py_BEGIN_ALLOW_THREADS;
    ucall_server_take_batch(&take);
    Py_END_ALLOW_THREADS;
    if (ucall_py_raise_outcome(&outcome) != 0) return NULL;
    Py_RETURN_NONE;
}

static char const doc_BatchEndpoint_take_batches[] =                                     //
    "take_batches() -> None\n"                                                           //
    "\n"                                                                                 //
    "Runs every due batch on this thread, sleeping in between, until `Server.stop()`.\n" //
    "\n"                                                                                 //
    "Requests still queued at the stop are released without a call to the handler.\n"    //
    "\n"                                                                                 //
    "Raises:\n"                                                                          //
    "  Error: The server failed, or was released.\n"                                     //
    "\n"                                                                                 //
    "Example:\n"                                                                         //
    "  >>> drainer = threading.Thread(target=endpoint.take_batches)\n"                   //
    "  >>> drainer.start()";

static PyObject* BatchEndpoint_take_batches(BatchEndpoint* self, PyObject* unused) {
    (void)unused;
    if (batch_endpoint_live(self) != 0) return NULL;
    ucall_outcome_t outcome = {0};
    ucall_server_take_batches_t take = {self->server->handle, &outcome, self->handle};
    Py_BEGIN_ALLOW_THREADS;
    ucall_server_take_batches(&take);
    Py_END_ALLOW_THREADS;
    if (ucall_py_raise_outcome(&outcome) != 0) return NULL;
    Py_RETURN_NONE;
}

static char const doc_BatchEndpoint_statistics[] =                                                 //
    "statistics() -> dict[str, int]\n"                                                             //
    "\n"                                                                                           //
    "Counts the batches the endpoint handed out since registration, and why each fired.\n"         //
    "\n"                                                                                           //
    "Each counter is read on its own, so a snapshot of an endpoint being drained is not one\n"     //
    "instant, and batches a stop released count nowhere.\n"                                        //
    "\n"                                                                                           //
    "Returns:\n"                                                                                   //
    "  dict[str, int]: `batches` handed to the handler and the `requests` in them, then the\n"     //
    "    `filled_batches` that reached `max_size`, the `ready_batches` that reached `min_size`,\n" //
    "    and the `expired_batches` that waited out `max_latency_us`.\n"                            //
    "\n"                                                                                           //
    "Example:\n"                                                                                   //
    "  >>> counters = endpoint.statistics()\n"                                                     //
    "  >>> counters[\"requests\"] / max(counters[\"batches\"], 1)\n"                               //
    "  0.0";

static PyObject* BatchEndpoint_statistics(BatchEndpoint* self, PyObject* unused) {
    (void)unused;
    if (batch_endpoint_live(self) != 0) return NULL;
    ucall_outcome_t outcome = {0};
    ucall_batch_endpoint_statistics_t counters = {0};
    ucall_server_batch_endpoint_statistics_t query = {self->server->handle, &outcome, self->handle, &counters};
    ucall_server_batch_endpoint_statistics(&query);
    if (ucall_py_raise_outcome(&outcome) != 0) return NULL;
    return Py_BuildValue("{sKsKsKsKsK}",                                                //
                         "batches", (unsigned long long)counters.batches,               //
                         "requests", (unsigned long long)counters.requests,             //
                         "filled_batches", (unsigned long long)counters.filled_batches, //
                         "ready_batches", (unsigned long long)counters.ready_batches,   //
                         "expired_batches", (unsigned long long)counters.expired_batches);
}

static PyMethodDef BatchEndpoint_methods[] = {
    {"take_batch", (PyCFunction)(void (*)(void))BatchEndpoint_take_batch, ucall_py_method_flags_k,
     doc_BatchEndpoint_take_batch},
    {"take_batches", (PyCFunction)BatchEndpoint_take_batches, METH_NOARGS, doc_BatchEndpoint_take_batches},
    {"statistics", (PyCFunction)BatchEndpoint_statistics, METH_NOARGS, doc_BatchEndpoint_statistics},
    {NULL, NULL, 0, NULL},
};

static PyGetSetDef BatchEndpoint_getset[] = {
    {"handler", ucall_py_get_optional, NULL, "The function handed each batch.",
     (void*)offsetof(BatchEndpoint, handler)},
    {NULL, NULL, NULL, NULL, NULL},
};

static char const doc_BatchEndpoint[] =                                                            //
    "One batching route of a server, drained by one application thread.\n"                         //
    "\n"                                                                                           //
    "Requests matching it from every event loop share one queue, which `take_batch` and\n"         //
    "`take_batches` hand to the handler as a list once enough arrived or the oldest waited long\n" //
    "enough. The handler runs on the draining thread and replies to each request, in any order.\n" //
    "\n"                                                                                           //
    "Example:\n"                                                                                   //
    "  >>> @server.batch(\"/infer\", min_size=8, max_size=64, max_latency_us=500)\n"               //
    "  ... def infer(requests: list[ucall.Request]):\n"                                            //
    "  ...     for request in requests:\n"                                                         //
    "  ...         request.reply(bytes(request.body))\n"                                           //
    "  >>> infer in server.batch_endpoints\n"                                                      //
    "  True";

PyTypeObject BatchEndpointType = {
    PyVarObject_HEAD_INIT(NULL, 0).tp_name = "ucall.BatchEndpoint",
    .tp_basicsize = sizeof(BatchEndpoint),
    .tp_flags = Py_TPFLAGS_DEFAULT | Py_TPFLAGS_HAVE_GC,
    .tp_doc = doc_BatchEndpoint,
    .tp_traverse = (traverseproc)BatchEndpoint_traverse,
    .tp_clear = (inquiry)BatchEndpoint_clear,
    .tp_dealloc = (destructor)BatchEndpoint_dealloc,
    .tp_methods = BatchEndpoint_methods,
    .tp_getset = BatchEndpoint_getset,
};

#pragma endregion Batch Endpoints

#pragma region Server

static char const doc_Server[] =                                                                     //
    "Server(*interfaces, backend=Backend.AUTOMATIC, cpu_class=CPUClass.AUTOMATIC)\n"                 //
    "\n"                                                                                             //
    "An HTTP server over one or more interfaces, polled by threads the application starts.\n"        //
    "\n"                                                                                             //
    "It starts no threads: each event loop needs one owner calling `take_calls`, and each batch\n"   //
    "endpoint one calling `BatchEndpoint.take_batches`, while `run` serves the simplest server on\n" //
    "the calling thread. Register every endpoint before the first poll.\n"                           //
    "\n"                                                                                             //
    "Args:\n"                                                                                        //
    "  *interfaces (Interface): Where to answer; none answers on `DEFAULT_ADDRESS`.\n"               //
    "  backend (Backend, optional): The I/O implementation. Defaults to `Backend.AUTOMATIC`.\n"      //
    "  cpu_class (CPUClass, optional): The CPU kernels. Defaults to `CPUClass.AUTOMATIC`.\n"         //
    "\n"                                                                                             //
    "Raises:\n"                                                                                      //
    "  Error: An interface that cannot be bound, such as an address in use.\n"                       //
    "\n"                                                                                             //
    "Example:\n"                                                                                     //
    "  >>> server = ucall.Server(ucall.Interface(\"127.0.0.1:0\"), backend=\"posix\")\n"             //
    "  >>> server.event_loops, server.backend\n"                                                     //
    "  (1, <Backend.POSIX: 1>)";

/** The interfaces a server answers on: the positional @c Interface objects, or the default one. */
static PyObject* server_interfaces(PyObject* positional) {
    Py_ssize_t const count = PyTuple_GET_SIZE(positional);
    for (Py_ssize_t index = 0; index != count; ++index)
        if (!PyObject_TypeCheck(PyTuple_GET_ITEM(positional, index), &InterfaceType))
            return PyErr_Format(PyExc_TypeError, "Server() takes ucall.Interface arguments, got %s",
                                Py_TYPE(PyTuple_GET_ITEM(positional, index))->tp_name);
    if (count) return Py_NewRef(positional);
    PyObject* const address = PyUnicode_FromString(ucall_py_default_address_k);
    PyObject* const fallback = address ? PyObject_CallOneArg((PyObject*)&InterfaceType, address) : NULL;
    PyObject* const interfaces = fallback ? PyTuple_Pack(1, fallback) : NULL;
    Py_XDECREF(fallback);
    Py_XDECREF(address);
    return interfaces;
}

static PyObject* Server_new(PyTypeObject* type, PyObject* positional, PyObject* keywords) {
    PyObject *backend = NULL, *cpu_class = NULL;
    ucall_py_argument_t const arguments[] = {{"backend", &backend}, {"cpu_class", &cpu_class}};
    if (ucall_py_parse_tuple("Server", NULL, keywords, 0, 0, arguments, sizeof(arguments) / sizeof(arguments[0])) != 0)
        return NULL;
    ucall_server_config_t config = {0};
    int backend_value = ucall_io_backend_automatic_k, cpu_class_value = ucall_cpu_class_unknown_k;
    if (ucall_py_enum_from_object(backend, "backend", &ucall_py_backend_enum, &backend_value) != 0 ||
        ucall_py_enum_from_object(cpu_class, "cpu_class", &ucall_py_cpu_class_enum, &cpu_class_value) != 0)
        return NULL;
    config.backend = (ucall_io_backend_t)backend_value;
    config.cpu_class = (ucall_cpu_class_t)cpu_class_value;

    PyObject* const interfaces = server_interfaces(positional);
    if (!interfaces) return NULL;
    Py_ssize_t const interfaces_count = PyTuple_GET_SIZE(interfaces);
    ucall_network_interface_t* const network_interfaces = PyMem_Calloc((size_t)interfaces_count,
                                                                       sizeof(ucall_network_interface_t));
    ucall_noise_key_t* const keys = PyMem_Calloc((size_t)interfaces_count, sizeof(ucall_noise_key_t));
    Server* const self = network_interfaces && keys ? (Server*)type->tp_alloc(type, 0) : NULL;
    if (!self) {
        if (!PyErr_Occurred()) PyErr_NoMemory();
        PyMem_Free(network_interfaces);
        PyMem_Free(keys);
        Py_DECREF(interfaces);
        return NULL;
    }
    self->interfaces = interfaces;
    self->stage = server_serving_k;
    int filled = 0;
    for (Py_ssize_t index = 0; filled == 0 && index != interfaces_count; ++index) {
        Interface const* const source = (Interface const*)PyTuple_GET_ITEM(interfaces, index);
        ucall_network_interface_t* const target = &network_interfaces[index];
        target->address = PyUnicode_AsUTF8(source->address);
        target->device_name = source->device_name ? PyUnicode_AsUTF8(source->device_name) : NULL;
        if (!target->address || (source->device_name && !target->device_name)) filled = -1;
        target->security_mode = source->security;
        if (source->private_key) {
            memcpy(keys[index], PyBytes_AS_STRING(source->private_key), sizeof(ucall_noise_key_t));
            target->noise_private_key = (ucall_noise_key_t const*)&keys[index];
        }
        if (source->peer_authorizer) {
            target->peer_authorizer = ucall_py_authorize_peer;
            target->peer_authorizer_context = source->peer_authorizer;
        }
        target->event_loops = (size_t)source->event_loops;
        target->max_concurrent_connections = (size_t)source->connections;
        target->max_pipelined_requests = (size_t)source->pipelined_requests;
    }
    config.interfaces = network_interfaces;
    config.interfaces_count = (size_t)interfaces_count;
    self->endpoints = filled == 0 ? PyList_New(0) : NULL;
    ucall_outcome_t outcome = {0};
    ucall_server_init_t init = {&self->handle, &outcome, &config, &self->resolved};
    if (self->endpoints) ucall_server_init(&init);
    memset(keys, 0, (size_t)interfaces_count * sizeof(ucall_noise_key_t));
    PyMem_Free(network_interfaces);
    PyMem_Free(keys);
    if (!self->endpoints || ucall_py_raise_outcome(&outcome) != 0) {
        Py_DECREF(self);
        return NULL;
    }
    for (size_t index = 0; index != self->resolved.interfaces_count; ++index)
        if (self->resolved.interfaces[index].event_loops > self->event_loops)
            self->event_loops = self->resolved.interfaces[index].event_loops;
    return (PyObject*)self;
}

static int Server_traverse(Server* self, visitproc visit, void* arg) {
    Py_VISIT(self->interfaces);
    Py_VISIT(self->endpoints);
    return 0;
}

static int Server_clear(Server* self) {
    Py_CLEAR(self->endpoints);
    Py_CLEAR(self->interfaces);
    return 0;
}

static void Server_dealloc(Server* self) {
    PyObject_GC_UnTrack(self);
    // Every polling caller holds a reference, so none is inside the server when the last one goes.
    ucall_server_t const handle = self->handle;
    self->handle = NULL;
    if (handle) {
        Py_BEGIN_ALLOW_THREADS;
        ucall_server_stop(handle);
        ucall_server_free(handle);
        Py_END_ALLOW_THREADS;
    }
    Server_clear(self);
    Py_TYPE(self)->tp_free((PyObject*)self);
}

static char const doc_Server_add_endpoint[] =                                                          //
    "add_endpoint(path, verb, handler, /) -> Callable\n"                                               //
    "\n"                                                                                               //
    "Routes `verb` requests matching the URI template `path` to `handler`, on the polling thread.\n"   //
    "\n"                                                                                               //
    "A handler taking one parameter annotated `Request` receives the request, which it may answer\n"   //
    "later from any thread, and what it returns other than None is the reply. Any other handler's\n"   //
    "parameters, annotated `str`, `int`, `float`, `bool` or `bytes` or left bare, bind by name from\n" //
    "a path placeholder, then the query, then a JSON object body, then their defaults; a missing\n"    //
    "or malformed value answers 400, and None returned answers 204. Returned bytes-like objects\n"     //
    "reply as binary, `str` as UTF-8 text, and anything else as JSON. An exception answers 500.\n"     //
    "\n"                                                                                               //
    "Args:\n"                                                                                          //
    "  path (str): A URI template such as \"/users/{name}\" or \"/files/{*path}\".\n"                  //
    "  verb (Verb): The method to answer; `Verb.ANY` answers every one.\n"                             //
    "  handler (Callable): The function to route to.\n"                                                //
    "\n"                                                                                               //
    "Returns:\n"                                                                                       //
    "  Callable: `handler` itself.\n"                                                                  //
    "\n"                                                                                               //
    "Raises:\n"                                                                                        //
    "  TypeError: A parameter that cannot bind, such as `*args` or one annotated `list`.\n"            //
    "  Error: A duplicate route or an invalid template.\n"                                             //
    "\n"                                                                                               //
    "Example:\n"                                                                                       //
    "  >>> def scale(value: float, factor: float = 2.0):\n"                                            //
    "  ...     return value * factor\n"                                                                //
    "  >>> server.add_endpoint(\"/scale/{value}\", ucall.Verb.GET, scale) is scale\n"                  //
    "  True";

static PyObject* Server_add_endpoint(Server* self, PyObject* const* values, Py_ssize_t count, PyObject* names) {
    PyObject *path = NULL, *verb = NULL, *handler = NULL;
    ucall_py_argument_t const arguments[] = {{"path", &path}, {"verb", &verb}, {"handler", &handler}};
    if (ucall_py_parse_fast("add_endpoint", values, count, names, 3, 3, arguments, 3) != 0) return NULL;
    ucall_bytes_view_t template_view;
    int verb_value = 0;
    if (ucall_py_text_from_object(path, "path", &template_view) != 0 ||
        ucall_py_enum_from_object(verb, "verb", &ucall_py_verb_enum, &verb_value) != 0)
        return NULL;
    if (!PyCallable_Check(handler))
        return PyErr_Format(PyExc_TypeError, "'handler' must be callable, got %s", Py_TYPE(handler)->tp_name);
    Endpoint* const endpoint = PyObject_GC_New(Endpoint, &EndpointType);
    if (!endpoint) return NULL;
    memset((char*)endpoint + sizeof(PyObject), 0, sizeof(Endpoint) - sizeof(PyObject));
    endpoint->server = (Server*)Py_NewRef(self);
    endpoint->handler = Py_NewRef(handler);
    PyObject_GC_Track(endpoint);
    ucall_received_http_request_callback_t callback = NULL;
    if (endpoint_resolve(endpoint, template_view, &callback) != 0) {
        Py_DECREF(endpoint);
        return NULL;
    }
    ucall_outcome_t outcome = {0};
    ucall_server_add_http_endpoint_t add = {
        self->handle, &outcome, template_view, (ucall_verb_t)verb_value, callback, endpoint,
    };
    ucall_server_add_http_endpoint(&add);
    int const added = ucall_py_raise_outcome(&outcome) == 0 && PyList_Append(self->endpoints, (PyObject*)endpoint) == 0;
    Py_DECREF(endpoint);
    return added ? Py_NewRef(handler) : NULL;
}

static char const doc_Server_add_batch_endpoint[] =                                                  //
    "add_batch_endpoint(path, verb, handler, /, min_size=0, max_size=0, max_latency_us=0)\n"         //
    "    -> BatchEndpoint\n"                                                                         //
    "\n"                                                                                             //
    "Queues matching requests from every event loop for `handler(requests)`, called in batches.\n"   //
    "\n"                                                                                             //
    "A batch is due once `min_size` requests arrived, `max_size` are queued, or the oldest waited\n" //
    "`max_latency_us`. The handler runs on the thread draining the returned endpoint and replies\n"  //
    "to each request.\n"                                                                             //
    "\n"                                                                                             //
    "Args:\n"                                                                                        //
    "  path (str): A URI template such as \"/infer\".\n"                                             //
    "  verb (Verb): The method to answer; `Verb.ANY` answers every one.\n"                           //
    "  handler (Callable[[list[Request]], object]): The function handed each batch.\n"               //
    "  min_size (int, optional): Requests that make a batch due at once; 0 means 1.\n"               //
    "  max_size (int, optional): Requests one batch holds at most; 0 means 32.\n"                    //
    "  max_latency_us (int, optional): The longest the oldest request waits for a batch to\n"        //
    "    fill, in microseconds; 0 means 10 ms.\n"                                                    //
    "\n"                                                                                             //
    "Returns:\n"                                                                                     //
    "  BatchEndpoint: The endpoint to drain.\n"                                                      //
    "\n"                                                                                             //
    "Raises:\n"                                                                                      //
    "  Error: A duplicate route or an invalid template.\n"                                           //
    "\n"                                                                                             //
    "Example:\n"                                                                                     //
    "  >>> endpoint = server.add_batch_endpoint(\"/sizes\", \"POST\", lambda requests: None, 4)\n"   //
    "  >>> endpoint in server.batch_endpoints\n"                                                     //
    "  True";

static PyObject* Server_add_batch_endpoint(Server* self, PyObject* const* values, Py_ssize_t count, PyObject* names) {
    PyObject *path = NULL, *verb = NULL, *handler = NULL, *min_size = NULL, *max_size = NULL, *max_latency = NULL;
    ucall_py_argument_t const arguments[] = {{"path", &path},         {"verb", &verb},
                                             {"handler", &handler},   {"min_size", &min_size},
                                             {"max_size", &max_size}, {"max_latency_us", &max_latency}};
    if (ucall_py_parse_fast("add_batch_endpoint", values, count, names, 3, 6, arguments, 6) != 0) return NULL;
    ucall_bytes_view_t template_view;
    int verb_value = 0;
    size_t minimum = 0, maximum = 0, latency = 0;
    if (ucall_py_text_from_object(path, "path", &template_view) != 0 ||
        ucall_py_enum_from_object(verb, "verb", &ucall_py_verb_enum, &verb_value) != 0 ||
        ucall_py_size_from_object(min_size, "min_size", &minimum) != 0 ||
        ucall_py_size_from_object(max_size, "max_size", &maximum) != 0 ||
        ucall_py_size_from_object(max_latency, "max_latency_us", &latency) != 0)
        return NULL;
    if (!PyCallable_Check(handler))
        return PyErr_Format(PyExc_TypeError, "'handler' must be callable, got %s", Py_TYPE(handler)->tp_name);
    BatchEndpoint* const endpoint = PyObject_GC_New(BatchEndpoint, &BatchEndpointType);
    if (!endpoint) return NULL;
    endpoint->handle = NULL;
    endpoint->server = (Server*)Py_NewRef(self);
    endpoint->handler = Py_NewRef(handler);
    PyObject_GC_Track(endpoint);
    ucall_outcome_t outcome = {0};
    ucall_server_add_http_batch_endpoint_t add = {
        self->handle, &outcome, template_view, (ucall_verb_t)verb_value, call_batch_endpoint, endpoint,
        minimum,      maximum,  latency,       &endpoint->handle};
    ucall_server_add_http_batch_endpoint(&add);
    if (ucall_py_raise_outcome(&outcome) != 0 || PyList_Append(self->endpoints, (PyObject*)endpoint) != 0) {
        Py_DECREF(endpoint);
        return NULL;
    }
    return (PyObject*)endpoint;
}

/** A registration as a decorator: `functools.partial(self.<method>, path, verb, **keywords)`. */
static PyObject* registration_decorator(Server* self, char const* method, PyObject* path, PyObject* verb,
                                        PyObject* keywords) {
    PyObject* const functools = PyImport_ImportModule("functools");
    PyObject* const partial = functools ? PyObject_GetAttrString(functools, "partial") : NULL;
    PyObject* const bound = partial ? PyObject_GetAttrString((PyObject*)self, method) : NULL;
    PyObject* const arguments = bound ? PyTuple_Pack(3, bound, path, verb) : NULL;
    PyObject* const decorator = arguments ? PyObject_Call(partial, arguments, keywords) : NULL;
    Py_XDECREF(arguments);
    Py_XDECREF(bound);
    Py_XDECREF(partial);
    Py_XDECREF(functools);
    return decorator;
}

/** The decorator registering a typed or raw handler for @p verb at @p path, both checked first. */
static PyObject* server_route(Server* self, PyObject* path, PyObject* verb) {
    ucall_bytes_view_t template_view;
    int verb_value = 0;
    if (ucall_py_text_from_object(path, "path", &template_view) != 0 ||
        ucall_py_enum_from_object(verb, "verb", &ucall_py_verb_enum, &verb_value) != 0)
        return NULL;
    PyObject* const member = ucall_py_enum_to_object(&ucall_py_verb_enum, verb_value);
    PyObject* const decorator = member ? registration_decorator(self, "add_endpoint", path, member, NULL) : NULL;
    Py_XDECREF(member);
    return decorator;
}

/** The decorator for one fixed @p verb, as `get` and its siblings answer it. */
static PyObject* server_route_verb(Server* self, PyObject* path, ucall_verb_t verb) {
    PyObject* const member = ucall_py_enum_to_object(&ucall_py_verb_enum, verb);
    PyObject* const decorator = member ? server_route(self, path, member) : NULL;
    Py_XDECREF(member);
    return decorator;
}

static char const doc_Server_route[] =                                                           //
    "route(path, verb=Verb.GET) -> Callable[[F], F]\n"                                           //
    "\n"                                                                                         //
    "Registers the decorated function for `verb` requests matching the URI template `path`.\n"   //
    "\n"                                                                                         //
    "Args:\n"                                                                                    //
    "  path (str): A URI template such as \"/users/{name}\".\n"                                  //
    "  verb (Verb, optional): The method to answer. Defaults to `Verb.GET`.\n"                   //
    "\n"                                                                                         //
    "Returns:\n"                                                                                 //
    "  Callable[[F], F]: A decorator calling `add_endpoint` and returning the function as is.\n" //
    "\n"                                                                                         //
    "Example:\n"                                                                                 //
    "  >>> @server.route(\"/anything\", ucall.Verb.ANY)\n"                                       //
    "  ... def anything(request: ucall.Request):\n"                                              //
    "  ...     return request.verb.name";

static PyObject* Server_route(Server* self, PyObject* const* values, Py_ssize_t count, PyObject* names) {
    PyObject *path = NULL, *verb = NULL;
    ucall_py_argument_t const arguments[] = {{"path", &path}, {"verb", &verb}};
    if (ucall_py_parse_fast("route", values, count, names, 1, 2, arguments, 2) != 0) return NULL;
    if (verb) return server_route(self, path, verb);
    return server_route_verb(self, path, ucall_verb_get_k);
}

static char const doc_Server_get[] =                                                             //
    "get(path, /) -> Callable[[F], F]\n"                                                         //
    "\n"                                                                                         //
    "Registers the decorated function for GET requests matching the URI template `path`.\n"      //
    "\n"                                                                                         //
    "Args:\n"                                                                                    //
    "  path (str): A URI template such as \"/users/{name}\".\n"                                  //
    "\n"                                                                                         //
    "Returns:\n"                                                                                 //
    "  Callable[[F], F]: A decorator calling `add_endpoint` and returning the function as is.\n" //
    "\n"                                                                                         //
    "Example:\n"                                                                                 //
    "  >>> @server.get(\"/users/{name}\")\n"                                                     //
    "  ... def user(name: str, verbose: bool = False):\n"                                        //
    "  ...     return {\"name\": name, \"verbose\": verbose}";

static PyObject* Server_get(Server* self, PyObject* path) { return server_route_verb(self, path, ucall_verb_get_k); }

static char const doc_Server_post[] =                                                            //
    "post(path, /) -> Callable[[F], F]\n"                                                        //
    "\n"                                                                                         //
    "Registers the decorated function for POST requests matching the URI template `path`.\n"     //
    "\n"                                                                                         //
    "Args:\n"                                                                                    //
    "  path (str): A URI template such as \"/sum\".\n"                                           //
    "\n"                                                                                         //
    "Returns:\n"                                                                                 //
    "  Callable[[F], F]: A decorator calling `add_endpoint` and returning the function as is.\n" //
    "\n"                                                                                         //
    "Example:\n"                                                                                 //
    "  >>> @server.post(\"/sum\")\n"                                                             //
    "  ... def sum(a: int, b: float = 0.5):\n"                                                   //
    "  ...     return a + b";

static PyObject* Server_post(Server* self, PyObject* path) { return server_route_verb(self, path, ucall_verb_post_k); }

static char const doc_Server_put[] =                                                             //
    "put(path, /) -> Callable[[F], F]\n"                                                         //
    "\n"                                                                                         //
    "Registers the decorated function for PUT requests matching the URI template `path`.\n"      //
    "\n"                                                                                         //
    "Args:\n"                                                                                    //
    "  path (str): A URI template such as \"/files/{*path}\".\n"                                 //
    "\n"                                                                                         //
    "Returns:\n"                                                                                 //
    "  Callable[[F], F]: A decorator calling `add_endpoint` and returning the function as is.\n" //
    "\n"                                                                                         //
    "Example:\n"                                                                                 //
    "  >>> @server.put(\"/files/{*path}\")\n"                                                    //
    "  ... def store(request: ucall.Request):\n"                                                 //
    "  ...     return len(request.body)";

static PyObject* Server_put(Server* self, PyObject* path) { return server_route_verb(self, path, ucall_verb_put_k); }

static char const doc_Server_delete[] =                                                          //
    "delete(path, /) -> Callable[[F], F]\n"                                                      //
    "\n"                                                                                         //
    "Registers the decorated function for DELETE requests matching the URI template `path`.\n"   //
    "\n"                                                                                         //
    "Args:\n"                                                                                    //
    "  path (str): A URI template such as \"/files/{*path}\".\n"                                 //
    "\n"                                                                                         //
    "Returns:\n"                                                                                 //
    "  Callable[[F], F]: A decorator calling `add_endpoint` and returning the function as is.\n" //
    "\n"                                                                                         //
    "Example:\n"                                                                                 //
    "  >>> @server.delete(\"/files/{*path}\")\n"                                                 //
    "  ... def remove(path: str):\n"                                                             //
    "  ...     return None";

static PyObject* Server_delete(Server* self, PyObject* path) {
    return server_route_verb(self, path, ucall_verb_delete_k);
}

static char const doc_Server_patch[] =                                                           //
    "patch(path, /) -> Callable[[F], F]\n"                                                       //
    "\n"                                                                                         //
    "Registers the decorated function for PATCH requests matching the URI template `path`.\n"    //
    "\n"                                                                                         //
    "Args:\n"                                                                                    //
    "  path (str): A URI template such as \"/users/{name}\".\n"                                  //
    "\n"                                                                                         //
    "Returns:\n"                                                                                 //
    "  Callable[[F], F]: A decorator calling `add_endpoint` and returning the function as is.\n" //
    "\n"                                                                                         //
    "Example:\n"                                                                                 //
    "  >>> @server.patch(\"/users/{name}\")\n"                                                   //
    "  ... def rename(name: str, alias: str):\n"                                                 //
    "  ...     return f\"{name} is {alias}\"";

static PyObject* Server_patch(Server* self, PyObject* path) {
    return server_route_verb(self, path, ucall_verb_patch_k);
}

static char const doc_Server_batch[] =                                                           //
    "batch(path, verb=Verb.POST, *, min_size=0, max_size=0, max_latency_us=0)\n"                 //
    "    -> Callable[[Callable[[list[Request]], object]], BatchEndpoint]\n"                      //
    "\n"                                                                                         //
    "Registers the decorated `handler(requests)` as a batch endpoint, replacing it with that.\n" //
    "\n"                                                                                         //
    "Args:\n"                                                                                    //
    "  path (str): A URI template such as \"/infer\".\n"                                         //
    "  verb (Verb, optional): The method to answer. Defaults to `Verb.POST`.\n"                  //
    "  min_size (int, optional): Requests that make a batch due at once; 0 means 1.\n"           //
    "  max_size (int, optional): Requests one batch holds at most; 0 means 32.\n"                //
    "  max_latency_us (int, optional): The longest the oldest request waits, in microseconds;\n" //
    "    0 means 10 ms.\n"                                                                       //
    "\n"                                                                                         //
    "Returns:\n"                                                                                 //
    "  Callable: A decorator calling `add_batch_endpoint` and returning its `BatchEndpoint`.\n"  //
    "\n"                                                                                         //
    "Example:\n"                                                                                 //
    "  >>> @server.batch(\"/reverse\", min_size=4, max_size=4)\n"                                //
    "  ... def reverse(requests: list[ucall.Request]):\n"                                        //
    "  ...     for request in reversed(requests):\n"                                             //
    "  ...         request.reply(request.body)\n"                                                //
    "  >>> type(reverse).__name__\n"                                                             //
    "  'BatchEndpoint'";

static PyObject* Server_batch(Server* self, PyObject* const* values, Py_ssize_t count, PyObject* names) {
    PyObject *path = NULL, *verb = NULL, *min_size = NULL, *max_size = NULL, *max_latency = NULL;
    ucall_py_argument_t const arguments[] = {{"path", &path},
                                             {"verb", &verb},
                                             {"min_size", &min_size},
                                             {"max_size", &max_size},
                                             {"max_latency_us", &max_latency}};
    if (ucall_py_parse_fast("batch", values, count, names, 1, 2, arguments, 5) != 0) return NULL;
    ucall_bytes_view_t template_view;
    int verb_value = ucall_verb_post_k;
    if (ucall_py_text_from_object(path, "path", &template_view) != 0 ||
        ucall_py_enum_from_object(verb, "verb", &ucall_py_verb_enum, &verb_value) != 0)
        return NULL;
    PyObject* const member = ucall_py_enum_to_object(&ucall_py_verb_enum, verb_value);
    PyObject* keywords = member ? PyDict_New() : NULL;
    for (size_t index = 2; keywords && index != 5; ++index)
        if (*arguments[index].value &&
            PyDict_SetItemString(keywords, arguments[index].name, *arguments[index].value) != 0)
            Py_CLEAR(keywords);
    PyObject* const decorator = keywords ? registration_decorator(self, "add_batch_endpoint", path, member, keywords)
                                         : NULL;
    Py_XDECREF(keywords);
    Py_XDECREF(member);
    return decorator;
}

static size_t event_loop_index(PyObject* object, int* failed) {
    size_t index = 0;
    *failed = ucall_py_size_from_object(object, "event_loop", &index);
    return index;
}

static char const doc_Server_take_call[] =                                                      //
    "take_call(event_loop=0, timeout_us=0) -> None\n"                                           //
    "\n"                                                                                        //
    "Advances one event loop and runs its ready handlers on this thread.\n"                     //
    "\n"                                                                                        //
    "Each loop has one polling owner, and handlers run inside the call, so a slow one delays\n" //
    "its return past `timeout_us`.\n"                                                           //
    "\n"                                                                                        //
    "Args:\n"                                                                                   //
    "  event_loop (int, optional): The loop to advance, below `event_loops`. Defaults to 0.\n"  //
    "  timeout_us (int, optional): The longest wait for I/O in microseconds; 0 polls once.\n"   //
    "\n"                                                                                        //
    "Raises:\n"                                                                                 //
    "  Error: An `event_loop` past the last one, or an I/O failure.\n"                          //
    "\n"                                                                                        //
    "Example:\n"                                                                                //
    "  >>> server.take_call(0, timeout_us=1_000)";

static PyObject* Server_take_call(Server* self, PyObject* const* values, Py_ssize_t count, PyObject* names) {
    PyObject *loop = NULL, *timeout = NULL;
    ucall_py_argument_t const arguments[] = {{"event_loop", &loop}, {"timeout_us", &timeout}};
    if (ucall_py_parse_fast("take_call", values, count, names, 0, 2, arguments, 2) != 0) return NULL;
    int failed = 0;
    size_t microseconds = 0;
    size_t const index = event_loop_index(loop, &failed);
    if (failed || ucall_py_size_from_object(timeout, "timeout_us", &microseconds) != 0) return NULL;
    ucall_outcome_t outcome = {0};
    ucall_server_take_call_t take = {self->handle, &outcome, index, microseconds};
    Py_BEGIN_ALLOW_THREADS;
    ucall_server_take_call(&take);
    Py_END_ALLOW_THREADS;
    if (ucall_py_raise_outcome(&outcome) != 0) return NULL;
    Py_RETURN_NONE;
}

static char const doc_Server_take_calls[] =                                                    //
    "take_calls(event_loop=0) -> None\n"                                                       //
    "\n"                                                                                       //
    "Drives one event loop on this thread until `stop()` or an I/O failure.\n"                 //
    "\n"                                                                                       //
    "The interpreter lock is released meanwhile and taken back only to run handlers, so one\n" //
    "thread per loop serves in parallel with the others. Signals reach Python only once it\n"  //
    "returns, so call it from threads other than the main one.\n"                              //
    "\n"                                                                                       //
    "Args:\n"                                                                                  //
    "  event_loop (int, optional): The loop to drive, below `event_loops`. Defaults to 0.\n"   //
    "\n"                                                                                       //
    "Raises:\n"                                                                                //
    "  Error: An `event_loop` past the last one, or an I/O failure.\n"                         //
    "\n"                                                                                       //
    "Example:\n"                                                                               //
    "  >>> pollers = [threading.Thread(target=server.take_calls, args=(loop,))\n"              //
    "  ...            for loop in range(server.event_loops)]";

static PyObject* Server_take_calls(Server* self, PyObject* const* values, Py_ssize_t count, PyObject* names) {
    PyObject* loop = NULL;
    ucall_py_argument_t const arguments[] = {{"event_loop", &loop}};
    if (ucall_py_parse_fast("take_calls", values, count, names, 0, 1, arguments, 1) != 0) return NULL;
    int failed = 0;
    size_t const index = event_loop_index(loop, &failed);
    if (failed) return NULL;
    ucall_outcome_t outcome = {0};
    ucall_server_take_calls_t take = {self->handle, &outcome, index};
    Py_BEGIN_ALLOW_THREADS;
    ucall_server_take_calls(&take);
    Py_END_ALLOW_THREADS;
    if (ucall_py_raise_outcome(&outcome) != 0) return NULL;
    Py_RETURN_NONE;
}

static Py_ssize_t server_batch_endpoints_count(Server* self) {
    Py_ssize_t const count = self->endpoints ? PyList_GET_SIZE(self->endpoints) : 0;
    Py_ssize_t batches = 0;
    for (Py_ssize_t index = 0; index != count; ++index)
        batches += Py_IS_TYPE(PyList_GET_ITEM(self->endpoints, index), &BatchEndpointType);
    return batches;
}

static char const doc_Server_run[] =                                                               //
    "run() -> None\n"                                                                              //
    "\n"                                                                                           //
    "Serves a server of one event loop and no batch endpoints on the calling thread.\n"            //
    "\n"                                                                                           //
    "It returns after `stop()` or `KeyboardInterrupt`, polling in slices of 100 ms and checking\n" //
    "for signals between them, and once stopped it lets the loop finish the requests in flight.\n" //
    "\n"                                                                                           //
    "Raises:\n"                                                                                    //
    "  RuntimeError: The server has more than one event loop or any batch endpoint.\n"             //
    "  KeyboardInterrupt: Ctrl+C arrived while serving.\n"                                         //
    "  Error: An I/O failure.\n"                                                                   //
    "\n"                                                                                           //
    "Example:\n"                                                                                   //
    "  >>> runner = threading.Thread(target=server.run)\n"                                         //
    "  >>> runner.start()\n"                                                                       //
    "  >>> server.stop()\n"                                                                        //
    "  >>> runner.join()";

static PyObject* Server_run(Server* self, PyObject* unused) {
    (void)unused;
    Py_ssize_t const batches = server_batch_endpoints_count(self);
    if (self->event_loops != 1 || batches)
        return PyErr_Format(PyExc_RuntimeError,
                            "Server.run() polls one event loop on the calling thread, and this server has %zu event "
                            "loops and %zd batch endpoints, so poll each loop with take_calls and drain each batch "
                            "endpoint with take_batches on threads of your own.",
                            self->event_loops, batches);
    ucall_outcome_t outcome = {0};
    int failed = 0;
    while (!failed && self->stage == server_serving_k) {
        ucall_server_take_call_t take = {self->handle, &outcome, 0, ucall_py_interrupt_period_us_k};
        Py_BEGIN_ALLOW_THREADS;
        ucall_server_take_call(&take);
        Py_END_ALLOW_THREADS;
        failed = ucall_py_raise_outcome(&outcome) != 0 || PyErr_CheckSignals() != 0;
    }
    // Handlers draining below run on this thread, so the exception that ended serving waits aside.
    PyObject* const interrupted = PyErr_GetRaisedException();
    self->stage = server_stopping_k;
    ucall_server_stop(self->handle);
    ucall_outcome_t drained = {0};
    ucall_server_take_calls_t take = {self->handle, &drained, 0};
    Py_BEGIN_ALLOW_THREADS;
    ucall_server_take_calls(&take);
    Py_END_ALLOW_THREADS;
    if (interrupted) {
        PyErr_SetRaisedException(interrupted);
        return NULL;
    }
    if (ucall_py_raise_outcome(&drained) != 0) return NULL;
    Py_RETURN_NONE;
}

static char const doc_Server_stop[] =                                                      //
    "stop() -> None\n"                                                                     //
    "\n"                                                                                   //
    "Asks the server to stop, waking every polling and draining caller to return.\n"       //
    "\n"                                                                                   //
    "Safe from any thread and from a handler. Join the polling threads before releasing\n" //
    "the server.\n"                                                                        //
    "\n"                                                                                   //
    "Example:\n"                                                                           //
    "  >>> server.stop()";

static PyObject* Server_stop(Server* self, PyObject* unused) {
    (void)unused;
    self->stage = server_stopping_k;
    ucall_server_stop(self->handle);
    Py_RETURN_NONE;
}

static char const doc_Server_event_loop_statistics[] =                                           //
    "event_loop_statistics(event_loop, /) -> dict[str, int]\n"                                   //
    "\n"                                                                                         //
    "Counts what one event loop did since initialization.\n"                                     //
    "\n"                                                                                         //
    "Divided by `requests`, the counters price one call.\n"                                      //
    "\n"                                                                                         //
    "Args:\n"                                                                                    //
    "  event_loop (int): The loop to read, below `event_loops`.\n"                               //
    "\n"                                                                                         //
    "Returns:\n"                                                                                 //
    "  dict[str, int]: `polls`, `empty_polls`, `kernel_enters`, `submissions`, `completions`,\n" //
    "    `cancellations`, `accepts`, `requests`, `receive_rearms`, `bytes_received`,\n"          //
    "    `bytes_sent` and `bytes_copied`, each read on its own.\n"                               //
    "\n"                                                                                         //
    "Raises:\n"                                                                                  //
    "  Error: An `event_loop` past the last one.\n"                                              //
    "\n"                                                                                         //
    "Example:\n"                                                                                 //
    "  >>> server.event_loop_statistics(0)[\"requests\"]\n"                                      //
    "  0";

static PyObject* Server_event_loop_statistics(Server* self, PyObject* const* values, Py_ssize_t count,
                                              PyObject* names) {
    PyObject* loop = NULL;
    ucall_py_argument_t const arguments[] = {{"event_loop", &loop}};
    if (ucall_py_parse_fast("event_loop_statistics", values, count, names, 1, 1, arguments, 1) != 0) return NULL;
    int failed = 0;
    size_t const index = event_loop_index(loop, &failed);
    if (failed) return NULL;
    ucall_outcome_t outcome = {0};
    ucall_event_loop_statistics_t counters = {0};
    ucall_server_event_loop_statistics_t query = {self->handle, &outcome, index, &counters};
    ucall_server_event_loop_statistics(&query);
    if (ucall_py_raise_outcome(&outcome) != 0) return NULL;
    return Py_BuildValue("{sKsKsKsKsKsKsKsKsKsKsKsK}",                                  //
                         "polls", (unsigned long long)counters.polls,                   //
                         "empty_polls", (unsigned long long)counters.empty_polls,       //
                         "kernel_enters", (unsigned long long)counters.kernel_enters,   //
                         "submissions", (unsigned long long)counters.submissions,       //
                         "completions", (unsigned long long)counters.completions,       //
                         "cancellations", (unsigned long long)counters.cancellations,   //
                         "accepts", (unsigned long long)counters.accepts,               //
                         "requests", (unsigned long long)counters.requests,             //
                         "receive_rearms", (unsigned long long)counters.receive_rearms, //
                         "bytes_received", (unsigned long long)counters.bytes_received, //
                         "bytes_sent", (unsigned long long)counters.bytes_sent,         //
                         "bytes_copied", (unsigned long long)counters.bytes_copied);
}

static PyObject* Server_get_event_loops(Server* self, void* closure) {
    (void)closure;
    return PyLong_FromSize_t(self->event_loops);
}

static PyObject* Server_get_backend(Server* self, void* closure) {
    (void)closure;
    return ucall_py_enum_to_object(&ucall_py_backend_enum, self->resolved.backend);
}

static PyObject* Server_get_cpu_class(Server* self, void* closure) {
    (void)closure;
    return ucall_py_enum_to_object(&ucall_py_cpu_class_enum, self->resolved.cpu_class);
}

static PyObject* Server_get_addresses(Server* self, void* closure) {
    (void)closure;
    PyObject* const addresses = PyTuple_New((Py_ssize_t)self->resolved.interfaces_count);
    for (size_t index = 0; addresses && index != self->resolved.interfaces_count; ++index) {
        PyObject* const address = PyUnicode_FromString(self->resolved.interfaces[index].address);
        if (!address) {
            Py_DECREF(addresses);
            return NULL;
        }
        PyTuple_SET_ITEM(addresses, (Py_ssize_t)index, address);
    }
    return addresses;
}

static PyObject* Server_get_batch_endpoints(Server* self, void* closure) {
    (void)closure;
    PyObject* const endpoints = PyTuple_New(server_batch_endpoints_count(self));
    Py_ssize_t const count = self->endpoints ? PyList_GET_SIZE(self->endpoints) : 0;
    for (Py_ssize_t index = 0, found = 0; endpoints && index != count; ++index) {
        PyObject* const endpoint = PyList_GET_ITEM(self->endpoints, index);
        if (Py_IS_TYPE(endpoint, &BatchEndpointType)) PyTuple_SET_ITEM(endpoints, found++, Py_NewRef(endpoint));
    }
    return endpoints;
}

static PyMethodDef Server_methods[] = {
    {"add_endpoint", (PyCFunction)(void (*)(void))Server_add_endpoint, ucall_py_method_flags_k,
     doc_Server_add_endpoint},
    {"add_batch_endpoint", (PyCFunction)(void (*)(void))Server_add_batch_endpoint, ucall_py_method_flags_k,
     doc_Server_add_batch_endpoint},
    {"route", (PyCFunction)(void (*)(void))Server_route, ucall_py_method_flags_k, doc_Server_route},
    {"get", (PyCFunction)Server_get, METH_O, doc_Server_get},
    {"post", (PyCFunction)Server_post, METH_O, doc_Server_post},
    {"put", (PyCFunction)Server_put, METH_O, doc_Server_put},
    {"delete", (PyCFunction)Server_delete, METH_O, doc_Server_delete},
    {"patch", (PyCFunction)Server_patch, METH_O, doc_Server_patch},
    {"batch", (PyCFunction)(void (*)(void))Server_batch, ucall_py_method_flags_k, doc_Server_batch},
    {"take_call", (PyCFunction)(void (*)(void))Server_take_call, ucall_py_method_flags_k, doc_Server_take_call},
    {"take_calls", (PyCFunction)(void (*)(void))Server_take_calls, ucall_py_method_flags_k, doc_Server_take_calls},
    {"run", (PyCFunction)Server_run, METH_NOARGS, doc_Server_run},
    {"stop", (PyCFunction)Server_stop, METH_NOARGS, doc_Server_stop},
    {"event_loop_statistics", (PyCFunction)(void (*)(void))Server_event_loop_statistics, ucall_py_method_flags_k,
     doc_Server_event_loop_statistics},
    {NULL, NULL, 0, NULL},
};

static PyGetSetDef Server_getset[] = {
    {"event_loops", (getter)Server_get_event_loops, NULL, "Resolved loops, each needing one polling thread.", NULL},
    {"backend", (getter)Server_get_backend, NULL, "The I/O implementation initialization chose.", NULL},
    {"cpu_class", (getter)Server_get_cpu_class, NULL, "The CPU kernels initialization chose.", NULL},
    {"addresses", (getter)Server_get_addresses, NULL, "The resolved \"host:port\" of each interface.", NULL},
    {"batch_endpoints", (getter)Server_get_batch_endpoints, NULL, "Batch endpoints, each needing a drainer.", NULL},
    {NULL, NULL, NULL, NULL, NULL},
};

PyTypeObject ServerType = {
    PyVarObject_HEAD_INIT(NULL, 0).tp_name = "ucall.Server",
    .tp_basicsize = sizeof(Server),
    .tp_flags = Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE | Py_TPFLAGS_HAVE_GC,
    .tp_doc = doc_Server,
    .tp_new = Server_new,
    .tp_traverse = (traverseproc)Server_traverse,
    .tp_clear = (inquiry)Server_clear,
    .tp_dealloc = (destructor)Server_dealloc,
    .tp_methods = Server_methods,
    .tp_getset = Server_getset,
};

#pragma endregion Server
