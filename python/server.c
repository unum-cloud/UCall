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
    PyObject* noise_private_key;

    /** The callable vetting Noise peers, or NULL. */
    PyObject* peer_authorizer;

    /** The initiator's 32-byte static public key, a @c bytes, which KK requires, or NULL. */
    PyObject* noise_peer_key;

    /** The directories path parts resolve beneath, by position: a tuple of @c str or @c bytes. */
    PyObject* reply_directories;

    /** The encryption of accepted connections. */
    ucall_security_t security;

    /** The requested loops; zero lets the library choose. */
    Py_ssize_t event_loops;

    /** The open-connection budget. */
    Py_ssize_t connections;

    /** The requests one connection carries at once; zero means one. */
    Py_ssize_t pipelined_requests;

    /** The largest request head and buffered body; zero takes the kernel's receive buffer. */
    Py_ssize_t max_request_bytes;

    /** A listening socket to accept on instead of binding @c address, or -1 to bind. */
    intptr_t descriptor;
} Interface;

static char const doc_Interface[] =                                                                 //
    "Interface(address=\"\", *, descriptor=None, device_name=None, security=Security.NONE,\n"       //
    "    noise_private_key=None, peer_authorizer=None, noise_peer_key=None, event_loops=0,\n"       //
    "    connections=1024, pipelined_requests=0, max_request_bytes=0, reply_directories=())\n"      //
    "\n"                                                                                            //
    "One address a server answers on, with the security and admission of what arrives there.\n"     //
    "\n"                                                                                            //
    "Args:\n"                                                                                       //
    "  address (str): The \"host:port\" to listen on; port 0 takes a free one, which\n"             //
    "    `Server.addresses` reports. Required unless `descriptor` is given.\n"                      //
    "  descriptor (int | socket.socket, optional): A listening stream socket to accept on\n"        //
    "    instead, such as an AF_UNIX one; the server accepts on duplicates and never closes it.\n"  //
    "  device_name (str, optional): A network device to pin the socket to, such as \"eth0\";\n"     //
    "    None binds by address alone.\n"                                                            //
    "  security (Security, optional): Encryption of accepted connections. Defaults to\n"            //
    "    `Security.NONE`.\n"                                                                        //
    "  noise_private_key (bytes, optional): The 32-byte Noise identity, required under Noise.\n"    //
    "  peer_authorizer (Callable[[bytes], bool], optional): Admits a Noise peer by its 32-byte\n"   //
    "    static key, required under `Security.NOISE_XX`; None admits every peer.\n"                 //
    "  noise_peer_key (bytes, optional): The one caller's 32-byte static public key, required\n"    //
    "    under `Security.NOISE_KK`.\n"                                                              //
    "  event_loops (int, optional): Loops accepting here; 0 takes one for an address and one per\n" //
    "    receive queue for a device.\n"                                                             //
    "  connections (int, optional): Connections open at once. Defaults to 1024.\n"                  //
    "  pipelined_requests (int, optional): Requests one connection carries before the server\n"     //
    "    stops reading from it; 0 means one.\n"                                                     //
    "  max_request_bytes (int, optional): The largest request head and buffered body, past which\n" //
    "    the reply is 413; 0 takes the largest receive buffer the kernel grants a socket.\n"        //
    "  reply_directories (Sequence[str | bytes | os.PathLike], optional): The directories a\n"      //
    "    `Path` part names by position, each opened once by the server.\n"                          //
    "\n"                                                                                            //
    "Raises:\n"                                                                                     //
    "  TypeError: An argument of the wrong type.\n"                                                 //
    "  ValueError: A key other than 32 bytes long, or an unknown `security`.\n"                     //
    "\n"                                                                                            //
    "Example:\n"                                                                                    //
    "  >>> interface = ucall.Interface(\"127.0.0.1:0\", connections=64, pipelined_requests=16)\n"   //
    "  >>> interface.connections, interface.security\n"                                             //
    "  (64, <Security.NONE: 0>)";

/** The reply directories as a tuple of @c os.fspath results, each a @c str or a @c bytes. */
static PyObject* interface_directories(PyObject* object) {
    if (!object || object == Py_None) return PyTuple_New(0);
    if (PyUnicode_Check(object) || PyBytes_Check(object))
        return PyErr_Format(PyExc_TypeError, "'reply_directories' takes a sequence of paths, got one %s",
                            Py_TYPE(object)->tp_name);
    PyObject* const listed = PySequence_Tuple(object);
    if (!listed) return NULL;
    Py_ssize_t const count = PyTuple_GET_SIZE(listed);
    PyObject* paths = PyTuple_New(count);
    for (Py_ssize_t index = 0; paths && index != count; ++index) {
        PyObject* const path = PyOS_FSPath(PyTuple_GET_ITEM(listed, index));
        if (path) PyTuple_SET_ITEM(paths, index, path);
        else Py_CLEAR(paths);
    }
    Py_DECREF(listed);
    return paths;
}

static PyObject* Interface_new(PyTypeObject* type, PyObject* positional, PyObject* keywords) {
    PyObject *address = NULL, *descriptor = NULL, *device_name = NULL, *security = NULL, *noise_private_key = NULL,
             *peer_authorizer = NULL, *noise_peer_key = NULL, *event_loops = NULL, *connections = NULL,
             *pipelined_requests = NULL, *max_request_bytes = NULL, *reply_directories = NULL;
    ucall_py_argument_t const arguments[] = {
        {"address", &address},
        {"descriptor", &descriptor},
        {"device_name", &device_name},
        {"security", &security},
        {"noise_private_key", &noise_private_key},
        {"peer_authorizer", &peer_authorizer},
        {"noise_peer_key", &noise_peer_key},
        {"event_loops", &event_loops},
        {"connections", &connections},
        {"pipelined_requests", &pipelined_requests},
        {"max_request_bytes", &max_request_bytes},
        {"reply_directories", &reply_directories},
    };
    if (ucall_py_parse_tuple("Interface", positional, keywords, 0, 1, arguments,
                             sizeof(arguments) / sizeof(arguments[0])) != 0)
        return NULL;
    PyObject* const empty = PyUnicode_FromString("");
    if (!empty) return NULL;
    if (!address) address = empty;
    if (!PyUnicode_Check(address)) {
        Py_DECREF(empty);
        return PyErr_Format(PyExc_TypeError, "'address' must be str, got %s", Py_TYPE(address)->tp_name);
    }
    long long listening = -1;
    if (descriptor && descriptor != Py_None) {
        // A `socket.socket` hands its descriptor over through `fileno()`, as `select` takes it.
        PyObject* const number = PyLong_Check(descriptor) ? Py_NewRef(descriptor)
                                                          : PyObject_CallMethod(descriptor, "fileno", NULL);
        listening = number ? PyLong_AsLongLong(number) : -1;
        Py_XDECREF(number);
        if (PyErr_Occurred() || listening < 0) {
            Py_DECREF(empty);
            if (!PyErr_Occurred()) PyErr_SetString(PyExc_ValueError, "'descriptor' must name an open socket");
            return NULL;
        }
    }
    else if (PyUnicode_GetLength(address) == 0) {
        Py_DECREF(empty);
        return PyErr_Format(PyExc_TypeError, "Interface() needs an 'address' or a 'descriptor'");
    }
    if (device_name == Py_None) device_name = NULL;
    if (device_name && !PyUnicode_Check(device_name))
        return PyErr_Format(PyExc_TypeError, "'device_name' must be str or None, got %s",
                            Py_TYPE(device_name)->tp_name);
    if (noise_private_key == Py_None) noise_private_key = NULL;
    ucall_noise_key_t key_check;
    if (noise_private_key && ucall_py_key_from_object(noise_private_key, "noise_private_key", key_check) != 0)
        return NULL;
    if (noise_peer_key == Py_None) noise_peer_key = NULL;
    if (noise_peer_key && ucall_py_key_from_object(noise_peer_key, "noise_peer_key", key_check) != 0) return NULL;
    if (peer_authorizer == Py_None) peer_authorizer = NULL;
    if (peer_authorizer && !PyCallable_Check(peer_authorizer))
        return PyErr_Format(PyExc_TypeError, "'peer_authorizer' must be callable, got %s",
                            Py_TYPE(peer_authorizer)->tp_name);
    int security_value = ucall_security_none_k;
    size_t loops = 0, budget = 1024, pipelined = 0, request_bytes = 0;
    if (ucall_py_enum_from_object(security, "security", &ucall_py_security_enum, &security_value) != 0 ||
        ucall_py_size_from_object(event_loops, "event_loops", &loops) != 0 ||
        ucall_py_size_from_object(connections, "connections", &budget) != 0 ||
        ucall_py_size_from_object(pipelined_requests, "pipelined_requests", &pipelined) != 0 ||
        ucall_py_size_from_object(max_request_bytes, "max_request_bytes", &request_bytes) != 0)
        return NULL;
    PyObject* const directories = interface_directories(reply_directories);
    if (!directories) {
        Py_DECREF(empty);
        return NULL;
    }

    Interface* const self = (Interface*)type->tp_alloc(type, 0);
    if (!self) {
        Py_DECREF(directories);
        Py_DECREF(empty);
        return NULL;
    }
    self->address = Py_NewRef(address);
    Py_DECREF(empty);
    self->descriptor = (intptr_t)listening;
    self->device_name = Py_XNewRef(device_name);
    self->noise_private_key = Py_XNewRef(noise_private_key);
    self->peer_authorizer = Py_XNewRef(peer_authorizer);
    self->noise_peer_key = Py_XNewRef(noise_peer_key);
    self->reply_directories = directories;
    self->security = (ucall_security_t)security_value;
    self->event_loops = (Py_ssize_t)loops;
    self->connections = (Py_ssize_t)budget;
    self->pipelined_requests = (Py_ssize_t)pipelined;
    self->max_request_bytes = (Py_ssize_t)request_bytes;
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
    Py_CLEAR(self->noise_private_key);
    Py_CLEAR(self->noise_peer_key);
    Py_CLEAR(self->reply_directories);
    Py_TYPE(self)->tp_free((PyObject*)self);
}

static PyObject* Interface_get_security(Interface* self, [[maybe_unused]] void* closure) {
    return ucall_py_enum_to_object(&ucall_py_security_enum, self->security);
}

static PyMemberDef Interface_members[] = {
    {"address", Py_T_OBJECT_EX, offsetof(Interface, address), Py_READONLY, "The \"host:port\" to listen on."},
    {"event_loops", Py_T_PYSSIZET, offsetof(Interface, event_loops), Py_READONLY, "Requested loops; 0 chooses."},
    {"connections", Py_T_PYSSIZET, offsetof(Interface, connections), Py_READONLY, "Connections open at once."},
    {"pipelined_requests", Py_T_PYSSIZET, offsetof(Interface, pipelined_requests), Py_READONLY,
     "Requests one connection carries at once; 0 means one."},
    {"max_request_bytes", Py_T_PYSSIZET, offsetof(Interface, max_request_bytes), Py_READONLY,
     "The largest request head and buffered body; 0 takes the kernel's receive buffer."},
    {"reply_directories", Py_T_OBJECT_EX, offsetof(Interface, reply_directories), Py_READONLY,
     "The directories `Path` parts name by position."},
    {NULL, 0, 0, 0, NULL},
};

static PyGetSetDef Interface_getset[] = {
    {"security", (getter)Interface_get_security, NULL, "Encryption of accepted connections.", NULL},
    {"device_name", ucall_py_get_optional, NULL, "The pinned device, or None.",
     (void*)offsetof(Interface, device_name)},
    {"noise_private_key", ucall_py_get_optional, NULL, "The 32-byte Noise identity, or None.",
     (void*)offsetof(Interface, noise_private_key)},
    {"peer_authorizer", ucall_py_get_optional, NULL, "The Noise peer vetting, or None.",
     (void*)offsetof(Interface, peer_authorizer)},
    {"noise_peer_key", ucall_py_get_optional, NULL, "The 32-byte static key KK expects, or None.",
     (void*)offsetof(Interface, noise_peer_key)},
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

#pragma region Metrics

typedef struct Metrics {
    PyObject ob_base;

    /** The StatsD "host:port", a @c str or @c bytes. */
    PyObject* address;

    /** The metric name prefix, a @c str or @c bytes, empty taking "ucall". */
    PyObject* prefix;

    /** Global "key:value" tags, a tuple of @c str or @c bytes. */
    PyObject* tags;

    /** The fraction of finished requests whose latency is reported; zero takes 1.0. */
    double sample_rate;

    /** Microseconds between one event loop's datagrams; zero takes one second. */
    Py_ssize_t interval_microseconds;
} Metrics;

static char const doc_Metrics[] =                                                                    //
    "Metrics(address, sample_rate=0.0, prefix=\"\", tags=(), interval_microseconds=0)\n"             //
    "\n"                                                                                             //
    "Where a `Server` sends StatsD datagrams, each event loop on its own schedule.\n"                //
    "\n"                                                                                             //
    "Args:\n"                                                                                        //
    "  address (str | bytes): The StatsD UDP endpoint, \"host:port\".\n"                             //
    "  sample_rate (float, optional): The fraction of finished requests whose latency is\n"          //
    "    reported, in (0, 1]; 0 takes 1.\n"                                                          //
    "  prefix (str | bytes, optional): The metric name prefix; empty takes \"ucall\".\n"             //
    "  tags (Sequence[str | bytes], optional): Global \"key:value\" tags.\n"                         //
    "  interval_microseconds (int, optional): Microseconds between datagrams; 0 takes one second.\n" //
    "\n"                                                                                             //
    "Example:\n"                                                                                     //
    "  >>> metrics = ucall.Metrics(\"127.0.0.1:8125\", tags=(\"service:inference\",))\n"             //
    "  >>> server = ucall.Server(ucall.Interface(\"127.0.0.1:0\"), metrics=metrics)";

static PyObject* Metrics_new(PyTypeObject* type, PyObject* positional, PyObject* keywords) {
    PyObject *address = NULL, *sample_rate = NULL, *prefix = NULL, *tags = NULL, *interval_microseconds = NULL;
    ucall_py_argument_t const arguments[] = {
        {"address", &address},
        {"sample_rate", &sample_rate},
        {"prefix", &prefix},
        {"tags", &tags},
        {"interval_microseconds", &interval_microseconds},
    };
    if (ucall_py_parse_tuple("Metrics", positional, keywords, 1, 5, arguments, 5) != 0) return NULL;
    ucall_bytes_view_t view;
    double rate = 0.0;
    size_t interval = 0;
    if (ucall_py_text_from_object(address, "address", &view) != 0 ||
        (prefix && ucall_py_text_from_object(prefix, "prefix", &view) != 0) ||
        (sample_rate && (rate = PyFloat_AsDouble(sample_rate)) == -1.0 && PyErr_Occurred()) ||
        ucall_py_size_from_object(interval_microseconds, "interval_microseconds", &interval) != 0)
        return NULL;
    PyObject* const tagged = tags ? PySequence_Tuple(tags) : PyTuple_New(0);
    for (Py_ssize_t index = 0; tagged && index != PyTuple_GET_SIZE(tagged); ++index)
        if (ucall_py_text_from_object(PyTuple_GET_ITEM(tagged, index), "tags", &view) != 0) {
            Py_DECREF(tagged);
            return NULL;
        }
    Metrics* const self = tagged ? (Metrics*)type->tp_alloc(type, 0) : NULL;
    if (!self) {
        Py_XDECREF(tagged);
        return NULL;
    }
    self->address = Py_NewRef(address);
    self->prefix = Py_XNewRef(prefix);
    self->tags = tagged;
    self->sample_rate = rate;
    self->interval_microseconds = (Py_ssize_t)interval;
    return (PyObject*)self;
}

static void Metrics_dealloc(Metrics* self) {
    Py_CLEAR(self->address);
    Py_CLEAR(self->prefix);
    Py_CLEAR(self->tags);
    Py_TYPE(self)->tp_free((PyObject*)self);
}

static PyMemberDef Metrics_members[] = {
    {"address", Py_T_OBJECT_EX, offsetof(Metrics, address), Py_READONLY, "The StatsD \"host:port\"."},
    {"sample_rate", Py_T_DOUBLE, offsetof(Metrics, sample_rate), Py_READONLY, "Latencies reported; 0 takes 1."},
    {"tags", Py_T_OBJECT_EX, offsetof(Metrics, tags), Py_READONLY, "Global \"key:value\" tags."},
    {"interval_microseconds", Py_T_PYSSIZET, offsetof(Metrics, interval_microseconds), Py_READONLY,
     "Microseconds between datagrams."},
    {NULL, 0, 0, 0, NULL},
};

static PyGetSetDef Metrics_getset[] = {
    {"prefix", ucall_py_get_optional, NULL, "The metric name prefix, or None for \"ucall\".",
     (void*)offsetof(Metrics, prefix)},
    {NULL, NULL, NULL, NULL, NULL},
};

PyTypeObject MetricsType = {
    PyVarObject_HEAD_INIT(NULL, 0).tp_name = "ucall.Metrics",
    .tp_basicsize = sizeof(Metrics),
    .tp_flags = Py_TPFLAGS_DEFAULT,
    .tp_doc = doc_Metrics,
    .tp_new = Metrics_new,
    .tp_dealloc = (destructor)Metrics_dealloc,
    .tp_members = Metrics_members,
    .tp_getset = Metrics_getset,
};

#pragma endregion Metrics

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
    ucall_server_options_t resolved;

    /** The largest resolved @c event_loops among the interfaces: the server's parallelism. */
    size_t event_loops;

    /** The @c Interface tuple, keeping each authorizer the C interface borrows alive. */
    PyObject* interfaces;

    /** Every endpoint context the C interface borrows, an @c Endpoint or @c BatchEndpoint. */
    PyObject* endpoints;

    /** The callable receiving log lines, which the C interface borrows, or NULL. */
    PyObject* log;

    /** Advanced by @c stop() from any thread, so every access takes the server's section. */
    server_stage_t stage;
} Server;

/** A @c Request, or a @c DetachedRequest taken from one, sharing every read accessor. */
typedef struct Request {
    PyObject ob_base;

    /** The retained C request, NULL once a reply consumed it or a detached request took it. */
    ucall_received_http_request_t handle;

    /** The server that received it, kept alive as long as the request. */
    Server* server;

    /** Live buffer exports over its bytes, each of which a reply or a pull would leave dangling. */
    Py_ssize_t exports;
} Request;

/** The exporter behind a part's or a chunk's memoryview, counted among its request's exports. */
typedef struct RequestBytes {
    PyObject ob_base;

    /** The request owning the bytes, kept alive and refusing replies while the view is. */
    Request* request;

    /** The bytes exported. */
    ucall_bytes_view_t bytes;
} RequestBytes;

typedef struct RequestPart {
    PyObject ob_base;

    /** The part name from @c Content-Disposition, a @c str. */
    PyObject* name;

    /** The part's @c Content-Type, a @c str, empty if absent. */
    PyObject* content_type;

    /** A read-only memoryview of the payload, pinning the request. */
    PyObject* data;
} RequestPart;

typedef struct File {
    PyObject ob_base;

    /** The @c int or the object answering @c fileno() it was made from, which keeps a file object
     *  open. */
    PyObject* descriptor;

    /** The range as the C interface reads it. */
    ucall_file_range_t range;
} File;

typedef struct Path {
    PyObject ob_base;

    /** The file beneath the directory, the @c str or @c bytes that @c range views. */
    PyObject* path;

    /** The range as the C interface reads it. */
    ucall_path_range_t range;
} Path;

typedef struct Deferred {
    PyObject ob_base;

    /** The outcome the event loop publishes, at an address outliving the reply call. */
    ucall_outcome_t outcome;

    /** The @c File parts whose descriptors the reply borrows until final, a list. */
    PyObject* files;
} Deferred;

typedef struct ReplyStream {
    PyObject ob_base;

    /** The request whose reply is open, NULL once it ended. */
    ucall_received_http_request_t handle;

    /** The server that received it, kept alive as long as the stream. */
    Server* server;

    /** The @c File parts appended so far, whose descriptors the reply borrows until final,
     *  a list. */
    PyObject* files;

    /** File and path parts appended so far, which make the end defer. */
    size_t deferring_count;
} ReplyStream;

typedef struct BodyChunks {
    PyObject ob_base;

    /** The detached request whose body it pulls. */
    Request* request;

    /** The memoryview the last pull yielded, which the next pull releases, or NULL. */
    PyObject* chunk;
} BodyChunks;

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
    ucall_server_reply_content_t reply = {server, &outcome, request, status, headers, headers_count, body};
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
    if (Py_IS_TYPE(result, &FileType) || Py_IS_TYPE(result, &PathType)) {
        PyErr_Format(PyExc_TypeError,
                     "a handler returned a %s, which may defer, so send it with DetachedRequest.reply_parts " //
                     "on another thread",
                     Py_TYPE(result)->tp_name);
        return -1;
    }
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

static PyObject* request_new(Server* server, ucall_received_http_request_t handle, PyTypeObject* type) {
    Request* const request = PyObject_New(Request, type);
    if (!request) return NULL;
    request->handle = handle;
    request->server = (Server*)Py_NewRef(server);
    request->exports = 0;
    return (PyObject*)request;
}

/** Takes @p self's handle for one reply under its section, so of two racing replies one finds
 *  it gone. */
static ucall_received_http_request_t request_take(Request* self) {
    ucall_py_section_t section;
    ucall_py_section_begin(&section, (PyObject*)self);
    ucall_received_http_request_t const handle = self->handle;
    self->handle = NULL;
    ucall_py_section_end(&section);
    return handle;
}

/** Gives back the handle of a reply that queued nothing, so the request still answers. */
static void request_restore(Request* self, ucall_received_http_request_t handle) {
    ucall_py_section_t section;
    ucall_py_section_begin(&section, (PyObject*)self);
    self->handle = handle;
    ucall_py_section_end(&section);
}

static PyObject* request_raise_replied(void) {
    return ucall_py_raise_status(ucall_status_already_exists_k, "the request was already replied to");
}

/** Answers @p request with an error unless it was replied to or views over its body are alive. */
static void request_fail(Request* request, ucall_http_status_t status, char const* message) {
    if (request->exports) return;
    ucall_received_http_request_t const handle = request_take(request);
    if (!handle) return;
    ucall_status_t const replied = reply_failure(request->server->handle, handle, status, message, strlen(message));
    if (replied != ucall_status_success_k && replied != ucall_status_connection_closed_k)
        request_restore(request, handle);
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

static void Request_releasebuffer(Request* self, [[maybe_unused]] Py_buffer* view) { --self->exports; }

static PyBufferProcs Request_buffer = {(getbufferproc)Request_getbuffer, (releasebufferproc)Request_releasebuffer};

static PyObject* Request_get_body(Request* self, [[maybe_unused]] void* closure) {
    return PyMemoryView_FromObject((PyObject*)self);
}

static PyObject* Request_get_verb(Request* self, [[maybe_unused]] void* closure) {
    if (request_live(self) != 0) return NULL;
    return ucall_py_enum_to_object(&ucall_py_verb_enum, ucall_server_request_verb(self->server->handle, self->handle));
}

static PyObject* Request_get_path(Request* self, [[maybe_unused]] void* closure) {
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

static char const doc_Request_fields[] =                                                            //
    "fields() -> list[tuple[bytes, bytes]]\n"                                                       //
    "\n"                                                                                            //
    "Every header field line in arrival order, repeated names apart, as a proxy forwards a head.\n" //
    "\n"                                                                                            //
    "Returns:\n"                                                                                    //
    "  list[tuple[bytes, bytes]]: Each name, lowercased as the parser keeps it, with its value\n"   //
    "    trimmed.\n"                                                                                //
    "\n"                                                                                            //
    "Example:\n"                                                                                    //
    "  >>> [name for name, _ in request.fields()]\n"                                                //
    "  [b'host', b'accept']";

static PyObject* Request_fields(Request* self, [[maybe_unused]] PyObject* unused) {
    if (request_live(self) != 0) return NULL;
    ucall_outcome_t outcome = {0};
    size_t count = 0;
    ucall_server_request_fields_count_t counting = {self->server->handle, &outcome, self->handle, &count};
    ucall_server_request_fields_count(&counting);
    if (ucall_py_raise_outcome(&outcome) != 0) return NULL;
    PyObject* const fields = PyList_New((Py_ssize_t)count);
    for (size_t index = 0; fields && index != count; ++index) {
        ucall_bytes_view_t name = {0}, value = {0};
        ucall_server_request_field_t extract = {self->server->handle, &outcome, self->handle, index, &name, &value};
        ucall_server_request_field(&extract);
        PyObject* const field = ucall_py_raise_outcome(&outcome) == 0
                                    ? Py_BuildValue("(y#y#)", (char const*)name.data, (Py_ssize_t)name.length,
                                                    (char const*)value.data, (Py_ssize_t)value.length)
                                    : NULL;
        if (!field) {
            Py_DECREF(fields);
            return NULL;
        }
        PyList_SET_ITEM(fields, (Py_ssize_t)index, field);
    }
    return fields;
}

static PyObject* Request_get_query_string(Request* self, [[maybe_unused]] void* closure) {
    if (request_live(self) != 0) return NULL;
    ucall_outcome_t outcome = {0};
    ucall_bytes_view_t query = {0};
    ucall_server_request_query_t extract = {self->server->handle, &outcome, self->handle, &query};
    ucall_server_request_query(&extract);
    if (ucall_py_raise_outcome(&outcome) != 0) return NULL;
    return ucall_py_text_to_object(query);
}

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

static char const doc_Request_path_parameter[] =                                           //
    "path_parameter(name, /) -> str | None\n"                                              //
    "\n"                                                                                   //
    "Looks up a placeholder the endpoint's URI template captured.\n"                       //
    "\n"                                                                                   //
    "Args:\n"                                                                              //
    "  name (str | bytes): The placeholder name without braces, \"path\" for `{*path}`.\n" //
    "\n"                                                                                   //
    "Returns:\n"                                                                           //
    "  str | None: The captured text as sent, or None when the template has no such\n"     //
    "    placeholder.\n"                                                                   //
    "\n"                                                                                   //
    "Example:\n"                                                                           //
    "  >>> @server.get(\"/files/{*path}\")\n"                                              //
    "  ... def files(request: ucall.Request):\n"                                           //
    "  ...     return request.path_parameter(\"path\")";

static PyObject* Request_path_parameter(Request* self, PyObject* name) {
    return request_lookup(self, name, lookup_path_parameter);
}

/** A peer's socket address as Python's @c socket spells one: an address and port pair, an empty
 *  string for AF_UNIX as @c getpeername answers, or None when unknown. */
static PyObject* peer_address_object(ucall_peer_address_t const* address) {
    if (address->family == ucall_address_family_unix_k) return PyUnicode_FromString("");
    if (address->family != ucall_address_family_ipv4_k && address->family != ucall_address_family_ipv6_k)
        Py_RETURN_NONE;
    PyObject* const module = PyImport_ImportModule("ipaddress");
    if (!module) return NULL;
    Py_ssize_t const length = address->family == ucall_address_family_ipv4_k ? 4 : 16;
    PyObject* const ip = PyObject_CallMethod(module, "ip_address", "y#", (char const*)address->bytes, length);
    Py_DECREF(module);
    if (!ip) return NULL;
    return Py_BuildValue("(Ni)", ip, (int)address->port);
}

static PyObject* Request_get_peer(Request* self, [[maybe_unused]] void* closure) {
    if (request_live(self) != 0) return NULL;
    ucall_outcome_t outcome = {0};
    size_t interface_index = 0;
    ucall_noise_key_t static_key = {0};
    ucall_peer_address_t address = {0};
    ucall_server_request_peer_t query = {self->server->handle, &outcome,    self->handle,
                                         &interface_index,     &static_key, &address};
    ucall_server_request_peer(&query);
    if (ucall_py_raise_outcome(&outcome) != 0) return NULL;
    PyObject* const peer = peer_address_object(&address);
    if (!peer) return NULL;
    return Py_BuildValue("(nNN)", (Py_ssize_t)interface_index,
                         PyBytes_FromStringAndSize((char const*)static_key, sizeof(ucall_noise_key_t)), peer);
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
        request_raise_replied();
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

/** Keeps the request consumed after a reply that delivered it or found its connection closed, and
 *  gives @p handle back otherwise. */
static PyObject* request_finish_reply(Request* self, ucall_received_http_request_t handle, ucall_outcome_t* outcome) {
    ucall_status_t const status = ucall_outcome_status(outcome);
    if (status == ucall_status_success_k || status == ucall_status_connection_closed_k) Py_RETURN_NONE;
    request_restore(self, handle);
    ucall_py_raise_outcome(outcome);
    return NULL;
}

/** Hands @p deferred back once its reply was queued, or gives @p handle back and raises the refusal
 *  that queued nothing. */
static PyObject* request_defer_reply(Request* self, ucall_received_http_request_t handle, Deferred* deferred) {
    ucall_status_t const status = ucall_outcome_status(&deferred->outcome);
    // A queued reply may already be final, even failed, so only these refusals
    // leave the request unanswered.
    if (status == ucall_status_uninitialized_k || status == ucall_status_invalid_argument_k ||
        status == ucall_status_already_exists_k || status == ucall_status_out_of_memory_k) {
        request_restore(self, handle);
        ucall_py_raise_outcome(&deferred->outcome);
        return NULL;
    }
    return Py_NewRef((PyObject*)deferred);
}

/** Answers @p self with @p body, any bytes-like object or NULL for none, and consumes it. */
static PyObject* request_send(Request* self, PyObject* body, ucall_http_status_t status,
                              ucall_bytes_view_t const* headers, size_t headers_count) {
    ucall_bytes_view_t own;
    if (request_claim_reply(self, body, &own) != 0) return NULL;
    Py_buffer buffer = {0};
    if (body && !own.data && PyObject_GetBuffer(body, &buffer, PyBUF_SIMPLE) != 0) return NULL;
    ucall_bytes_view_t const content = own.data ? own : (ucall_bytes_view_t) {buffer.buf, (size_t)buffer.len};
    ucall_received_http_request_t const handle = request_take(self);
    ucall_outcome_t outcome = {0};
    ucall_server_reply_content_t reply = {self->server->handle, &outcome, handle, status, headers,
                                          headers_count,        content};
    if (handle) ucall_server_reply_content(&reply);
    if (buffer.obj) PyBuffer_Release(&buffer);
    return handle ? request_finish_reply(self, handle, &outcome) : request_raise_replied();
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
    ucall_received_http_request_t const handle = request_take(self);
    if (!handle) return request_raise_replied();
    ucall_outcome_t outcome = {0};
    ucall_server_reply_error_t reply = {self->server->handle, &outcome, handle, (ucall_http_status_t)http_status, text};
    ucall_server_reply_error(&reply);
    return request_finish_reply(self, handle, &outcome);
}

static int RequestBytes_getbuffer(RequestBytes* self, Py_buffer* view, int flags) {
    static ucall_byte_t const empty_k[1] = {0};
    void* const data = (void*)(self->bytes.data ? self->bytes.data : empty_k);
    if (PyBuffer_FillInfo(view, (PyObject*)self, data, (Py_ssize_t)self->bytes.length, 1, flags) != 0) return -1;
    ++self->request->exports;
    return 0;
}

static void RequestBytes_releasebuffer(RequestBytes* self, [[maybe_unused]] Py_buffer* view) {
    --self->request->exports;
}

static void RequestBytes_dealloc(RequestBytes* self) {
    Py_CLEAR(self->request);
    PyObject_Free(self);
}

static PyBufferProcs RequestBytes_buffer = {(getbufferproc)RequestBytes_getbuffer,
                                            (releasebufferproc)RequestBytes_releasebuffer};

PyTypeObject RequestBytesType = {
    PyVarObject_HEAD_INIT(NULL, 0).tp_name = "ucall.RequestBytes",
    .tp_basicsize = sizeof(RequestBytes),
    .tp_flags = Py_TPFLAGS_DEFAULT,
    .tp_doc = "Bytes a request owns, behind a memoryview that refuses the request's reply while alive.",
    .tp_dealloc = (destructor)RequestBytes_dealloc,
    .tp_as_buffer = &RequestBytes_buffer,
};

/** A read-only memoryview of @p bytes inside @p request, counted among its exports while alive. */
static PyObject* request_bytes_view(Request* request, ucall_bytes_view_t bytes) {
    RequestBytes* const exporter = PyObject_New(RequestBytes, &RequestBytesType);
    if (!exporter) return NULL;
    exporter->request = (Request*)Py_NewRef(request);
    exporter->bytes = bytes;
    PyObject* const view = PyMemoryView_FromObject((PyObject*)exporter);
    Py_DECREF(exporter);
    return view;
}

static void RequestPart_dealloc(RequestPart* self) {
    Py_CLEAR(self->name);
    Py_CLEAR(self->content_type);
    Py_CLEAR(self->data);
    PyObject_Free(self);
}

static PyMemberDef RequestPart_members[] = {
    {"name", Py_T_OBJECT_EX, offsetof(RequestPart, name), Py_READONLY, "The name from Content-Disposition."},
    {"content_type", Py_T_OBJECT_EX, offsetof(RequestPart, content_type), Py_READONLY,
     "The part's Content-Type, empty if absent."},
    {"data", Py_T_OBJECT_EX, offsetof(RequestPart, data), Py_READONLY,
     "A read-only memoryview of the payload, which refuses the request's reply while alive."},
    {NULL, 0, 0, 0, NULL},
};

static char const doc_RequestPart[] =                                                              //
    "One part of a `multipart/form-data` request body, from `Request.parts`.\n"                    //
    "\n"                                                                                           //
    "`data` views the received bytes without a copy and keeps the request alive, so the request\n" //
    "refuses its reply until every such view is gone, as it does for views over `body`.\n"         //
    "\n"                                                                                           //
    "Example:\n"                                                                                   //
    "  >>> @server.post(\"/upload\")\n"                                                            //
    "  ... def upload(request: ucall.Request):\n"                                                  //
    "  ...     return {part.name: len(part.data) for part in request.parts}";

PyTypeObject RequestPartType = {
    PyVarObject_HEAD_INIT(NULL, 0).tp_name = "ucall.RequestPart",
    .tp_basicsize = sizeof(RequestPart),
    .tp_flags = Py_TPFLAGS_DEFAULT,
    .tp_doc = doc_RequestPart,
    .tp_dealloc = (destructor)RequestPart_dealloc,
    .tp_members = RequestPart_members,
};

static PyObject* request_part_new(Request* request, ucall_bytes_view_t name, ucall_bytes_view_t content_type,
                                  ucall_bytes_view_t data) {
    RequestPart* const part = PyObject_New(RequestPart, &RequestPartType);
    if (!part) return NULL;
    part->name = ucall_py_text_to_object(name);
    part->content_type = part->name ? ucall_py_text_to_object(content_type) : NULL;
    part->data = part->content_type ? request_bytes_view(request, data) : NULL;
    if (part->data) return (PyObject*)part;
    Py_DECREF(part);
    return NULL;
}

static PyObject* Request_get_parts(Request* self, [[maybe_unused]] void* closure) {
    if (request_live(self) != 0) return NULL;
    size_t const count = ucall_server_request_parts_count(self->server->handle, self->handle);
    PyObject* const parts = PyTuple_New((Py_ssize_t)count);
    for (size_t index = 0; parts && index != count; ++index) {
        ucall_outcome_t outcome = {0};
        ucall_bytes_view_t name = {0}, content_type = {0}, data = {0};
        ucall_server_request_part_t extract = {self->server->handle, &outcome, self->handle, index, &name,
                                               &content_type,        &data};
        ucall_server_request_part(&extract);
        PyObject* const part = ucall_py_raise_outcome(&outcome) == 0 ? request_part_new(self, name, content_type, data)
                                                                     : NULL;
        if (!part) {
            Py_DECREF(parts);
            return NULL;
        }
        PyTuple_SET_ITEM(parts, (Py_ssize_t)index, part);
    }
    return parts;
}

static PyObject* Request_get_path_segments(Request* self, [[maybe_unused]] void* closure) {
    if (request_live(self) != 0) return NULL;
    size_t const count = ucall_server_request_path_segments_count(self->server->handle, self->handle);
    PyObject* const segments = PyTuple_New((Py_ssize_t)count);
    for (size_t index = 0; segments && index != count; ++index) {
        ucall_outcome_t outcome = {0};
        ucall_bytes_view_t segment = {0};
        ucall_server_request_path_segment_t extract = {self->server->handle, &outcome, self->handle, index, &segment};
        ucall_server_request_path_segment(&extract);
        PyObject* const bytes = ucall_py_raise_outcome(&outcome) == 0
                                    ? PyBytes_FromStringAndSize((char const*)segment.data, (Py_ssize_t)segment.length)
                                    : NULL;
        if (!bytes) {
            Py_DECREF(segments);
            return NULL;
        }
        PyTuple_SET_ITEM(segments, (Py_ssize_t)index, bytes);
    }
    return segments;
}

static char const doc_Request_detach[] =                                                         //
    "detach() -> DetachedRequest\n"                                                              //
    "\n"                                                                                         //
    "Hands the request to another thread, the one way to the verbs whose replies may defer.\n"   //
    "\n"                                                                                         //
    "The `DetachedRequest` owns the request from then on, and this object answers nothing. A\n"  //
    "`Deferred` waits when released, and a wait on the polling thread would wait for the loop\n" //
    "running it, so pass the detached request to a worker rather than replying here.\n"          //
    "\n"                                                                                         //
    "Raises:\n"                                                                                  //
    "  BufferError: A view over `body` or a part is still alive.\n"                              //
    "  Error: The request was already answered or detached, with `Status.ALREADY_EXISTS`.\n"     //
    "\n"                                                                                         //
    "Example:\n"                                                                                 //
    "  >>> @server.get(\"/videos/{name}\")\n"                                                    //
    "  ... def video(request: ucall.Request):\n"                                                 //
    "  ...     workers.submit(send_video, request.detach(), request.path_parameter(\"name\"))";

static PyObject* Request_detach(Request* self, [[maybe_unused]] PyObject* unused) {
    ucall_bytes_view_t own;
    if (request_claim_reply(self, NULL, &own) != 0) return NULL;
    ucall_received_http_request_t const handle = request_take(self);
    if (!handle) return request_raise_replied();
    PyObject* const detached = request_new(self->server, handle, &DetachedRequestType);
    if (!detached) request_restore(self, handle);
    return detached;
}

#pragma endregion Requests

#pragma region Reply Parts

/** Reads a non-negative 64-bit offset or length into @p output, leaving it untouched for NULL. */
static int range_field_from_object(PyObject* object, char const* field, uint64_t* output) {
    if (!object) return 0;
    if (!PyLong_Check(object)) {
        PyErr_Format(PyExc_TypeError, "'%s' must be a non-negative int, got %s", field, Py_TYPE(object)->tp_name);
        return -1;
    }
    unsigned long long const value = PyLong_AsUnsignedLongLong(object);
    if (value == (unsigned long long)-1 && PyErr_Occurred()) return -1;
    *output = (uint64_t)value;
    return 0;
}

static char const doc_File[] =                                                                   //
    "File(descriptor, offset=0, length=0)\n"                                                     //
    "\n"                                                                                         //
    "A byte range of a file the caller opened, as one part of `DetachedRequest.reply_parts`.\n"  //
    "\n"                                                                                         //
    "The event loop reads it unbuffered after the call returns, so the reply defers, and the\n"  //
    "`Deferred` keeps this part, and through it a file object, alive until it is final. UCall\n" //
    "never closes the descriptor.\n"                                                             //
    "\n"                                                                                         //
    "Args:\n"                                                                                    //
    "  descriptor (int | HasFileno): A regular file opened with `os.O_DIRECT`, or an object\n"   //
    "    whose `fileno()` answers one.\n"                                                        //
    "  offset (int, optional): The range's first byte. Defaults to 0.\n"                         //
    "  length (int, optional): The range's byte count; 0 sends through the end of the file.\n"   //
    "\n"                                                                                         //
    "Example:\n"                                                                                 //
    "  >>> part = ucall.File(os.open(\"/srv/videos/intro.mp4\", os.O_RDONLY | os.O_DIRECT))";

static PyObject* File_new(PyTypeObject* type, PyObject* positional, PyObject* keywords) {
    PyObject *descriptor = NULL, *offset = NULL, *length = NULL;
    ucall_py_argument_t const arguments[] = {{"descriptor", &descriptor}, {"offset", &offset}, {"length", &length}};
    if (ucall_py_parse_tuple("File", positional, keywords, 1, 3, arguments, 3) != 0) return NULL;
    ucall_file_range_t range = {0};
    range.file_descriptor = PyObject_AsFileDescriptor(descriptor);
    if (range.file_descriptor < 0 || range_field_from_object(offset, "offset", &range.offset) != 0 ||
        range_field_from_object(length, "length", &range.length) != 0)
        return NULL;
    File* const self = (File*)type->tp_alloc(type, 0);
    if (!self) return NULL;
    self->descriptor = Py_NewRef(descriptor);
    self->range = range;
    return (PyObject*)self;
}

static void File_dealloc(File* self) {
    Py_CLEAR(self->descriptor);
    Py_TYPE(self)->tp_free((PyObject*)self);
}

static PyMemberDef File_members[] = {
    {"descriptor", Py_T_OBJECT_EX, offsetof(File, descriptor), Py_READONLY, "The descriptor or its file object."},
    {"offset", Py_T_ULONGLONG, offsetof(File, range.offset), Py_READONLY, "The range's first byte."},
    {"length", Py_T_ULONGLONG, offsetof(File, range.length), Py_READONLY, "The range's bytes; 0 runs to the end."},
    {NULL, 0, 0, 0, NULL},
};

PyTypeObject FileType = {
    PyVarObject_HEAD_INIT(NULL, 0).tp_name = "ucall.File",
    .tp_basicsize = sizeof(File),
    .tp_flags = Py_TPFLAGS_DEFAULT,
    .tp_doc = doc_File,
    .tp_new = File_new,
    .tp_dealloc = (destructor)File_dealloc,
    .tp_members = File_members,
};

static char const doc_Path[] =                                                                     //
    "Path(directory, path, offset=0, length=0)\n"                                                  //
    "\n"                                                                                           //
    "A byte range of a file beneath a reply directory, as one part of `reply_parts`.\n"            //
    "\n"                                                                                           //
    "The event loop opens it unbuffered beneath the directory and closes it once sent, so the\n"   //
    "reply defers. Absolute paths, \"..\" and any resolution leaving the directory are refused.\n" //
    "\n"                                                                                           //
    "Args:\n"                                                                                      //
    "  directory (int): A position in the `reply_directories` of the interface the request\n"      //
    "    arrived on.\n"                                                                            //
    "  path (str | bytes | os.PathLike): The file beneath that directory.\n"                       //
    "  offset (int, optional): The range's first byte. Defaults to 0.\n"                           //
    "  length (int, optional): The range's byte count; 0 sends through the end of the file.\n"     //
    "\n"                                                                                           //
    "Example:\n"                                                                                   //
    "  >>> part = ucall.Path(0, \"intro.mp4\", offset=1 << 20)";

static PyObject* Path_new(PyTypeObject* type, PyObject* positional, PyObject* keywords) {
    PyObject *directory = NULL, *path = NULL, *offset = NULL, *length = NULL;
    ucall_py_argument_t const arguments[] = {{"directory", &directory},
                                             {"path", &path},
                                             {"offset", &offset},
                                             {"length", &length}};
    if (ucall_py_parse_tuple("Path", positional, keywords, 2, 4, arguments, 4) != 0) return NULL;
    ucall_path_range_t range = {0};
    if (ucall_py_size_from_object(directory, "directory", &range.directory_index) != 0 ||
        range_field_from_object(offset, "offset", &range.offset) != 0 ||
        range_field_from_object(length, "length", &range.length) != 0)
        return NULL;
    PyObject* const name = PyOS_FSPath(path);
    if (!name) return NULL;
    Path* const self = ucall_py_text_from_object(name, "path", &range.relative_path) == 0
                           ? (Path*)type->tp_alloc(type, 0)
                           : NULL;
    if (!self) {
        Py_DECREF(name);
        return NULL;
    }
    self->path = name;
    self->range = range;
    return (PyObject*)self;
}

static void Path_dealloc(Path* self) {
    Py_CLEAR(self->path);
    Py_TYPE(self)->tp_free((PyObject*)self);
}

static PyMemberDef Path_members[] = {
    {"directory", Py_T_PYSSIZET, offsetof(Path, range.directory_index), Py_READONLY,
     "The position of the reply directory."},
    {"path", Py_T_OBJECT_EX, offsetof(Path, path), Py_READONLY, "The file beneath the directory."},
    {"offset", Py_T_ULONGLONG, offsetof(Path, range.offset), Py_READONLY, "The range's first byte."},
    {"length", Py_T_ULONGLONG, offsetof(Path, range.length), Py_READONLY, "The range's bytes; 0 runs to the end."},
    {NULL, 0, 0, 0, NULL},
};

PyTypeObject PathType = {
    PyVarObject_HEAD_INIT(NULL, 0).tp_name = "ucall.Path",
    .tp_basicsize = sizeof(Path),
    .tp_flags = Py_TPFLAGS_DEFAULT,
    .tp_doc = doc_Path,
    .tp_new = Path_new,
    .tp_dealloc = (destructor)Path_dealloc,
    .tp_members = Path_members,
};

/** The parts one reply call lays out on the stack, past which it takes them from the heap. */
enum { inline_reply_parts_k = 16 };

/** The parts one reply call borrows: the C array, and the buffer of each bytes part. */
typedef struct reply_parts_t {

    /** The fast sequence of parts, keeping each alive for the call. */
    PyObject* sequence;

    /** One part per entry of @c sequence, @c inline_parts or on the heap. */
    ucall_reply_part_t* parts;

    /** The buffer of each bytes part, its @c obj NULL for the others. */
    Py_buffer* buffers;

    /** Entries filled in @c parts and @c buffers. */
    size_t count;

    /** File and path parts, which make the reply defer. */
    size_t deferring_count;

    ucall_reply_part_t inline_parts[inline_reply_parts_k];
    Py_buffer inline_buffers[inline_reply_parts_k];
} reply_parts_t;

/** Returns what @c reply_parts_from_object took. */
static void reply_parts_release(reply_parts_t* source) {
    for (size_t index = 0; index != source->count; ++index)
        if (source->buffers[index].obj) PyBuffer_Release(&source->buffers[index]);
    if (source->parts != source->inline_parts) {
        PyMem_Free(source->parts);
        PyMem_Free(source->buffers);
    }
    Py_CLEAR(source->sequence);
}

/** Lays out @p object, a sequence of bytes-like objects, @c File and @c Path parts, as C parts. */
static int reply_parts_from_object(PyObject* object, reply_parts_t* source) {
    source->parts = source->inline_parts;
    source->buffers = source->inline_buffers;
    source->count = source->deferring_count = 0;
    source->sequence = PySequence_Fast(object, "'parts' must be a sequence of bytes-like objects, Files and Paths");
    if (!source->sequence) return -1;
    size_t const count = (size_t)PySequence_Fast_GET_SIZE(source->sequence);
    if (count > inline_reply_parts_k) {
        source->parts = PyMem_Calloc(count, sizeof(ucall_reply_part_t));
        source->buffers = PyMem_Calloc(count, sizeof(Py_buffer));
        if (!source->parts || !source->buffers) {
            PyErr_NoMemory();
            reply_parts_release(source);
            return -1;
        }
    }
    for (; source->count != count; ++source->count) {
        PyObject* const item = PySequence_Fast_GET_ITEM(source->sequence, (Py_ssize_t)source->count);
        ucall_reply_part_t* const part = &source->parts[source->count];
        Py_buffer* const buffer = &source->buffers[source->count];
        buffer->obj = NULL;
        if (Py_IS_TYPE(item, &FileType)) {
            part->kind = ucall_reply_part_file_k;
            part->data.file = ((File*)item)->range;
            ++source->deferring_count;
        }
        else if (Py_IS_TYPE(item, &PathType)) {
            part->kind = ucall_reply_part_path_k;
            part->data.path = ((Path*)item)->range;
            ++source->deferring_count;
        }
        else if (PyObject_GetBuffer(item, buffer, PyBUF_SIMPLE) == 0) {
            part->kind = ucall_reply_part_bytes_k;
            part->data.bytes = (ucall_bytes_view_t) {buffer->buf, (size_t)buffer->len};
        }
        else {
            buffer->obj = NULL;
            reply_parts_release(source);
            return -1;
        }
    }
    return 0;
}

/** Appends every @c File part of @p source to @p files, which keeps them until the reply is
 *  final. */
static int reply_parts_keep_files(reply_parts_t const* source, PyObject* files) {
    for (size_t index = 0; index != source->count; ++index) {
        PyObject* const item = PySequence_Fast_GET_ITEM(source->sequence, (Py_ssize_t)index);
        if (Py_IS_TYPE(item, &FileType) && PyList_Append(files, item) != 0) return -1;
    }
    return 0;
}

#pragma endregion Reply Parts

#pragma region Deferred Replies

/** A @c Deferred keeping @p files, its outcome final until a reply call takes its address. */
static Deferred* deferred_new(PyObject* files) {
    Deferred* const deferred = PyObject_New(Deferred, &DeferredType);
    if (!deferred) return NULL;
    deferred->outcome = (ucall_outcome_t) {0};
    deferred->files = Py_NewRef(files);
    return deferred;
}

static void Deferred_dealloc(Deferred* self) {
    // The event loop writes the outcome and reads the files until final, so both outlive that.
    Py_BEGIN_ALLOW_THREADS;
    ucall_outcome_wait(&self->outcome);
    Py_END_ALLOW_THREADS;
    Py_CLEAR(self->files);
    PyObject_Free(self);
}

static char const doc_Deferred_status[] =                                        //
    "status() -> Status\n"                                                       //
    "\n"                                                                         //
    "Reads the reply's outcome without waiting.\n"                               //
    "\n"                                                                         //
    "Returns:\n"                                                                 //
    "  Status: `Status.DEFERRED` while parts still send, then the final one.\n"  //
    "\n"                                                                         //
    "Example:\n"                                                                 //
    "  >>> deferred.status() in [ucall.Status.DEFERRED, ucall.Status.SUCCESS]\n" //
    "  True";

static PyObject* Deferred_status(Deferred* self, [[maybe_unused]] PyObject* unused) {
    return ucall_py_enum_to_object(&ucall_py_status_enum, (long)ucall_outcome_status(&self->outcome));
}

static char const doc_Deferred_wait[] =                                                          //
    "wait() -> None\n"                                                                           //
    "\n"                                                                                         //
    "Blocks until every part is sent, without the interpreter lock.\n"                           //
    "\n"                                                                                         //
    "Raises:\n"                                                                                  //
    "  Error: The reply failed, such as `Status.NOT_FOUND` for a missing file, which answered\n" //
    "    404, or `Status.CONNECTION_CLOSED` for a peer that left.\n"                             //
    "\n"                                                                                         //
    "Example:\n"                                                                                 //
    "  >>> deferred.wait()";

static PyObject* Deferred_wait(Deferred* self, [[maybe_unused]] PyObject* unused) {
    Py_BEGIN_ALLOW_THREADS;
    ucall_outcome_wait(&self->outcome);
    Py_END_ALLOW_THREADS;
    if (ucall_py_raise_outcome(&self->outcome) != 0) return NULL;
    Py_RETURN_NONE;
}

/** @c await @c deferred runs @c wait in the running loop's default executor. */
static PyObject* Deferred_await(Deferred* self) {
    PyObject* const asyncio = PyImport_ImportModule("asyncio");
    PyObject* const loop = asyncio ? PyObject_CallMethod(asyncio, "get_running_loop", NULL) : NULL;
    PyObject* const wait = loop ? PyObject_GetAttrString((PyObject*)self, "wait") : NULL;
    PyObject* const future = wait ? PyObject_CallMethod(loop, "run_in_executor", "OO", Py_None, wait) : NULL;
    PyObject* const awaiting = future ? PyObject_CallMethod(future, "__await__", NULL) : NULL;
    Py_XDECREF(future);
    Py_XDECREF(wait);
    Py_XDECREF(loop);
    Py_XDECREF(asyncio);
    return awaiting;
}

static PyAsyncMethods Deferred_async = {.am_await = (unaryfunc)Deferred_await};

static PyMethodDef Deferred_methods[] = {
    {"status", (PyCFunction)Deferred_status, METH_NOARGS, doc_Deferred_status},
    {"wait", (PyCFunction)Deferred_wait, METH_NOARGS, doc_Deferred_wait},
    {NULL, NULL, 0, NULL},
};

static char const doc_Deferred[] =                                                                    //
    "A reply still sending file or path parts, from `reply_parts` or `ReplyStream.end`.\n"            //
    "\n"                                                                                              //
    "It owns the reply's outcome and keeps the `File` parts it borrows alive until the outcome is\n"  //
    "final. `await` it in a coroutine, or call `wait()`; released unfinished, it waits, so keep it\n" //
    "off the polling thread, as `Request.detach` does.\n"                                             //
    "\n"                                                                                              //
    "Example:\n"                                                                                      //
    "  >>> deferred = detached.reply_parts([b\"--frame\\r\\n\", ucall.Path(0, \"intro.mp4\")])\n"     //
    "  >>> deferred.wait()  # or: await deferred";

PyTypeObject DeferredType = {
    PyVarObject_HEAD_INIT(NULL, 0).tp_name = "ucall.Deferred",
    .tp_basicsize = sizeof(Deferred),
    .tp_flags = Py_TPFLAGS_DEFAULT,
    .tp_doc = doc_Deferred,
    .tp_dealloc = (destructor)Deferred_dealloc,
    .tp_as_async = &Deferred_async,
    .tp_methods = Deferred_methods,
};

#pragma endregion Deferred Replies

#pragma region Detached Requests

static char const doc_DetachedRequest_reply_parts[] =                                                 //
    "reply_parts(parts, status=200, headers=()) -> Deferred | None\n"                                 //
    "\n"                                                                                              //
    "Answers the request, once, with `parts` concatenated into the body.\n"                           //
    "\n"                                                                                              //
    "Bytes-like parts are copied before the call returns, and the reply is then final. A `File` or\n" //
    "`Path` part is read by the event loop afterwards, sized first so Content-Length is measured,\n"  //
    "and its reply defers: one failing before the head replaces the reply with 404 or 416, and one\n" //
    "failing after it resets the connection.\n"                                                       //
    "\n"                                                                                              //
    "Args:\n"                                                                                         //
    "  parts (Sequence[Buffer | File | Path]): The body, in order.\n"                                 //
    "  status (int, optional): The HTTP status. Defaults to 200.\n"                                   //
    "  headers (Sequence[str | bytes], optional): \"name: value\" lines; the server adds\n"           //
    "    Content-Length, Date and Server itself.\n"                                                   //
    "\n"                                                                                              //
    "Returns:\n"                                                                                      //
    "  Deferred | None: The `Deferred` of a reply with file or path parts, which may already be\n"    //
    "    final, or None for bytes alone, final on return.\n"                                          //
    "\n"                                                                                              //
    "Raises:\n"                                                                                       //
    "  BufferError: A view over the request's bytes is still alive.\n"                                //
    "  Error: A refused part, such as a descriptor without O_DIRECT, or a request already\n"          //
    "    answered, with `Status.ALREADY_EXISTS`.\n"                                                   //
    "\n"                                                                                              //
    "Example:\n"                                                                                      //
    "  >>> deferred = detached.reply_parts([b\"--frame\\r\\n\", ucall.Path(0, \"intro.mp4\")])\n"     //
    "  >>> deferred.wait()  # or: await deferred";

static PyObject* DetachedRequest_reply_parts(Request* self, PyObject* const* values, Py_ssize_t count,
                                             PyObject* names) {
    PyObject *parts = NULL, *status = NULL, *headers = NULL;
    ucall_py_argument_t const arguments[] = {{"parts", &parts}, {"status", &status}, {"headers", &headers}};
    if (ucall_py_parse_fast("reply_parts", values, count, names, 1, 3, arguments, 3) != 0) return NULL;
    size_t http_status = ucall_http_status_ok_k;
    ucall_bytes_view_t own;
    if (ucall_py_size_from_object(status, "status", &http_status) != 0 || request_claim_reply(self, NULL, &own) != 0)
        return NULL;
    ucall_py_header_lines_t lines;
    if (ucall_py_header_lines_from_object(headers, &lines) != 0) return NULL;
    reply_parts_t source;
    if (reply_parts_from_object(parts, &source) != 0) {
        ucall_py_header_lines_release(&lines);
        return NULL;
    }
    // Memory-only replies are final on return, so only file and path parts need an outcome
    // on the heap.
    PyObject* const files = source.deferring_count ? PyList_New(0) : NULL;
    Deferred* const deferred = files && reply_parts_keep_files(&source, files) == 0 ? deferred_new(files) : NULL;
    Py_XDECREF(files);
    PyObject* answer = NULL;
    ucall_received_http_request_t const handle = deferred || !source.deferring_count ? request_take(self) : NULL;
    if (handle) {
        ucall_outcome_t final = {0};
        ucall_outcome_t* const outcome = deferred ? &deferred->outcome : &final;
        ucall_server_reply_vectored_t reply = {
            self->server->handle, outcome,     handle,       (ucall_http_status_t)http_status,
            lines.views,          lines.count, source.parts, source.count,
        };
        ucall_server_reply_vectored(&reply);
        answer = deferred ? request_defer_reply(self, handle, deferred) : request_finish_reply(self, handle, &final);
    }
    else if (deferred || !source.deferring_count) request_raise_replied();
    reply_parts_release(&source);
    ucall_py_header_lines_release(&lines);
    Py_XDECREF(deferred);
    return answer;
}

static char const doc_DetachedRequest_reply_stream[] =                                             //
    "reply_stream(status=200, headers=()) -> ReplyStream\n"                                        //
    "\n"                                                                                           //
    "Answers the request with a body sent in parts, emitting the status line and headers now.\n"   //
    "\n"                                                                                           //
    "The body is chunked for HTTP/1.1 peers, unless `headers` declare Content-Length, which the\n" //
    "parts must then sum to. A peer that left already still opens the stream, whose parts drop.\n" //
    "\n"                                                                                           //
    "Args:\n"                                                                                      //
    "  status (int, optional): The HTTP status. Defaults to 200.\n"                                //
    "  headers (Sequence[str | bytes], optional): \"name: value\" lines.\n"                        //
    "\n"                                                                                           //
    "Returns:\n"                                                                                   //
    "  ReplyStream: The open reply, which owns the request from then on.\n"                        //
    "\n"                                                                                           //
    "Raises:\n"                                                                                    //
    "  BufferError: A view over the request's bytes is still alive.\n"                             //
    "  Error: A malformed header, or a request already answered, with `Status.ALREADY_EXISTS`.\n"  //
    "\n"                                                                                           //
    "Example:\n"                                                                                   //
    "  >>> stream = detached.reply_stream(headers=(\"content-type: text/event-stream\",))\n"       //
    "  >>> stream.append([b\"data: 1\\n\\n\"])\n"                                                  //
    "  >>> stream.end()";

static PyObject* DetachedRequest_reply_stream(Request* self, PyObject* const* values, Py_ssize_t count,
                                              PyObject* names) {
    PyObject *status = NULL, *headers = NULL;
    ucall_py_argument_t const arguments[] = {{"status", &status}, {"headers", &headers}};
    if (ucall_py_parse_fast("reply_stream", values, count, names, 0, 2, arguments, 2) != 0) return NULL;
    size_t http_status = ucall_http_status_ok_k;
    ucall_bytes_view_t own;
    if (ucall_py_size_from_object(status, "status", &http_status) != 0 || request_claim_reply(self, NULL, &own) != 0)
        return NULL;
    ucall_py_header_lines_t lines;
    if (ucall_py_header_lines_from_object(headers, &lines) != 0) return NULL;
    ReplyStream* const stream = PyObject_New(ReplyStream, &ReplyStreamType);
    if (stream) {
        stream->handle = NULL;
        stream->server = (Server*)Py_NewRef(self->server);
        stream->files = PyList_New(0);
        stream->deferring_count = 0;
    }
    PyObject* opened = NULL;
    ucall_received_http_request_t const handle = stream && stream->files ? request_take(self) : NULL;
    if (handle) {
        ucall_outcome_t outcome = {0};
        ucall_server_reply_begin_t begin = {
            self->server->handle, &outcome, handle, (ucall_http_status_t)http_status, lines.views, lines.count,
        };
        ucall_server_reply_begin(&begin);
        ucall_status_t const begun = ucall_outcome_status(&outcome);
        if (begun == ucall_status_success_k || begun == ucall_status_connection_closed_k) {
            stream->handle = handle;
            opened = Py_NewRef((PyObject*)stream);
        }
        else {
            request_restore(self, handle);
            ucall_py_raise_outcome(&outcome);
        }
    }
    else if (stream && stream->files) request_raise_replied();
    ucall_py_header_lines_release(&lines);
    Py_XDECREF(stream);
    return opened;
}

static char const doc_DetachedRequest_body_chunks[] =                                               //
    "body_chunks() -> BodyChunks\n"                                                                 //
    "\n"                                                                                            //
    "Iterates the request body as it arrives, each chunk the bytes decoded since the last pull.\n"  //
    "\n"                                                                                            //
    "Each chunk is a read-only memoryview valid until the next pull, which releases it, and a\n"    //
    "pull waits for bytes without the interpreter lock. On a buffered endpoint the first chunk\n"   //
    "is the whole body.\n"                                                                          //
    "\n"                                                                                            //
    "Returns:\n"                                                                                    //
    "  BodyChunks: The iterator, ending once the body did.\n"                                       //
    "\n"                                                                                            //
    "Raises:\n"                                                                                     //
    "  BufferError: From a pull, while a view derived from the last chunk is still alive.\n"        //
    "  Error: From a pull, `Status.CONNECTION_CLOSED` or `Status.MALFORMED` for a body cut short\n" //
    "    or badly framed, or `Status.WOULD_BLOCK` on the polling thread with nothing decoded.\n"    //
    "\n"                                                                                            //
    "Example:\n"                                                                                    //
    "  >>> for chunk in detached.body_chunks():\n"                                                  //
    "  ...     digest.update(chunk)";

static PyObject* DetachedRequest_body_chunks(Request* self, [[maybe_unused]] PyObject* unused) {
    if (request_live(self) != 0) return NULL;
    BodyChunks* const chunks = PyObject_New(BodyChunks, &BodyChunksType);
    if (!chunks) return NULL;
    chunks->request = (Request*)Py_NewRef(self);
    chunks->chunk = NULL;
    return (PyObject*)chunks;
}

#pragma endregion Detached Requests

#pragma region Reply Streams

static void ReplyStream_dealloc(ReplyStream* self) {
    if (self->handle) {
        ucall_outcome_t outcome = {0};
        ucall_server_reply_end_t end = {self->server->handle, &outcome, self->handle};
        ucall_server_reply_end(&end);
        Py_BEGIN_ALLOW_THREADS;
        ucall_outcome_wait(&outcome);
        Py_END_ALLOW_THREADS;
    }
    Py_CLEAR(self->files);
    Py_CLEAR(self->server);
    PyObject_Free(self);
}

static int reply_stream_live(ReplyStream* self) {
    if (self->handle) return 0;
    ucall_py_raise_status(ucall_status_already_exists_k, "the stream already ended");
    return -1;
}

static char const doc_ReplyStream_append[] =                                                  //
    "append(parts, /) -> None\n"                                                              //
    "\n"                                                                                      //
    "Queues `parts` after the ones before, all of them or none.\n"                            //
    "\n"                                                                                      //
    "Bytes-like parts are copied before the call returns; `File` parts stay alive with the\n" //
    "stream until its end is final.\n"                                                        //
    "\n"                                                                                      //
    "Args:\n"                                                                                 //
    "  parts (Sequence[Buffer | File | Path]): The next parts of the body.\n"                 //
    "\n"                                                                                      //
    "Raises:\n"                                                                               //
    "  Error: `Status.WOULD_BLOCK` while the peer lags, to retry once it caught up, or\n"     //
    "    `Status.CONNECTION_CLOSED` once it left; nothing was queued either way.\n"           //
    "\n"                                                                                      //
    "Example:\n"                                                                              //
    "  >>> stream.append([b\"data: \", payload, b\"\\n\\n\"])";

static PyObject* ReplyStream_append(ReplyStream* self, PyObject* parts) {
    if (reply_stream_live(self) != 0) return NULL;
    reply_parts_t source;
    if (reply_parts_from_object(parts, &source) != 0) return NULL;
    // Kept before the call, since a refused append queues nothing and the extra
    // references are harmless.
    int appended = reply_parts_keep_files(&source, self->files);
    if (appended == 0) {
        ucall_outcome_t outcome = {0};
        ucall_server_reply_append_t append = {self->server->handle, &outcome, self->handle, source.parts, source.count};
        ucall_server_reply_append(&append);
        appended = ucall_py_raise_outcome(&outcome);
    }
    if (appended == 0) self->deferring_count += source.deferring_count;
    reply_parts_release(&source);
    if (appended != 0) return NULL;
    Py_RETURN_NONE;
}

static char const doc_ReplyStream_end[] =                                                       //
    "end() -> Deferred | None\n"                                                                //
    "\n"                                                                                        //
    "Completes the reply, consuming the request whatever happens.\n"                            //
    "\n"                                                                                        //
    "Returns:\n"                                                                                //
    "  Deferred | None: The `Deferred` of a stream that appended file or path parts, which\n"   //
    "    may already be final, or None for bytes alone.\n"                                      //
    "\n"                                                                                        //
    "Raises:\n"                                                                                 //
    "  Error: The parts fell short of a declared Content-Length, with `Status.MALFORMED`, or\n" //
    "    the stream already ended, with `Status.ALREADY_EXISTS`.\n"                             //
    "\n"                                                                                        //
    "Example:\n"                                                                                //
    "  >>> deferred = stream.end()";

static PyObject* ReplyStream_end(ReplyStream* self, [[maybe_unused]] PyObject* unused) {
    if (reply_stream_live(self) != 0) return NULL;
    Deferred* const deferred = self->deferring_count ? deferred_new(self->files) : NULL;
    if (self->deferring_count && !deferred) return NULL;
    ucall_py_section_t section;
    ucall_py_section_begin(&section, (PyObject*)self);
    ucall_received_http_request_t const handle = self->handle;
    self->handle = NULL;
    ucall_py_section_end(&section);
    if (!handle) {
        Py_XDECREF(deferred);
        return ucall_py_raise_status(ucall_status_already_exists_k, "the stream already ended");
    }
    ucall_outcome_t final = {0};
    ucall_server_reply_end_t end = {self->server->handle, deferred ? &deferred->outcome : &final, handle};
    ucall_server_reply_end(&end);
    if (deferred) return (PyObject*)deferred;
    ucall_status_t const status = ucall_outcome_status(&final);
    if (status == ucall_status_success_k || status == ucall_status_connection_closed_k) Py_RETURN_NONE;
    ucall_py_raise_outcome(&final);
    return NULL;
}

static PyMethodDef ReplyStream_methods[] = {
    {"append", (PyCFunction)ReplyStream_append, METH_O, doc_ReplyStream_append},
    {"end", (PyCFunction)ReplyStream_end, METH_NOARGS, doc_ReplyStream_end},
    {NULL, NULL, 0, NULL},
};

static char const doc_ReplyStream[] =                                                            //
    "A reply sent in parts, from `DetachedRequest.reply_stream`, ended once.\n"                  //
    "\n"                                                                                         //
    "Released without `end()`, it ends the reply itself and waits for any file parts to send.\n" //
    "\n"                                                                                         //
    "Example:\n"                                                                                 //
    "  >>> stream = detached.reply_stream(headers=(\"content-type: application/x-ndjson\",))\n"  //
    "  >>> for row in rows:\n"                                                                   //
    "  ...     stream.append([json.dumps(row).encode(), b\"\\n\"])\n"                            //
    "  >>> stream.end()";

PyTypeObject ReplyStreamType = {
    PyVarObject_HEAD_INIT(NULL, 0).tp_name = "ucall.ReplyStream",
    .tp_basicsize = sizeof(ReplyStream),
    .tp_flags = Py_TPFLAGS_DEFAULT,
    .tp_doc = doc_ReplyStream,
    .tp_dealloc = (destructor)ReplyStream_dealloc,
    .tp_methods = ReplyStream_methods,
};

#pragma endregion Reply Streams

#pragma region Body Chunks

/** Releases the chunk the last pull yielded, so a view of it the caller kept reads nothing. */
static int body_chunks_release(BodyChunks* self) {
    PyObject* const chunk = self->chunk;
    if (!chunk) return 0;
    self->chunk = NULL;
    PyObject* const released = PyObject_CallMethod(chunk, "release", NULL);
    Py_DECREF(chunk);
    Py_XDECREF(released);
    return released ? 0 : -1;
}

static PyObject* BodyChunks_next(BodyChunks* self) {
    Request* const request = self->request;
    if (body_chunks_release(self) != 0 || request_live(request) != 0) return NULL;
    if (request->exports)
        return PyErr_Format(PyExc_BufferError,
                            "%zd views over the request's bytes are alive, and the next pull would free them; " //
                            "drop them or copy with bytes() first",
                            request->exports);
    ucall_outcome_t outcome = {0};
    ucall_bytes_view_t data = {0};
    ucall_server_request_body_chunk_t pull = {request->server->handle, &outcome, request->handle, &data};
    ucall_server_request_body_chunk(&pull);
    if (ucall_outcome_status(&outcome) == ucall_status_deferred_k) {
        Py_BEGIN_ALLOW_THREADS;
        ucall_outcome_wait(&outcome);
        Py_END_ALLOW_THREADS;
    }
    if (ucall_py_raise_outcome(&outcome) != 0 || !data.length) return NULL;
    self->chunk = request_bytes_view(request, data);
    return Py_XNewRef(self->chunk);
}

static void BodyChunks_dealloc(BodyChunks* self) {
    // Releasing may run while an exception unwinds past the iterator, which must survive it.
    PyObject* const pending = PyErr_GetRaisedException();
    if (body_chunks_release(self) != 0) PyErr_Clear();
    PyErr_SetRaisedException(pending);
    Py_CLEAR(self->request);
    PyObject_Free(self);
}

static char const doc_BodyChunks[] =                                                          //
    "The iterator `DetachedRequest.body_chunks` returns, yielding memoryviews of the body.\n" //
    "\n"                                                                                      //
    "Example:\n"                                                                              //
    "  >>> received = sum(len(chunk) for chunk in detached.body_chunks())";

PyTypeObject BodyChunksType = {
    PyVarObject_HEAD_INIT(NULL, 0).tp_name = "ucall.BodyChunks",
    .tp_basicsize = sizeof(BodyChunks),
    .tp_flags = Py_TPFLAGS_DEFAULT,
    .tp_doc = doc_BodyChunks,
    .tp_dealloc = (destructor)BodyChunks_dealloc,
    .tp_iter = PyObject_SelfIter,
    .tp_iternext = (iternextfunc)BodyChunks_next,
};

#pragma endregion Body Chunks

#pragma region Request Types

static PyMethodDef Request_methods[] = {
    {"header", (PyCFunction)Request_header, METH_O, doc_Request_header},
    {"fields", (PyCFunction)Request_fields, METH_NOARGS, doc_Request_fields},
    {"query", (PyCFunction)Request_query, METH_O, doc_Request_query},
    {"path_parameter", (PyCFunction)Request_path_parameter, METH_O, doc_Request_path_parameter},
    {"reply", (PyCFunction)(void (*)(void))Request_reply, ucall_py_method_flags_k, doc_Request_reply},
    {"reply_error", (PyCFunction)(void (*)(void))Request_reply_error, ucall_py_method_flags_k, doc_Request_reply_error},
    {"detach", (PyCFunction)Request_detach, METH_NOARGS, doc_Request_detach},
    {NULL, NULL, 0, NULL},
};

static PyMethodDef DetachedRequest_methods[] = {
    {"header", (PyCFunction)Request_header, METH_O, doc_Request_header},
    {"fields", (PyCFunction)Request_fields, METH_NOARGS, doc_Request_fields},
    {"query", (PyCFunction)Request_query, METH_O, doc_Request_query},
    {"path_parameter", (PyCFunction)Request_path_parameter, METH_O, doc_Request_path_parameter},
    {"reply", (PyCFunction)(void (*)(void))Request_reply, ucall_py_method_flags_k, doc_Request_reply},
    {"reply_error", (PyCFunction)(void (*)(void))Request_reply_error, ucall_py_method_flags_k, doc_Request_reply_error},
    {"reply_parts", (PyCFunction)(void (*)(void))DetachedRequest_reply_parts, ucall_py_method_flags_k,
     doc_DetachedRequest_reply_parts},
    {"reply_stream", (PyCFunction)(void (*)(void))DetachedRequest_reply_stream, ucall_py_method_flags_k,
     doc_DetachedRequest_reply_stream},
    {"body_chunks", (PyCFunction)DetachedRequest_body_chunks, METH_NOARGS, doc_DetachedRequest_body_chunks},
    {NULL, NULL, 0, NULL},
};

static PyGetSetDef Request_getset[] = {
    {"verb", (getter)Request_get_verb, NULL, "The `Verb` it arrived with, never `Verb.ANY`.", NULL},
    {"path", (getter)Request_get_path, NULL, "The path as sent, still percent-encoded, without the query.", NULL},
    {"query_string", (getter)Request_get_query_string, NULL,
     "The query after the first `?`, still percent-encoded, or \"\" without one.", NULL},
    {"body", (getter)Request_get_body, NULL, "A read-only memoryview of the body, valid until the reply.", NULL},
    {"peer", (getter)Request_get_peer, NULL,
     "The index of the interface it arrived on, the peer's 32-byte Noise key, zeros on plaintext, " //
     "and its address: (ipaddress, port), \"\" for AF_UNIX, or None.",
     NULL},
    {"parts", (getter)Request_get_parts, NULL, "The `RequestPart`s of a multipart/form-data body, else empty.", NULL},
    {"path_segments", (getter)Request_get_path_segments, NULL, "The path's components between slashes, as sent.", NULL},
    {NULL, NULL, NULL, NULL, NULL},
};

static char const doc_Request[] =                                                                      //
    "One received HTTP request, retained until a reply consumes it.\n"                                 //
    "\n"                                                                                               //
    "A handler taking one parameter annotated `Request` receives it on the polling thread, and may\n"  //
    "keep it to answer later from any thread, once, or `detach` it to a worker for the replies that\n" //
    "may defer. `body`, `parts` and the buffer protocol view the received bytes without a copy\n"      //
    "until the reply, which is refused while such a view is alive, except the `body` passed as the\n"  //
    "reply body itself. A request released without a reply answers 500.\n"                             //
    "\n"                                                                                               //
    "Example:\n"                                                                                       //
    "  >>> @server.put(\"/echo/{name}\")\n"                                                            //
    "  ... def echo(request: ucall.Request):\n"                                                        //
    "  ...     interface_index, static_key = request.peer\n"                                           //
    "  ...     greeting = f\"{request.verb.name} {request.path_parameter('name')}\"\n"                 //
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

static char const doc_DetachedRequest[] =                                                              //
    "A request taken off its polling thread by `Request.detach`, owning the replies that may defer.\n" //
    "\n"                                                                                               //
    "It reads and answers as `Request` does, and alone offers `reply_parts`, `reply_stream` and\n"     //
    "`body_chunks`, whose `Deferred` replies and waiting pulls belong on a worker thread. Released\n"  //
    "without a reply, it answers 500.\n"                                                               //
    "\n"                                                                                               //
    "Example:\n"                                                                                       //
    "  >>> def send_video(detached: ucall.DetachedRequest, name: str):\n"                              //
    "  ...     deferred = detached.reply_parts([b\"--frame\\r\\n\", ucall.Path(0, name)])\n"           //
    "  ...     deferred.wait()  # or: await deferred";

PyTypeObject DetachedRequestType = {
    PyVarObject_HEAD_INIT(NULL, 0).tp_name = "ucall.DetachedRequest",
    .tp_basicsize = sizeof(Request),
    .tp_flags = Py_TPFLAGS_DEFAULT,
    .tp_doc = doc_DetachedRequest,
    .tp_dealloc = (destructor)Request_dealloc,
    .tp_as_buffer = &Request_buffer,
    .tp_methods = DetachedRequest_methods,
    .tp_getset = Request_getset,
};

#pragma endregion Request Types

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

/** Converts a query value to @p kind, percent-decoded with "+" as a space as by `unquote_plus`. */
static PyObject* scalar_from_query(ucall_bytes_view_t text, scalar_kind_t kind) {
    char inline_buffer[256];
    char* const decoded = text.length <= sizeof(inline_buffer) ? inline_buffer : PyMem_Malloc(text.length);
    if (!decoded) return PyErr_NoMemory();
    size_t length = 0;
    ucall_status_t const status = ucall_decode_percent(text, (ucall_byte_t*)decoded, &length, ucall_percent_query_k);
    PyObject* const value = status == ucall_status_success_k
                                ? scalar_from_text(decoded, length, kind, "replace")
                                : PyErr_Format(PyExc_ValueError, "a '%%' in the query lacks two hexadecimal digits");
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
    PyObject* const request = request_new(endpoint->server, handle, &RequestType);
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

    /** The endpoint the polling verbs address. */
    ucall_http_batch_endpoint_t handle;

    /** The server that registered it, NULL once a collection cleared it. */
    Server* server;

    /** The function handed each batch as a list of requests. */
    PyObject* handler;
} BatchEndpoint;

/** Runs a batch endpoint's Python handler on its polling owner's thread with a list of its
 *  requests. */
static void call_batch_endpoint(ucall_received_http_request_t const* handles, size_t count, void* context) {
    PyGILState_STATE const state = PyGILState_Ensure();
    BatchEndpoint* const endpoint = (BatchEndpoint*)context;
    PyObject* const held = PyTuple_New((Py_ssize_t)count);
    size_t created = 0;
    for (; held && created != count; ++created) {
        PyObject* const request = request_new(endpoint->server, handles[created], &RequestType);
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

static char const doc_BatchEndpoint_take_batch[] =                                                         //
    "take_batch(timeout_microseconds=0) -> None\n"                                                         //
    "\n"                                                                                                   //
    "Runs the handler on this thread if a batch is due, waiting for one at most `timeout_microseconds`.\n" //
    "\n"                                                                                                   //
    "Each batch endpoint has one polling owner, and the wait polls no event loop.\n"                       //
    "\n"                                                                                                   //
    "Args:\n"                                                                                              //
    "  timeout_microseconds (int, optional): The longest wait in microseconds; 0 checks once.\n"           //
    "\n"                                                                                                   //
    "Raises:\n"                                                                                            //
    "  Error: The server failed, or was released.\n"                                                       //
    "\n"                                                                                                   //
    "Example:\n"                                                                                           //
    "  >>> endpoint.take_batch(timeout_microseconds=1_000)";

static PyObject* BatchEndpoint_take_batch(BatchEndpoint* self, PyObject* const* values, Py_ssize_t count,
                                          PyObject* names) {
    PyObject* timeout = NULL;
    ucall_py_argument_t const arguments[] = {{"timeout_microseconds", &timeout}};
    if (ucall_py_parse_fast("take_batch", values, count, names, 0, 1, arguments, 1) != 0) return NULL;
    size_t microseconds = 0;
    if (ucall_py_size_from_object(timeout, "timeout_microseconds", &microseconds) != 0 ||
        batch_endpoint_live(self) != 0)
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
    "  >>> poller = threading.Thread(target=endpoint.take_batches)\n"                    //
    "  >>> poller.start()";

static PyObject* BatchEndpoint_take_batches(BatchEndpoint* self, [[maybe_unused]] PyObject* unused) {
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
    "Each counter is read on its own, so a snapshot of an endpoint being polled is not one\n"      //
    "instant, and batches a stop released count nowhere.\n"                                        //
    "\n"                                                                                           //
    "Returns:\n"                                                                                   //
    "  dict[str, int]: `batches` handed to the handler and the `requests` in them, then the\n"     //
    "    `filled_batches` that reached `max_size`, the `ready_batches` that reached `min_size`,\n" //
    "    and the `expired_batches` that waited out `max_latency_microseconds`.\n"                  //
    "\n"                                                                                           //
    "Example:\n"                                                                                   //
    "  >>> counters = endpoint.statistics()\n"                                                     //
    "  >>> counters[\"requests\"] / max(counters[\"batches\"], 1)\n"                               //
    "  0.0";

static PyObject* BatchEndpoint_statistics(BatchEndpoint* self, [[maybe_unused]] PyObject* unused) {
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

static char const doc_BatchEndpoint[] =                                                                   //
    "One batching route of a server, polled by one application thread.\n"                                 //
    "\n"                                                                                                  //
    "Requests matching it from every event loop share one queue, which `take_batch` and `take_batches`\n" //
    "hand to the handler as a list once enough arrived or the oldest waited long enough. The handler\n"   //
    "runs on its polling owner's thread and replies to each request, in any order.\n"                     //
    "\n"                                                                                                  //
    "Example:\n"                                                                                          //
    "  >>> @server.batch(\"/infer\", min_size=8, max_size=64, max_latency_microseconds=500)\n"            //
    "  ... def infer(requests: list[ucall.Request]):\n"                                                   //
    "  ...     for request in requests:\n"                                                                //
    "  ...         request.reply(bytes(request.body))\n"                                                  //
    "  >>> infer in server.batch_endpoints\n"                                                             //
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
    "Server(*interfaces, backend=Backend.AUTOMATIC, cpu_class=CPUClass.UNKNOWN, log=None,\n"         //
    "    log_level=LogLevel.DEBUG, log_format=LogFormat.HUMAN, metrics=None)\n"                      //
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
    "  cpu_class (CPUClass, optional): The CPU kernels. Defaults to `CPUClass.UNKNOWN`.\n"           //
    "  log (Callable[[LogLevel, str], object], optional): Receives every line the server writes,\n"  //
    "    on whichever thread wrote it, holding the interpreter lock; None writes nothing.\n"         //
    "  log_level (LogLevel, optional): The least severe line `log` receives. Defaults to DEBUG.\n"   //
    "  log_format (LogFormat, optional): How lines are spelled. Defaults to `LogFormat.HUMAN`.\n"    //
    "  metrics (Metrics, optional): Where to send StatsD datagrams; None sends none.\n"              //
    "\n"                                                                                             //
    "Raises:\n"                                                                                      //
    "  Error: An interface that cannot be bound, such as an address in use, or a reply directory\n"  //
    "    that cannot be opened.\n"                                                                   //
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

/** Views the StatsD settings of @p metrics, a @c Metrics, in @p config; @p tags keeps the tag
 *  views. */
static int server_metrics(PyObject* metrics, ucall_server_options_t* config, ucall_py_header_lines_t* tags) {
    if (!metrics) return ucall_py_header_lines_from_object(NULL, tags);
    Metrics const* const source = (Metrics const*)metrics;
    if (ucall_py_text_from_object(source->address, "address", &config->metrics_address) != 0 ||
        (source->prefix && ucall_py_text_from_object(source->prefix, "prefix", &config->metrics_prefix) != 0) ||
        ucall_py_header_lines_from_object(source->tags, tags) != 0)
        return -1;
    config->metrics_sample_rate = (float)source->sample_rate;
    config->metrics_tags = tags->views;
    config->metrics_tags_count = tags->count;
    config->metrics_interval_microseconds = (size_t)source->interval_microseconds;
    return 0;
}

static PyObject* Server_new(PyTypeObject* type, PyObject* positional, PyObject* keywords) {
    PyObject *backend = NULL, *cpu_class = NULL, *log = NULL, *log_level = NULL, *log_format = NULL, *metrics = NULL;
    ucall_py_argument_t const arguments[] = {
        {"backend", &backend},     {"cpu_class", &cpu_class},   {"log", &log},
        {"log_level", &log_level}, {"log_format", &log_format}, {"metrics", &metrics}};
    if (ucall_py_parse_tuple("Server", NULL, keywords, 0, 0, arguments, sizeof(arguments) / sizeof(arguments[0])) != 0)
        return NULL;
    ucall_server_options_t config = {0};
    int backend_value = ucall_io_backend_automatic_k, cpu_class_value = ucall_cpu_class_unknown_k;
    if (ucall_py_enum_from_object(backend, "backend", &ucall_py_backend_enum, &backend_value) != 0 ||
        ucall_py_enum_from_object(cpu_class, "cpu_class", &ucall_py_cpu_class_enum, &cpu_class_value) != 0)
        return NULL;
    config.backend = (ucall_io_backend_t)backend_value;
    config.cpu_class = (ucall_cpu_class_t)cpu_class_value;
    if (ucall_py_log_from_objects(log, log_level, log_format, &config.log) != 0) return NULL;
    if (log == Py_None) log = NULL;
    if (metrics == Py_None) metrics = NULL;
    if (metrics && !Py_IS_TYPE(metrics, &MetricsType))
        return PyErr_Format(PyExc_TypeError, "'metrics' must be a ucall.Metrics, got %s", Py_TYPE(metrics)->tp_name);
    ucall_py_header_lines_t tags;
    if (server_metrics(metrics, &config, &tags) != 0) return NULL;

    PyObject* const interfaces = server_interfaces(positional);
    if (!interfaces) {
        ucall_py_header_lines_release(&tags);
        return NULL;
    }
    Py_ssize_t const interfaces_count = PyTuple_GET_SIZE(interfaces);
    size_t directories_count = 0;
    for (Py_ssize_t index = 0; index != interfaces_count; ++index)
        directories_count += (size_t)PyTuple_GET_SIZE(
            ((Interface*)PyTuple_GET_ITEM(interfaces, index))->reply_directories);
    ucall_network_interface_t* const network_interfaces = PyMem_Calloc((size_t)interfaces_count,
                                                                       sizeof(ucall_network_interface_t));
    ucall_noise_key_t* const keys = PyMem_Calloc((size_t)interfaces_count, sizeof(ucall_noise_key_t));
    ucall_bytes_view_t* const directories = PyMem_Calloc(directories_count ? directories_count : 1,
                                                         sizeof(ucall_bytes_view_t));
    Server* const self = network_interfaces && keys && directories ? (Server*)type->tp_alloc(type, 0) : NULL;
    if (!self) {
        if (!PyErr_Occurred()) PyErr_NoMemory();
        PyMem_Free(network_interfaces);
        PyMem_Free(keys);
        PyMem_Free(directories);
        ucall_py_header_lines_release(&tags);
        Py_DECREF(interfaces);
        return NULL;
    }
    self->interfaces = interfaces;
    self->log = Py_XNewRef(log);
    self->stage = server_serving_k;
    int filled = 0;
    ucall_bytes_view_t* directory = directories;
    for (Py_ssize_t index = 0; filled == 0 && index != interfaces_count; ++index) {
        Interface const* const source = (Interface const*)PyTuple_GET_ITEM(interfaces, index);
        ucall_network_interface_t* const target = &network_interfaces[index];
        Py_ssize_t address_length = 0, device_length = 0;
        char const* const address = PyUnicode_AsUTF8AndSize(source->address, &address_length);
        char const* const device = source->device_name ? PyUnicode_AsUTF8AndSize(source->device_name, &device_length)
                                                       : NULL;
        if (!address || (source->device_name && !device)) filled = -1;
        target->address = (ucall_bytes_view_t) {(ucall_byte_t const*)address, (size_t)address_length};
        if (source->descriptor >= 0) target->listen_descriptor = &source->descriptor;
        target->device_name = (ucall_bytes_view_t) {(ucall_byte_t const*)device, (size_t)device_length};
        target->security = source->security;
        if (source->noise_private_key) {
            memcpy(keys[index], PyBytes_AS_STRING(source->noise_private_key), sizeof(ucall_noise_key_t));
            target->noise_private_key = (ucall_noise_key_t const*)&keys[index];
        }
        if (source->peer_authorizer) {
            target->peer_authorizer = ucall_py_authorize_peer;
            target->peer_authorizer_context = source->peer_authorizer;
        }
        if (source->noise_peer_key)
            target->noise_peer_key = (ucall_noise_key_t const*)PyBytes_AS_STRING(source->noise_peer_key);
        target->event_loops = (size_t)source->event_loops;
        target->max_concurrent_connections = (size_t)source->connections;
        target->max_pipelined_requests = (size_t)source->pipelined_requests;
        target->max_request_bytes = (size_t)source->max_request_bytes;
        target->reply_directories = directory;
        target->reply_directories_count = (size_t)PyTuple_GET_SIZE(source->reply_directories);
        for (size_t position = 0; filled == 0 && position != target->reply_directories_count; ++position)
            filled = ucall_py_text_from_object(PyTuple_GET_ITEM(source->reply_directories, (Py_ssize_t)position),
                                               "reply_directories", directory++);
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
    PyMem_Free(directories);
    ucall_py_header_lines_release(&tags);
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
    Py_VISIT(self->log);
    return 0;
}

static int Server_clear(Server* self) {
    Py_CLEAR(self->endpoints);
    Py_CLEAR(self->interfaces);
    Py_CLEAR(self->log);
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
    "add_endpoint(path, verb, handler, /, body=BodyDelivery.BUFFERED) -> Callable\n"                   //
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
    "  path (str): A URI template such as `/users/{name}` or `/files/{*path}`.\n"                      //
    "  verb (Verb): The method to answer; `Verb.ANY` answers every one.\n"                             //
    "  handler (Callable): The function to route to.\n"                                                //
    "  body (BodyDelivery, optional): `BodyDelivery.STREAMED` runs the handler once the headers\n"     //
    "    arrived, its body pulled through `DetachedRequest.body_chunks`. Defaults to buffered.\n"      //
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
    PyObject *path = NULL, *verb = NULL, *handler = NULL, *body = NULL;
    ucall_py_argument_t const arguments[] = {{"path", &path}, {"verb", &verb}, {"handler", &handler}, {"body", &body}};
    if (ucall_py_parse_fast("add_endpoint", values, count, names, 3, 3, arguments, 4) != 0) return NULL;
    ucall_bytes_view_t template_view;
    int verb_value = 0, body_value = ucall_body_delivery_buffered_k;
    if (ucall_py_text_from_object(path, "path", &template_view) != 0 ||
        ucall_py_enum_from_object(verb, "verb", &ucall_py_verb_enum, &verb_value) != 0 ||
        ucall_py_enum_from_object(body, "body", &ucall_py_body_delivery_enum, &body_value) != 0)
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
        self->handle,
        &outcome,
        template_view,
        (ucall_verb_t)verb_value,
        callback,
        endpoint,
        (ucall_body_delivery_t)body_value,
    };
    ucall_server_add_http_endpoint(&add);
    int const added = ucall_py_raise_outcome(&outcome) == 0 && PyList_Append(self->endpoints, (PyObject*)endpoint) == 0;
    Py_DECREF(endpoint);
    return added ? Py_NewRef(handler) : NULL;
}

static char const doc_Server_add_batch_endpoint[] =                                                     //
    "add_batch_endpoint(path, verb, handler, /, min_size=0, max_size=0, max_latency_microseconds=0)\n"  //
    "    -> BatchEndpoint\n"                                                                            //
    "\n"                                                                                                //
    "Queues matching requests from every event loop for `handler(requests)`, called in batches.\n"      //
    "\n"                                                                                                //
    "A batch is due once `min_size` requests arrived, `max_size` are queued, or the oldest waited\n"    //
    "`max_latency_microseconds`. The handler runs on the thread polling the returned endpoint and\n"    //
    "replies to each request.\n"                                                                        //
    "\n"                                                                                                //
    "Args:\n"                                                                                           //
    "  path (str): A URI template such as \"/infer\".\n"                                                //
    "  verb (Verb): The method to answer; `Verb.ANY` answers every one.\n"                              //
    "  handler (Callable[[list[Request]], object]): The function handed each batch.\n"                  //
    "  min_size (int, optional): Requests that make a batch due at once; 0 means 1.\n"                  //
    "  max_size (int, optional): Requests one batch holds at most; 0 means 32.\n"                       //
    "  max_latency_microseconds (int, optional): The longest the oldest request waits for a batch to\n" //
    "    fill, in microseconds; 0 means 10 ms.\n"                                                       //
    "\n"                                                                                                //
    "Returns:\n"                                                                                        //
    "  BatchEndpoint: The endpoint to drain.\n"                                                         //
    "\n"                                                                                                //
    "Raises:\n"                                                                                         //
    "  Error: A duplicate route or an invalid template.\n"                                              //
    "\n"                                                                                                //
    "Example:\n"                                                                                        //
    "  >>> endpoint = server.add_batch_endpoint(\"/sizes\", \"POST\", lambda requests: None, 4)\n"      //
    "  >>> endpoint in server.batch_endpoints\n"                                                        //
    "  True";

static PyObject* Server_add_batch_endpoint(Server* self, PyObject* const* values, Py_ssize_t count, PyObject* names) {
    PyObject *path = NULL, *verb = NULL, *handler = NULL, *min_size = NULL, *max_size = NULL, *max_latency = NULL;
    ucall_py_argument_t const arguments[] = {{"path", &path},         {"verb", &verb},
                                             {"handler", &handler},   {"min_size", &min_size},
                                             {"max_size", &max_size}, {"max_latency_microseconds", &max_latency}};
    if (ucall_py_parse_fast("add_batch_endpoint", values, count, names, 3, 6, arguments, 6) != 0) return NULL;
    ucall_bytes_view_t template_view;
    int verb_value = 0;
    size_t minimum = 0, maximum = 0, latency = 0;
    if (ucall_py_text_from_object(path, "path", &template_view) != 0 ||
        ucall_py_enum_from_object(verb, "verb", &ucall_py_verb_enum, &verb_value) != 0 ||
        ucall_py_size_from_object(min_size, "min_size", &minimum) != 0 ||
        ucall_py_size_from_object(max_size, "max_size", &maximum) != 0 ||
        ucall_py_size_from_object(max_latency, "max_latency_microseconds", &latency) != 0)
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

/** The decorator registering a handler for @p verb, or @p verb_value without one, at @p path. */
static PyObject* server_route(Server* self, PyObject* path, PyObject* verb, int verb_value, PyObject* body) {
    ucall_bytes_view_t template_view;
    if (ucall_py_text_from_object(path, "path", &template_view) != 0 ||
        ucall_py_enum_from_object(verb, "verb", &ucall_py_verb_enum, &verb_value) != 0)
        return NULL;
    PyObject* const member = ucall_py_enum_to_object(&ucall_py_verb_enum, verb_value);
    PyObject* const keywords = member && body ? Py_BuildValue("{sO}", "body", body) : NULL;
    PyObject* const decorator = member && (keywords || !body)
                                    ? registration_decorator(self, "add_endpoint", path, member, keywords)
                                    : NULL;
    Py_XDECREF(keywords);
    Py_XDECREF(member);
    return decorator;
}

/** Parses @c get and its siblings, which differ only in @p verb. */
static PyObject* server_route_verb(Server* self, char const* name, ucall_verb_t verb, PyObject* const* values,
                                   Py_ssize_t count, PyObject* names) {
    PyObject *path = NULL, *body = NULL;
    ucall_py_argument_t const arguments[] = {{"path", &path}, {"body", &body}};
    if (ucall_py_parse_fast(name, values, count, names, 1, 1, arguments, 2) != 0) return NULL;
    return server_route(self, path, NULL, verb, body);
}

static char const doc_Server_route[] =                                                           //
    "route(path, verb=Verb.GET, *, body=BodyDelivery.BUFFERED) -> Callable[[F], F]\n"            //
    "\n"                                                                                         //
    "Registers the decorated function for `verb` requests matching the URI template `path`.\n"   //
    "\n"                                                                                         //
    "Args:\n"                                                                                    //
    "  path (str): A URI template such as \"/users/{name}\".\n"                                  //
    "  verb (Verb, optional): The method to answer. Defaults to `Verb.GET`.\n"                   //
    "  body (BodyDelivery, optional): When the handler runs, as `add_endpoint` takes it.\n"      //
    "\n"                                                                                         //
    "Returns:\n"                                                                                 //
    "  Callable[[F], F]: A decorator calling `add_endpoint` and returning the function as is.\n" //
    "\n"                                                                                         //
    "Example:\n"                                                                                 //
    "  >>> @server.route(\"/anything\", ucall.Verb.ANY)\n"                                       //
    "  ... def anything(request: ucall.Request):\n"                                              //
    "  ...     return request.verb.name";

static PyObject* Server_route(Server* self, PyObject* const* values, Py_ssize_t count, PyObject* names) {
    PyObject *path = NULL, *verb = NULL, *body = NULL;
    ucall_py_argument_t const arguments[] = {{"path", &path}, {"verb", &verb}, {"body", &body}};
    if (ucall_py_parse_fast("route", values, count, names, 1, 2, arguments, 3) != 0) return NULL;
    return server_route(self, path, verb, ucall_verb_get_k, body);
}

static char const doc_Server_get[] =                                                             //
    "get(path, /, *, body=BodyDelivery.BUFFERED) -> Callable[[F], F]\n"                          //
    "\n"                                                                                         //
    "Registers the decorated function for GET requests matching the URI template `path`.\n"      //
    "\n"                                                                                         //
    "Args:\n"                                                                                    //
    "  path (str): A URI template such as \"/users/{name}\".\n"                                  //
    "  body (BodyDelivery, optional): When the handler runs, as `add_endpoint` takes it.\n"      //
    "\n"                                                                                         //
    "Returns:\n"                                                                                 //
    "  Callable[[F], F]: A decorator calling `add_endpoint` and returning the function as is.\n" //
    "\n"                                                                                         //
    "Example:\n"                                                                                 //
    "  >>> @server.get(\"/users/{name}\")\n"                                                     //
    "  ... def user(name: str, verbose: bool = False):\n"                                        //
    "  ...     return {\"name\": name, \"verbose\": verbose}";

static PyObject* Server_get(Server* self, PyObject* const* values, Py_ssize_t count, PyObject* names) {
    return server_route_verb(self, "get", ucall_verb_get_k, values, count, names);
}

static char const doc_Server_post[] =                                                            //
    "post(path, /, *, body=BodyDelivery.BUFFERED) -> Callable[[F], F]\n"                         //
    "\n"                                                                                         //
    "Registers the decorated function for POST requests matching the URI template `path`.\n"     //
    "\n"                                                                                         //
    "Args:\n"                                                                                    //
    "  path (str): A URI template such as \"/sum\".\n"                                           //
    "  body (BodyDelivery, optional): When the handler runs, as `add_endpoint` takes it.\n"      //
    "\n"                                                                                         //
    "Returns:\n"                                                                                 //
    "  Callable[[F], F]: A decorator calling `add_endpoint` and returning the function as is.\n" //
    "\n"                                                                                         //
    "Example:\n"                                                                                 //
    "  >>> @server.post(\"/sum\")\n"                                                             //
    "  ... def sum(a: int, b: float = 0.5):\n"                                                   //
    "  ...     return a + b";

static PyObject* Server_post(Server* self, PyObject* const* values, Py_ssize_t count, PyObject* names) {
    return server_route_verb(self, "post", ucall_verb_post_k, values, count, names);
}

static char const doc_Server_put[] =                                                             //
    "put(path, /, *, body=BodyDelivery.BUFFERED) -> Callable[[F], F]\n"                          //
    "\n"                                                                                         //
    "Registers the decorated function for PUT requests matching the URI template `path`.\n"      //
    "\n"                                                                                         //
    "Args:\n"                                                                                    //
    "  path (str): A URI template such as `/files/{*path}`.\n"                                   //
    "  body (BodyDelivery, optional): When the handler runs, as `add_endpoint` takes it.\n"      //
    "\n"                                                                                         //
    "Returns:\n"                                                                                 //
    "  Callable[[F], F]: A decorator calling `add_endpoint` and returning the function as is.\n" //
    "\n"                                                                                         //
    "Example:\n"                                                                                 //
    "  >>> @server.put(\"/files/{*path}\")\n"                                                    //
    "  ... def store(request: ucall.Request):\n"                                                 //
    "  ...     return len(request.body)";

static PyObject* Server_put(Server* self, PyObject* const* values, Py_ssize_t count, PyObject* names) {
    return server_route_verb(self, "put", ucall_verb_put_k, values, count, names);
}

static char const doc_Server_delete[] =                                                          //
    "delete(path, /, *, body=BodyDelivery.BUFFERED) -> Callable[[F], F]\n"                       //
    "\n"                                                                                         //
    "Registers the decorated function for DELETE requests matching the URI template `path`.\n"   //
    "\n"                                                                                         //
    "Args:\n"                                                                                    //
    "  path (str): A URI template such as `/files/{*path}`.\n"                                   //
    "  body (BodyDelivery, optional): When the handler runs, as `add_endpoint` takes it.\n"      //
    "\n"                                                                                         //
    "Returns:\n"                                                                                 //
    "  Callable[[F], F]: A decorator calling `add_endpoint` and returning the function as is.\n" //
    "\n"                                                                                         //
    "Example:\n"                                                                                 //
    "  >>> @server.delete(\"/files/{*path}\")\n"                                                 //
    "  ... def remove(path: str):\n"                                                             //
    "  ...     return None";

static PyObject* Server_delete(Server* self, PyObject* const* values, Py_ssize_t count, PyObject* names) {
    return server_route_verb(self, "delete", ucall_verb_delete_k, values, count, names);
}

static char const doc_Server_patch[] =                                                           //
    "patch(path, /, *, body=BodyDelivery.BUFFERED) -> Callable[[F], F]\n"                        //
    "\n"                                                                                         //
    "Registers the decorated function for PATCH requests matching the URI template `path`.\n"    //
    "\n"                                                                                         //
    "Args:\n"                                                                                    //
    "  path (str): A URI template such as \"/users/{name}\".\n"                                  //
    "  body (BodyDelivery, optional): When the handler runs, as `add_endpoint` takes it.\n"      //
    "\n"                                                                                         //
    "Returns:\n"                                                                                 //
    "  Callable[[F], F]: A decorator calling `add_endpoint` and returning the function as is.\n" //
    "\n"                                                                                         //
    "Example:\n"                                                                                 //
    "  >>> @server.patch(\"/users/{name}\")\n"                                                   //
    "  ... def rename(name: str, alias: str):\n"                                                 //
    "  ...     return f\"{name} is {alias}\"";

static PyObject* Server_patch(Server* self, PyObject* const* values, Py_ssize_t count, PyObject* names) {
    return server_route_verb(self, "patch", ucall_verb_patch_k, values, count, names);
}

static char const doc_Server_batch[] =                                                                     //
    "batch(path, verb=Verb.POST, *, min_size=0, max_size=0, max_latency_microseconds=0)\n"                 //
    "    -> Callable[[Callable[[list[Request]], object]], BatchEndpoint]\n"                                //
    "\n"                                                                                                   //
    "Registers the decorated `handler(requests)` as a batch endpoint, replacing it with that.\n"           //
    "\n"                                                                                                   //
    "Args:\n"                                                                                              //
    "  path (str): A URI template such as \"/infer\".\n"                                                   //
    "  verb (Verb, optional): The method to answer. Defaults to `Verb.POST`.\n"                            //
    "  min_size (int, optional): Requests that make a batch due at once; 0 means 1.\n"                     //
    "  max_size (int, optional): Requests one batch holds at most; 0 means 32.\n"                          //
    "  max_latency_microseconds (int, optional): The longest the oldest request waits, in microseconds;\n" //
    "    0 means 10 ms.\n"                                                                                 //
    "\n"                                                                                                   //
    "Returns:\n"                                                                                           //
    "  Callable: A decorator calling `add_batch_endpoint` and returning its `BatchEndpoint`.\n"            //
    "\n"                                                                                                   //
    "Example:\n"                                                                                           //
    "  >>> @server.batch(\"/reverse\", min_size=4, max_size=4)\n"                                          //
    "  ... def reverse(requests: list[ucall.Request]):\n"                                                  //
    "  ...     for request in reversed(requests):\n"                                                       //
    "  ...         request.reply(request.body)\n"                                                          //
    "  >>> type(reverse).__name__\n"                                                                       //
    "  'BatchEndpoint'";

static PyObject* Server_batch(Server* self, PyObject* const* values, Py_ssize_t count, PyObject* names) {
    PyObject *path = NULL, *verb = NULL, *min_size = NULL, *max_size = NULL, *max_latency = NULL;
    ucall_py_argument_t const arguments[] = {{"path", &path},
                                             {"verb", &verb},
                                             {"min_size", &min_size},
                                             {"max_size", &max_size},
                                             {"max_latency_microseconds", &max_latency}};
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

static char const doc_Server_take_call[] =                                                              //
    "take_call(event_loop=0, timeout_microseconds=0) -> bool\n"                                         //
    "\n"                                                                                                //
    "Advances one event loop and runs its ready handlers on this thread.\n"                             //
    "\n"                                                                                                //
    "Each loop has one polling owner, and handlers run inside the call, so a slow one delays\n"         //
    "its return past `timeout_microseconds`.\n"                                                         //
    "\n"                                                                                                //
    "Args:\n"                                                                                           //
    "  event_loop (int, optional): The loop to advance, below `event_loops`. Defaults to 0.\n"          //
    "  timeout_microseconds (int, optional): The longest wait for I/O in microseconds; 0 polls once.\n" //
    "\n"                                                                                                //
    "Returns:\n"                                                                                        //
    "  bool: False once the loop retired after `stop()`, with nothing left to take.\n"                  //
    "\n"                                                                                                //
    "Raises:\n"                                                                                         //
    "  Error: An `event_loop` past the last one, or an I/O failure.\n"                                  //
    "\n"                                                                                                //
    "Example:\n"                                                                                        //
    "  >>> while server.take_call(0, timeout_microseconds=1_000): pass";

static PyObject* Server_take_call(Server* self, PyObject* const* values, Py_ssize_t count, PyObject* names) {
    PyObject *loop = NULL, *timeout = NULL;
    ucall_py_argument_t const arguments[] = {{"event_loop", &loop}, {"timeout_microseconds", &timeout}};
    if (ucall_py_parse_fast("take_call", values, count, names, 0, 2, arguments, 2) != 0) return NULL;
    int failed = 0;
    size_t microseconds = 0;
    size_t const index = event_loop_index(loop, &failed);
    if (failed || ucall_py_size_from_object(timeout, "timeout_microseconds", &microseconds) != 0) return NULL;
    ucall_outcome_t outcome = {0};
    ucall_server_take_call_t take = {self->handle, &outcome, index, microseconds};
    Py_BEGIN_ALLOW_THREADS;
    ucall_server_take_call(&take);
    Py_END_ALLOW_THREADS;
    if (outcome.status == ucall_status_connection_closed_k) Py_RETURN_FALSE;
    if (ucall_py_raise_outcome(&outcome) != 0) return NULL;
    Py_RETURN_TRUE;
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
    "for signals between them, and once stopped it lets the loop finish the requests in flight;\n" //
    "a second `KeyboardInterrupt` cuts them.\n"                                                    //
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

/** Whether @p self still serves, read under its section since @c stop may run on any thread. */
static int server_serving(Server* self) {
    ucall_py_section_t section;
    ucall_py_section_begin(&section, (PyObject*)self);
    int const serving = self->stage == server_serving_k;
    ucall_py_section_end(&section);
    return serving;
}

static void server_stop_serving(Server* self) {
    ucall_py_section_t section;
    ucall_py_section_begin(&section, (PyObject*)self);
    self->stage = server_stopping_k;
    ucall_py_section_end(&section);
}

static PyObject* Server_run(Server* self, [[maybe_unused]] PyObject* unused) {
    Py_ssize_t const batches = server_batch_endpoints_count(self);
    if (self->event_loops != 1 || batches)
        return PyErr_Format(PyExc_RuntimeError,
                            "Server.run() polls one event loop on the calling thread, and this server has %zu event "
                            "loops and %zd batch endpoints, so poll each loop with take_calls and drain each batch "
                            "endpoint with take_batches on threads of your own.",
                            self->event_loops, batches);
    ucall_outcome_t outcome = {0};
    int failed = 0;
    while (!failed && server_serving(self) && outcome.status == ucall_status_success_k) {
        ucall_server_take_call_t take = {self->handle, &outcome, 0, ucall_py_interrupt_period_microseconds_k};
        Py_BEGIN_ALLOW_THREADS;
        ucall_server_take_call(&take);
        Py_END_ALLOW_THREADS;
        failed = (outcome.status != ucall_status_connection_closed_k && ucall_py_raise_outcome(&outcome) != 0) ||
                 PyErr_CheckSignals() != 0;
    }
    // Handlers draining below run on this thread, so the exception that ended serving waits aside.
    PyObject* interrupted = PyErr_GetRaisedException();
    server_stop_serving(self);
    ucall_server_stop(self->handle);
    ucall_outcome_t drained = {0};
    // Slices keep Ctrl+C live through the drain, and a second one cuts what it still waits for.
    while (drained.status == ucall_status_success_k) {
        ucall_server_take_call_t take = {self->handle, &drained, 0, ucall_py_interrupt_period_microseconds_k};
        Py_BEGIN_ALLOW_THREADS;
        ucall_server_take_call(&take);
        Py_END_ALLOW_THREADS;
        if (PyErr_CheckSignals() == 0) continue;
        PyObject* const again = PyErr_GetRaisedException();
        if (interrupted) Py_DECREF(again);
        else interrupted = again;
        ucall_server_stop(self->handle);
    }
    if (drained.status == ucall_status_connection_closed_k) drained.status = ucall_status_success_k;
    if (interrupted) {
        PyErr_SetRaisedException(interrupted);
        return NULL;
    }
    if (ucall_py_raise_outcome(&drained) != 0) return NULL;
    Py_RETURN_NONE;
}

static char const doc_Server_stop[] =                                                                  //
    "stop() -> None\n"                                                                                 //
    "\n"                                                                                               //
    "Asks the server to stop, waking every polling caller, of loops and batch endpoints, to return.\n" //
    "\n"                                                                                               //
    "The first call drains: no new connections, idle ones close, and the requests\n"                   //
    "already held are answered before their connections close. A second call cuts the\n"               //
    "replies still in flight.\n"                                                                       //
    "\n"                                                                                               //
    "Safe from any thread and from a handler. Join the polling threads before releasing\n"             //
    "the server.\n"                                                                                    //
    "\n"                                                                                               //
    "Example:\n"                                                                                       //
    "  >>> server.stop()";

static PyObject* Server_stop(Server* self, [[maybe_unused]] PyObject* unused) {
    server_stop_serving(self);
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
    "    `bytes_sent`, `bytes_copied`, `zero_copy_sends`, `zero_copy_fallbacks`,\n"              //
    "    `copying_sends`, `file_reads_asynchronous`, `file_reads_blocking`, `bytes_read`,\n"     //
    "    `file_window_overlaps`, `linger_resets`, `ready_passes`, `replied_dequeues`,\n"         //
    "    `refused_requests`, `handshake_failures` and `authorizer_refusals`, each read on its\n" //
    "    own.\n"                                                                                 //
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
    return Py_BuildValue("{sKsKsKsKsKsKsKsKsKsKsKsKsKsKsKsKsKsKsKsKsKsKsKsKsK}",                          //
                         "polls", (unsigned long long)counters.polls,                                     //
                         "empty_polls", (unsigned long long)counters.empty_polls,                         //
                         "kernel_enters", (unsigned long long)counters.kernel_enters,                     //
                         "submissions", (unsigned long long)counters.submissions,                         //
                         "completions", (unsigned long long)counters.completions,                         //
                         "cancellations", (unsigned long long)counters.cancellations,                     //
                         "accepts", (unsigned long long)counters.accepts,                                 //
                         "requests", (unsigned long long)counters.requests,                               //
                         "receive_rearms", (unsigned long long)counters.receive_rearms,                   //
                         "bytes_received", (unsigned long long)counters.bytes_received,                   //
                         "bytes_sent", (unsigned long long)counters.bytes_sent,                           //
                         "bytes_copied", (unsigned long long)counters.bytes_copied,                       //
                         "zero_copy_sends", (unsigned long long)counters.zero_copy_sends,                 //
                         "zero_copy_fallbacks", (unsigned long long)counters.zero_copy_fallbacks,         //
                         "copying_sends", (unsigned long long)counters.copying_sends,                     //
                         "file_reads_asynchronous", (unsigned long long)counters.file_reads_asynchronous, //
                         "file_reads_blocking", (unsigned long long)counters.file_reads_blocking,         //
                         "bytes_read", (unsigned long long)counters.bytes_read,                           //
                         "file_window_overlaps", (unsigned long long)counters.file_window_overlaps,       //
                         "linger_resets", (unsigned long long)counters.linger_resets,                     //
                         "ready_passes", (unsigned long long)counters.ready_passes,                       //
                         "replied_dequeues", (unsigned long long)counters.replied_dequeues,               //
                         "refused_requests", (unsigned long long)counters.refused_requests,               //
                         "handshake_failures", (unsigned long long)counters.handshake_failures,           //
                         "authorizer_refusals", (unsigned long long)counters.authorizer_refusals);
}

static PyObject* Server_get_event_loops(Server* self, [[maybe_unused]] void* closure) {
    return PyLong_FromSize_t(self->event_loops);
}

static PyObject* Server_get_backend(Server* self, [[maybe_unused]] void* closure) {
    return ucall_py_enum_to_object(&ucall_py_backend_enum, self->resolved.backend);
}

static PyObject* Server_get_cpu_class(Server* self, [[maybe_unused]] void* closure) {
    return ucall_py_enum_to_object(&ucall_py_cpu_class_enum, self->resolved.cpu_class);
}

static PyObject* Server_get_addresses(Server* self, [[maybe_unused]] void* closure) {
    PyObject* const addresses = PyTuple_New((Py_ssize_t)self->resolved.interfaces_count);
    for (size_t index = 0; addresses && index != self->resolved.interfaces_count; ++index) {
        ucall_bytes_view_t const bound = self->resolved.interfaces[index].address;
        PyObject* const address = PyUnicode_FromStringAndSize((char const*)bound.data, (Py_ssize_t)bound.length);
        if (!address) {
            Py_DECREF(addresses);
            return NULL;
        }
        PyTuple_SET_ITEM(addresses, (Py_ssize_t)index, address);
    }
    return addresses;
}

static PyObject* Server_get_batch_endpoints(Server* self, [[maybe_unused]] void* closure) {
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
    {"get", (PyCFunction)(void (*)(void))Server_get, ucall_py_method_flags_k, doc_Server_get},
    {"post", (PyCFunction)(void (*)(void))Server_post, ucall_py_method_flags_k, doc_Server_post},
    {"put", (PyCFunction)(void (*)(void))Server_put, ucall_py_method_flags_k, doc_Server_put},
    {"delete", (PyCFunction)(void (*)(void))Server_delete, ucall_py_method_flags_k, doc_Server_delete},
    {"patch", (PyCFunction)(void (*)(void))Server_patch, ucall_py_method_flags_k, doc_Server_patch},
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
    {"batch_endpoints", (getter)Server_get_batch_endpoints, NULL, "Batch endpoints, each needing a polling owner.",
     NULL},
    {NULL, NULL, NULL, NULL, NULL},
};

ucall_server_t ucall_py_server_handle(PyObject* server) { return ((Server*)server)->handle; }

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
