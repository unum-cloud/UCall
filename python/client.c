/**
 *  @file python/client.c
 *  @author Ash Vardanian
 *  @date January 30, 2023
 *  @brief The calling half of `ucall.lib`: `Client`, `Completed` and `Response`.
 */
#include "lib.h"

#pragma region Completions

typedef struct Completed Completed;

typedef struct Client {
    PyObject ob_base;
    ucall_client_t handle;

    /** The thread that created the client, the only one the C interface lets submit and poll. */
    unsigned long owner;

    /** The 32-byte Noise identity the C client borrows, or NULL. */
    PyObject* noise_private_key;

    /** The callable vetting Noise servers, or NULL. */
    PyObject* peer_authorizer;

    /** The callable receiving the client's log lines, or NULL. */
    PyObject* log;

    /** The @c ucall.Server whose event loop drives a bound client, kept alive past it, or NULL. */
    PyObject* server;

    /** Completions a blocking call retrieved for others, which `take_completed` hands out first. */
    PyObject* buffered;

    /** Accepted calls not yet retrieved, linked through their own objects. */
    Completed* in_flight;
} Client;

struct Completed {
    PyObject ob_base;

    /** The `context` given to `submit`. */
    PyObject* context;

    /** The @c Response, or NULL until retrieval and on failure. */
    PyObject* response;

    /** The static detail of a failure, or NULL. */
    char const* message;

    /** @c ucall_status_deferred_k until retrieved. */
    ucall_status_t status;

    /** The URL the client borrows while the call is in flight, as UTF-8 @c bytes. */
    PyObject* url;

    /** The header lines the client borrows while the call is in flight. */
    ucall_py_header_lines_t headers;

    /** The body the client borrows while the call is in flight. */
    Py_buffer body;

    /** The server's static key the client borrows while the call is in flight. */
    ucall_noise_key_t noise_peer_key;

    /** The client's private key for this call, which the client borrows while the call is in
     *  flight. */
    ucall_noise_key_t noise_private_key;

    /** The neighbors in the client's in-flight list. */
    Completed* previous;
    Completed* next;
};

/** A response owns its bytes and reads them without its client, which may be freed first. */
typedef struct Response {
    PyObject ob_base;

    /** The received response, freed with the object. */
    ucall_received_http_response_t handle;
} Response;

/** Returns the inputs a finished or cancelled call borrowed and unlinks it from its client. */
static void completed_release_inputs(Client* client, Completed* call) {
    if (call->previous) call->previous->next = call->next;
    else if (client->in_flight == call) client->in_flight = call->next;
    if (call->next) call->next->previous = call->previous;
    call->previous = call->next = NULL;
    if (call->body.obj) PyBuffer_Release(&call->body);
    ucall_py_header_lines_release(&call->headers);
    Py_CLEAR(call->url);
}

static void Completed_dealloc(Completed* self) {
    if (self->body.obj) PyBuffer_Release(&self->body);
    ucall_py_header_lines_release(&self->headers);
    Py_CLEAR(self->url);
    Py_CLEAR(self->context);
    Py_CLEAR(self->response);
    memset(self->noise_private_key, 0, sizeof(self->noise_private_key));
    PyObject_Free(self);
}

static PyObject* Completed_get_status(Completed* self, void* closure) {
    (void)closure;
    return ucall_py_enum_to_object(&ucall_py_status_enum, (long)self->status);
}

static PyObject* Completed_get_message(Completed* self, void* closure) {
    (void)closure;
    if (!self->message) Py_RETURN_NONE;
    return PyUnicode_FromString(self->message);
}

static PyObject* Completed_get_response(Completed* self, void* closure) {
    (void)closure;
    return Py_NewRef(self->response ? self->response : Py_None);
}

static PyGetSetDef Completed_getset[] = {
    {"context", ucall_py_get_optional, NULL, "The `context` given to `submit`.", (void*)offsetof(Completed, context)},
    {"status", (getter)Completed_get_status, NULL, "The final `Status` of the exchange.", NULL},
    {"message", (getter)Completed_get_message, NULL, "The detail of a failure, or None.", NULL},
    {"response", (getter)Completed_get_response, NULL, "The `Response`, or None on failure.", NULL},
    {NULL, NULL, NULL, NULL, NULL},
};

static char const doc_Completed[] =                                                               //
    "The final result of one accepted client call, from `Client.take_completed`.\n"               //
    "\n"                                                                                          //
    "`status` is `Status.SUCCESS` once any response arrived, whatever its HTTP status, and the\n" //
    "failure otherwise, such as `Status.TIMEOUT`, with `response` None.\n"                        //
    "\n"                                                                                          //
    "Example:\n"                                                                                  //
    "  >>> client.submit(\"GET\", \"http://127.0.0.1:8545/health\", context=\"health\")\n"        //
    "  >>> for completed in client.take_completed(timeout_microseconds=1_000_000):\n"             //
    "  ...     print(completed.context, completed.status.name)\n"                                 //
    "  health SUCCESS";

PyTypeObject CompletedType = {
    PyVarObject_HEAD_INIT(NULL, 0).tp_name = "ucall.Completed",
    .tp_basicsize = sizeof(Completed),
    .tp_flags = Py_TPFLAGS_DEFAULT,
    .tp_doc = doc_Completed,
    .tp_dealloc = (destructor)Completed_dealloc,
    .tp_getset = Completed_getset,
};

static void Response_dealloc(Response* self) {
    ucall_client_response_free(self->handle);
    PyObject_Free(self);
}

static int Response_getbuffer(Response* self, Py_buffer* view, int flags) {
    static ucall_byte_t const empty_k[1] = {0};
    ucall_outcome_t outcome = {0};
    ucall_bytes_view_t body = {0};
    ucall_client_response_body_t extract = {self->handle, &outcome, &body};
    ucall_client_response_body(&extract);
    if (ucall_py_raise_outcome(&outcome) != 0) {
        view->obj = NULL;
        return -1;
    }
    return PyBuffer_FillInfo(view, (PyObject*)self, (void*)(body.data ? body.data : empty_k), (Py_ssize_t)body.length,
                             1, flags);
}

static PyBufferProcs Response_buffer = {(getbufferproc)Response_getbuffer, NULL};

static PyObject* Response_get_status_code(Response* self, void* closure) {
    (void)closure;
    return PyLong_FromUnsignedLong(ucall_client_response_status(self->handle));
}

static PyObject* Response_get_body(Response* self, void* closure) {
    (void)closure;
    return PyMemoryView_FromObject((PyObject*)self);
}

static char const doc_Response_header[] =                                              //
    "header(name, /) -> str | None\n"                                                  //
    "\n"                                                                               //
    "Looks up a header of the response by its case-insensitive name.\n"                //
    "\n"                                                                               //
    "Args:\n"                                                                          //
    "  name (str | bytes): The header name, such as \"Content-Type\".\n"               //
    "\n"                                                                               //
    "Returns:\n"                                                                       //
    "  str | None: The value as sent, or None when the response has no such header.\n" //
    "\n"                                                                               //
    "Example:\n"                                                                       //
    "  >>> response.header(\"content-type\")\n"                                        //
    "  'application/json'";

static PyObject* Response_header(Response* self, PyObject* name) {
    ucall_bytes_view_t name_view;
    if (ucall_py_text_from_object(name, "name", &name_view) != 0) return NULL;
    ucall_outcome_t outcome = {0};
    ucall_bytes_view_t value = {0};
    ucall_client_response_header_t lookup = {self->handle, &outcome, name_view, &value};
    ucall_client_response_header(&lookup);
    if (outcome.status == ucall_status_not_found_k) Py_RETURN_NONE;
    if (ucall_py_raise_outcome(&outcome) != 0) return NULL;
    return ucall_py_text_to_object(value);
}

static char const doc_Response_fields[] =                                                         //
    "fields() -> list[tuple[bytes, bytes]]\n"                                                     //
    "\n"                                                                                          //
    "Every header field line of the response in arrival order, repeated names apart.\n"           //
    "\n"                                                                                          //
    "Returns:\n"                                                                                  //
    "  list[tuple[bytes, bytes]]: Each name, lowercased as the parser keeps it, with its value\n" //
    "    trimmed.\n"                                                                              //
    "\n"                                                                                          //
    "Example:\n"                                                                                  //
    "  >>> dict(client.get(url).fields())[b'content-type']\n"                                     //
    "  b'text/plain'";

static PyObject* Response_fields(Response* self, [[maybe_unused]] PyObject* unused) {
    ucall_outcome_t outcome = {0};
    size_t count = 0;
    ucall_client_response_fields_count_t counting = {self->handle, &outcome, &count};
    ucall_client_response_fields_count(&counting);
    if (ucall_py_raise_outcome(&outcome) != 0) return NULL;
    PyObject* const fields = PyList_New((Py_ssize_t)count);
    for (size_t index = 0; fields && index != count; ++index) {
        ucall_bytes_view_t name = {0}, value = {0};
        ucall_client_response_field_t extract = {self->handle, &outcome, index, &name, &value};
        ucall_client_response_field(&extract);
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

static PyMethodDef Response_methods[] = {
    {"header", (PyCFunction)Response_header, METH_O, doc_Response_header},
    {"fields", (PyCFunction)Response_fields, METH_NOARGS, doc_Response_fields},
    {NULL, NULL, 0, NULL},
};

static PyGetSetDef Response_getset[] = {
    {"status_code", (getter)Response_get_status_code, NULL, "The HTTP status the server sent.", NULL},
    {"body", (getter)Response_get_body, NULL, "A read-only memoryview of the body, alive as long as it is.", NULL},
    {NULL, NULL, NULL, NULL, NULL},
};

static char const doc_Response[] =                                                             //
    "One received HTTP response, which owns its bytes and outlives its client.\n"              //
    "\n"                                                                                       //
    "`body` and the buffer protocol view the received bytes without a copy.\n"                 //
    "\n"                                                                                       //
    "Example:\n"                                                                               //
    "  >>> response = client.post(\"http://127.0.0.1:8545/sum\", json={\"a\": 1, \"b\": 2})\n" //
    "  >>> response.status_code, bytes(response.body), json.loads(bytes(response))\n"          //
    "  (200, b'3', 3)";

PyTypeObject ResponseType = {
    PyVarObject_HEAD_INIT(NULL, 0).tp_name = "ucall.Response",
    .tp_basicsize = sizeof(Response),
    .tp_flags = Py_TPFLAGS_DEFAULT,
    .tp_doc = doc_Response,
    .tp_dealloc = (destructor)Response_dealloc,
    .tp_as_buffer = &Response_buffer,
    .tp_methods = Response_methods,
    .tp_getset = Response_getset,
};

#pragma endregion Completions

#pragma region Client

static char const doc_Client[] =                                                                        //
    "Client(*, connections, pipelined_calls=0, calls=0, connect_timeout_microseconds=0,\n"              //
    "    call_timeout_microseconds=0,\n"                                                                //
    "    noise_private_key=None, peer_authorizer=None, backend=Backend.AUTOMATIC,\n"                    //
    "    cpu_class=CPUClass.UNKNOWN, log=None, log_level=LogLevel.DEBUG, log_format=LogFormat.HUMAN,\n" //
    "    max_response_bytes=0, server=None, event_loop=0)\n"                                            //
    "\n"                                                                                                //
    "An HTTP client that belongs to the thread creating it, which alone may submit and poll.\n"         //
    "\n"                                                                                                //
    "Args:\n"                                                                                           //
    "  connections (int): Connections open at once, across every server it calls.\n"                    //
    "  pipelined_calls (int, optional): Calls one connection carries at once; 0 means one.\n"           //
    "  calls (int, optional): Calls accepted at once, retrieved or not; 0 means `connections`\n"        //
    "    times `pipelined_calls`.\n"                                                                    //
    "  connect_timeout_microseconds (int, optional): The budget to connect, in microseconds;\n"         //
    "    0 means 5 s.\n"                                                                                //
    "  call_timeout_microseconds (int, optional): The budget of a whole exchange, in microseconds;\n"   //
    "    0 means 30 s.\n"                                                                               //
    "  noise_private_key (bytes, optional): The 32-byte Noise identity, required to call over Noise.\n" //
    "  peer_authorizer (Callable[[bytes], bool], optional): Admits a Noise server by its 32-byte\n"     //
    "    static key, required to call under `Security.NOISE_XX`.\n"                                     //
    "  backend (Backend, optional): The I/O implementation. Defaults to `Backend.AUTOMATIC`.\n"         //
    "  cpu_class (CPUClass, optional): The CPU kernels. Defaults to `CPUClass.UNKNOWN`.\n"              //
    "  log (Callable[[LogLevel, str], object], optional): Receives every line the client writes,\n"     //
    "    such as a dial that failed every address; None writes nothing.\n"                              //
    "  log_level (LogLevel, optional): The least severe line `log` receives. Defaults to DEBUG.\n"      //
    "  log_format (LogFormat, optional): How lines are spelled. Defaults to `LogFormat.HUMAN`.\n"       //
    "  max_response_bytes (int, optional): The largest response a call buffers, past which it\n"        //
    "    fails with `Status.OVERFLOW`; 0 takes the largest receive buffer the kernel grants.\n"         //
    "  server (Server, optional): A server whose event loop drives this client, sharing its\n"          //
    "    engine: bound before that loop first polls, used on its polling thread, and its\n"             //
    "    `take_completed` only hands out what the loop finished. None gives it its own engine.\n"       //
    "  event_loop (int, optional): Which of `server`'s event loops. Defaults to 0.\n"                   //
    "\n"                                                                                                //
    "Raises:\n"                                                                                         //
    "  TypeError: A missing `connections`, or an argument of the wrong type.\n"                         //
    "  Error: The backend cannot start.\n"                                                              //
    "\n"                                                                                                //
    "Example:\n"                                                                                        //
    "  >>> client = ucall.Client(connections=4, pipelined_calls=16)\n"                                  //
    "  >>> client.get(\"http://127.0.0.1:8545/health\").status_code\n"                                  //
    "  200";

static PyObject* Client_new(PyTypeObject* type, PyObject* positional, PyObject* keywords) {
    PyObject *connections = NULL, *pipelined_calls = NULL, *calls = NULL, *connect_timeout = NULL, *call_timeout = NULL,
             *noise_private_key = NULL, *peer_authorizer = NULL, *backend = NULL, *cpu_class = NULL, *log = NULL,
             *log_level = NULL, *log_format = NULL, *max_response_bytes = NULL, *server = NULL, *event_loop = NULL;
    ucall_py_argument_t const arguments[] = {
        {"connections", &connections},
        {"pipelined_calls", &pipelined_calls},
        {"calls", &calls},
        {"connect_timeout_microseconds", &connect_timeout},
        {"call_timeout_microseconds", &call_timeout},
        {"noise_private_key", &noise_private_key},
        {"peer_authorizer", &peer_authorizer},
        {"backend", &backend},
        {"cpu_class", &cpu_class},
        {"log", &log},
        {"log_level", &log_level},
        {"log_format", &log_format},
        {"max_response_bytes", &max_response_bytes},
        {"server", &server},
        {"event_loop", &event_loop},
    };
    if (ucall_py_parse_tuple("Client", positional, keywords, 0, 0, arguments,
                             sizeof(arguments) / sizeof(arguments[0])) != 0)
        return NULL;
    if (!connections) return PyErr_Format(PyExc_TypeError, "Client() missing required argument 'connections'");
    ucall_client_options_t config = {0};
    int backend_value = ucall_io_backend_automatic_k, cpu_class_value = ucall_cpu_class_unknown_k;
    if (ucall_py_size_from_object(connections, "connections", &config.max_concurrent_connections) != 0 ||
        ucall_py_size_from_object(pipelined_calls, "pipelined_calls", &config.max_pipelined_calls) != 0 ||
        ucall_py_size_from_object(calls, "calls", &config.max_concurrent_calls) != 0 ||
        ucall_py_size_from_object(connect_timeout, "connect_timeout_microseconds",
                                  &config.connect_timeout_microseconds) != 0 ||
        ucall_py_size_from_object(call_timeout, "call_timeout_microseconds", &config.call_timeout_microseconds) != 0 ||
        ucall_py_size_from_object(max_response_bytes, "max_response_bytes", &config.max_response_bytes) != 0 ||
        ucall_py_size_from_object(event_loop, "event_loop", &config.event_loop) != 0 ||
        ucall_py_enum_from_object(backend, "backend", &ucall_py_backend_enum, &backend_value) != 0 ||
        ucall_py_enum_from_object(cpu_class, "cpu_class", &ucall_py_cpu_class_enum, &cpu_class_value) != 0)
        return NULL;
    config.backend = (ucall_io_backend_t)backend_value;
    config.cpu_class = (ucall_cpu_class_t)cpu_class_value;
    if (ucall_py_log_from_objects(log, log_level, log_format, &config.log) != 0) return NULL;
    if (log == Py_None) log = NULL;
    if (noise_private_key == Py_None) noise_private_key = NULL;
    ucall_noise_key_t key = {0};
    if (noise_private_key && ucall_py_key_from_object(noise_private_key, "noise_private_key", key) != 0) return NULL;
    if (server == Py_None) server = NULL;
    if (server && !PyObject_TypeCheck(server, &ServerType))
        return PyErr_Format(PyExc_TypeError, "'server' must be a ucall.Server, got %s", Py_TYPE(server)->tp_name);
    if (server) config.server = ucall_py_server_handle(server);
    if (peer_authorizer == Py_None) peer_authorizer = NULL;
    if (peer_authorizer && !PyCallable_Check(peer_authorizer))
        return PyErr_Format(PyExc_TypeError, "'peer_authorizer' must be callable, got %s",
                            Py_TYPE(peer_authorizer)->tp_name);

    Client* const self = (Client*)type->tp_alloc(type, 0);
    if (!self) return NULL;
    self->owner = PyThread_get_thread_ident();
    self->noise_private_key = Py_XNewRef(noise_private_key);
    self->peer_authorizer = Py_XNewRef(peer_authorizer);
    self->log = Py_XNewRef(log);
    self->server = Py_XNewRef(server);
    self->buffered = PyList_New(0);
    if (!self->buffered) {
        Py_DECREF(self);
        return NULL;
    }
    if (noise_private_key) config.noise_private_key = (ucall_noise_key_t const*)PyBytes_AS_STRING(noise_private_key);
    if (peer_authorizer) {
        config.peer_authorizer = ucall_py_authorize_peer;
        config.peer_authorizer_context = peer_authorizer;
    }
    ucall_outcome_t outcome = {0};
    ucall_client_init_t init = {&self->handle, &outcome, &config, NULL};
    ucall_client_init(&init);
    if (ucall_py_raise_outcome(&outcome) != 0) {
        Py_DECREF(self);
        return NULL;
    }
    return (PyObject*)self;
}

static int Client_traverse(Client* self, visitproc visit, void* arg) {
    Py_VISIT(self->peer_authorizer);
    Py_VISIT(self->log);
    Py_VISIT(self->buffered);
    for (Completed* call = self->in_flight; call; call = call->next) Py_VISIT(call->context);
    return 0;
}

static int Client_clear(Client* self) {
    Py_CLEAR(self->peer_authorizer);
    Py_CLEAR(self->log);
    Py_CLEAR(self->buffered);
    return 0;
}

static void Client_dealloc(Client* self) {
    PyObject_GC_UnTrack(self);
    // The C client cancels every accepted call, so their borrowed inputs return only after it.
    Py_BEGIN_ALLOW_THREADS;
    ucall_client_free(self->handle);
    Py_END_ALLOW_THREADS;
    self->handle = NULL;
    while (self->in_flight) {
        Completed* const call = self->in_flight;
        completed_release_inputs(self, call);
        Py_DECREF(call);
    }
    Client_clear(self);
    Py_CLEAR(self->noise_private_key);
    Py_CLEAR(self->server);
    Py_TYPE(self)->tp_free((PyObject*)self);
}

static int client_owned(Client* self) {
    if (PyThread_get_thread_ident() == self->owner) return 0;
    ucall_py_raise_status(ucall_status_invalid_argument_k,
                          "a ucall.Client belongs to the thread that created it; create one client per thread");
    return -1;
}

/** The per-call options every calling verb takes, mirroring @c ucall_client_call_options_t;
 *  NULL skips one. */
typedef struct call_options_t {
    PyObject* security;
    PyObject* noise_peer_key;
    PyObject* noise_private_key;
    PyObject* timeout;
    PyObject* retries;
    PyObject* redirects;
} call_options_t;

/**
 *  @brief Submits one exchange, whose @c Completed the client owns until it is retrieved.
 *  @return The borrowed @c Completed, or NULL with an exception set.
 */
static Completed* client_submit(Client* self, ucall_verb_t verb, PyObject* url, PyObject* body, PyObject* headers,
                                call_options_t const* options, PyObject* context) {
    int security = ucall_security_none_k;
    ucall_client_call_t submission = {0};
    if (ucall_py_enum_from_object(options->security, "security", &ucall_py_security_enum, &security) != 0 ||
        ucall_py_size_from_object(options->timeout, "timeout_microseconds", &submission.options.timeout_microseconds) !=
            0 ||
        ucall_py_size_from_object(options->retries, "max_retries", &submission.options.max_retries) != 0 ||
        ucall_py_size_from_object(options->redirects, "max_redirects", &submission.options.max_redirects) != 0)
        return NULL;
    Completed* const call = PyObject_New(Completed, &CompletedType);
    if (!call) return NULL;
    memset((char*)call + sizeof(PyObject), 0, sizeof(Completed) - sizeof(PyObject));
    call->status = ucall_status_deferred_k;
    call->context = Py_NewRef(context ? context : Py_None);
    ucall_outcome_t outcome = {0};
    submission.client = self->handle;
    submission.verb = verb;
    submission.options.security = (ucall_security_t)security;
    if (options->noise_peer_key && options->noise_peer_key != Py_None) {
        if (ucall_py_key_from_object(options->noise_peer_key, "noise_peer_key", call->noise_peer_key) != 0)
            goto refused;
        submission.options.noise_peer_key = (ucall_noise_key_t const*)&call->noise_peer_key;
    }
    if (options->noise_private_key && options->noise_private_key != Py_None) {
        if (ucall_py_key_from_object(options->noise_private_key, "noise_private_key", call->noise_private_key) != 0)
            goto refused;
        submission.options.noise_private_key = (ucall_noise_key_t const*)&call->noise_private_key;
    }
    call->url = PyUnicode_Check(url) ? PyUnicode_AsUTF8String(url) : Py_NewRef(url);
    if (!call->url || ucall_py_text_from_object(call->url, "url", &submission.url) != 0) goto refused;
    if (ucall_py_header_lines_from_object(headers, &call->headers) != 0) goto refused;
    submission.headers = call->headers.views;
    submission.headers_count = call->headers.count;
    if (body && PyObject_GetBuffer(body, &call->body, PyBUF_SIMPLE) != 0) goto refused;
    submission.body = (ucall_bytes_view_t) {call->body.buf, (size_t)call->body.len};
    submission.context = call;
    submission.outcome = &outcome;
    ucall_client_call(&submission);
    if (ucall_py_raise_outcome(&outcome) != 0) goto refused;
    // The reference created here belongs to the cookie until `take_completed` hands it out.
    call->next = self->in_flight;
    if (self->in_flight) self->in_flight->previous = call;
    self->in_flight = call;
    return call;

refused:
    Py_DECREF(call);
    return NULL;
}

/** Drives the client's I/O and answers up to @p capacity finished calls, bypassing the buffer. */
static PyObject* client_take(Client* self, size_t timeout_microseconds, size_t capacity) {
    ucall_completed_call_t* const records = PyMem_Calloc(capacity ? capacity : 1, sizeof(ucall_completed_call_t));
    if (!records) return PyErr_NoMemory();
    size_t taken = 0;
    ucall_outcome_t outcome = {0};
    ucall_client_take_completed_t take = {self->handle, &outcome, records, capacity, &taken, timeout_microseconds};
    Py_BEGIN_ALLOW_THREADS;
    ucall_client_take_completed(&take);
    Py_END_ALLOW_THREADS;

    // Every record is unlinked and owned even if building the list fails part way.
    PyObject* list = PyList_New((Py_ssize_t)taken);
    for (size_t index = 0; index != taken; ++index) {
        Completed* const call = (Completed*)records[index].context;
        completed_release_inputs(self, call);
        call->status = records[index].outcome.status;
        call->message = records[index].outcome.message;
        Response* const response = records[index].response ? PyObject_New(Response, &ResponseType) : NULL;
        if (response) {
            response->handle = records[index].response;
            call->response = (PyObject*)response;
        }
        else ucall_client_response_free(records[index].response);
        if (list && records[index].response && !response) Py_CLEAR(list);
        if (list) PyList_SET_ITEM(list, (Py_ssize_t)index, (PyObject*)call);
        else Py_DECREF(call);
    }
    PyMem_Free(records);
    if (!list) return NULL;
    if (!taken && ucall_py_raise_outcome(&outcome) != 0) {
        Py_DECREF(list);
        return NULL;
    }
    return list;
}

static char const doc_Client_submit[] =                                                                   //
    "submit(verb, url, /, body=b\"\", headers=(), *, context=None, security=Security.NONE,\n"             //
    "    noise_peer_key=None, noise_private_key=None, timeout_microseconds=0, max_retries=0,\n"           //
    "    max_redirects=0) -> None\n"                                                                      //
    "\n"                                                                                                  //
    "Queues one exchange without driving I/O.\n"                                                          //
    "\n"                                                                                                  //
    "`take_completed` later returns exactly one `Completed` carrying `context`.\n"                        //
    "\n"                                                                                                  //
    "Args:\n"                                                                                             //
    "  verb (Verb): The method, such as `Verb.POST` or \"post\".\n"                                       //
    "  url (str | bytes): The full URL, \"http://\" or \"http+noise://\" and the server.\n"               //
    "  body (Buffer, optional): Any bytes-like object, borrowed until the call completes.\n"              //
    "  headers (Sequence[str | bytes], optional): \"name: value\" lines; the client adds Host,\n"         //
    "    Content-Length and User-Agent itself.\n"                                                         //
    "  security (Security, optional): The handshake for this call. Defaults to `Security.NONE`,\n"        //
    "    and an \"http+noise://\" URL calls over Noise XX.\n"                                             //
    "  noise_peer_key (bytes, optional): The server's 32-byte static key, required for\n"                 //
    "    `Security.NOISE_IK` and `Security.NOISE_KK`.\n"                                                  //
    "  noise_private_key (bytes, optional): This call's 32-byte Noise private key in place of the\n"      //
    "    client's own, as `Security.NOISE_KK` names the caller to the server.\n"                          //
    "  timeout_microseconds (int, optional): The budget of this call, queueing and redirects included;\n" //
    "    0 takes the client's `call_timeout_microseconds`.\n"                                             //
    "  max_retries (int, optional): Connection attempts before sending; 0 takes 3.\n"                     //
    "  max_redirects (int, optional): Redirect hops followed before failing; 0 takes 5.\n"                //
    "  context (object, optional): Anything, handed back as `Completed.context`.\n"                       //
    "\n"                                                                                                  //
    "Raises:\n"                                                                                           //
    "  Error: The call was refused and will not complete, such as `Status.CONTENDED` once\n"              //
    "    `calls` are in flight, or `Status.INVALID_ARGUMENT` from another thread.\n"                      //
    "\n"                                                                                                  //
    "Example:\n"                                                                                          //
    "  >>> for index in range(4):\n"                                                                      //
    "  ...     client.submit(\"POST\", \"http://127.0.0.1:8545/echo\", b\"payload\", context=index)";

static PyObject* Client_submit(Client* self, PyObject* const* values, Py_ssize_t count, PyObject* names) {
    PyObject *verb = NULL, *url = NULL, *body = NULL, *headers = NULL, *context = NULL;
    call_options_t options;
    ucall_py_argument_t const arguments[] = {
        {"verb", &verb},
        {"url", &url},
        {"body", &body},
        {"headers", &headers},
        {"context", &context},
        {"security", &options.security},
        {"noise_peer_key", &options.noise_peer_key},
        {"noise_private_key", &options.noise_private_key},
        {"timeout_microseconds", &options.timeout},
        {"max_retries", &options.retries},
        {"max_redirects", &options.redirects},
    };
    if (ucall_py_parse_fast("submit", values, count, names, 2, 4, arguments,
                            sizeof(arguments) / sizeof(arguments[0])) != 0 ||
        client_owned(self) != 0)
        return NULL;
    int verb_value = 0;
    if (ucall_py_enum_from_object(verb, "verb", &ucall_py_verb_enum, &verb_value) != 0) return NULL;
    if (!client_submit(self, (ucall_verb_t)verb_value, url, body, headers, &options, context)) return NULL;
    Py_RETURN_NONE;
}

static char const doc_Client_take_completed[] =                                                    //
    "take_completed(timeout_microseconds=0, capacity=64) -> list[Completed]\n"                     //
    "\n"                                                                                           //
    "Drives the client's I/O on this thread and returns the calls that finished.\n"                //
    "\n"                                                                                           //
    "Completions a blocking call retrieved for other calls come first, without driving any I/O.\n" //
    "\n"                                                                                           //
    "Args:\n"                                                                                      //
    "  timeout_microseconds (int, optional): The longest wait for the first, in microseconds;\n"   //
    "    0 polls once.\n"                                                                          //
    "  capacity (int, optional): The most to return. Defaults to 64.\n"                            //
    "\n"                                                                                           //
    "Returns:\n"                                                                                   //
    "  list[Completed]: The finished calls in the order they finished, maybe none.\n"              //
    "\n"                                                                                           //
    "Raises:\n"                                                                                    //
    "  Error: An I/O failure, or `Status.INVALID_ARGUMENT` from another thread.\n"                 //
    "\n"                                                                                           //
    "Example:\n"                                                                                   //
    "  >>> finished = []\n"                                                                        //
    "  >>> while len(finished) != 4:\n"                                                            //
    "  ...     finished += client.take_completed(timeout_microseconds=1_000_000)";

static PyObject* Client_take_completed(Client* self, PyObject* const* values, Py_ssize_t count, PyObject* names) {
    PyObject *timeout = NULL, *capacity_object = NULL;
    ucall_py_argument_t const arguments[] = {{"timeout_microseconds", &timeout}, {"capacity", &capacity_object}};
    if (ucall_py_parse_fast("take_completed", values, count, names, 0, 2, arguments, 2) != 0 || client_owned(self) != 0)
        return NULL;
    size_t microseconds = 0, capacity = 64;
    if (ucall_py_size_from_object(timeout, "timeout_microseconds", &microseconds) != 0 ||
        ucall_py_size_from_object(capacity_object, "capacity", &capacity) != 0)
        return NULL;
    Py_ssize_t const buffered = PyList_GET_SIZE(self->buffered);
    if (!buffered) return client_take(self, microseconds, capacity);
    Py_ssize_t const handed = capacity < (size_t)buffered ? (Py_ssize_t)capacity : buffered;
    PyObject* const taken = PyList_GetSlice(self->buffered, 0, handed);
    if (!taken || PyList_SetSlice(self->buffered, 0, handed, NULL) != 0) {
        Py_XDECREF(taken);
        return NULL;
    }
    return taken;
}

/**
 *  @brief Submits one exchange and polls until its own completion, buffering every other one.
 *  @return The @c Response, or NULL with an exception set, a @c ucall.Error for a failed exchange.
 */
static PyObject* client_request(Client* self, ucall_verb_t verb, PyObject* url, PyObject* body, PyObject* json,
                                PyObject* headers, call_options_t const* options) {
    if (client_owned(self) != 0) return NULL;
    PyObject *encoded = NULL, *lines = NULL;
    if (json && json != Py_None) {
        encoded = ucall_py_json_from_object(json);
        lines = !encoded ? NULL : headers ? PySequence_List(headers) : PyList_New(0);
        PyObject* const line = lines ? PyUnicode_FromString("content-type: application/json") : NULL;
        if (!line || PyList_Append(lines, line) != 0) {
            Py_XDECREF(line);
            Py_XDECREF(lines);
            Py_XDECREF(encoded);
            return NULL;
        }
        Py_DECREF(line);
        body = encoded;
        headers = lines;
    }
    // The call keeps its own references to the body and header lines it borrows.
    Completed* const own = client_submit(self, verb, url, body, headers, options, NULL);
    Py_XDECREF(lines);
    Py_XDECREF(encoded);
    if (!own) return NULL;
    Py_INCREF(own);
    int failed = 0;
    while (!failed && own->status == ucall_status_deferred_k) {
        PyObject* const taken = client_take(self, ucall_py_interrupt_period_microseconds_k, 64);
        Py_ssize_t const taken_count = taken ? PyList_GET_SIZE(taken) : 0;
        failed = !taken;
        for (Py_ssize_t index = 0; !failed && index != taken_count; ++index) {
            PyObject* const completed = PyList_GET_ITEM(taken, index);
            if (completed != (PyObject*)own) failed = PyList_Append(self->buffered, completed) != 0;
        }
        Py_XDECREF(taken);
        if (!failed && own->status == ucall_status_deferred_k) failed = PyErr_CheckSignals() != 0;
    }
    PyObject* response = NULL;
    if (!failed && own->status != ucall_status_success_k) ucall_py_raise_status(own->status, own->message);
    else if (!failed) response = Py_NewRef(own->response ? own->response : Py_None);
    Py_DECREF(own);
    return response;
}

static char const doc_Client_request[] =                                                                    //
    "request(verb, url, /, body=b\"\", *, json=None, headers=(), security=Security.NONE,\n"                 //
    "    noise_peer_key=None, noise_private_key=None, timeout_microseconds=0, max_retries=0,\n"             //
    "    max_redirects=0) -> Response\n"                                                                    //
    "\n"                                                                                                    //
    "Sends one exchange and waits for its response on this thread.\n"                                       //
    "\n"                                                                                                    //
    "It polls in slices of 100 ms, checking for signals between them, and keeps every other\n"              //
    "call it finishes meanwhile for the next `take_completed`.\n"                                           //
    "\n"                                                                                                    //
    "Args:\n"                                                                                               //
    "  verb (Verb): The method, such as `Verb.POST` or \"post\".\n"                                         //
    "  url (str | bytes): The full URL, \"http://\" or \"http+noise://\" and the server.\n"                 //
    "  body (Buffer, optional): Any bytes-like object to send.\n"                                           //
    "  json (object, optional): A value to send as JSON in place of `body`, with its content\n"             //
    "    type; None sends `body`.\n"                                                                        //
    "  headers (Sequence[str | bytes], optional): \"name: value\" lines.\n"                                 //
    "  security (Security, optional): The handshake for this call. Defaults to `Security.NONE`.\n"          //
    "  noise_peer_key (bytes, optional): The server's 32-byte static key, for `Security.NOISE_IK`\n"        //
    "    and `Security.NOISE_KK`.\n"                                                                        //
    "  noise_private_key (bytes, optional): This call's 32-byte Noise private key in place of the\n"        //
    "    client's own, as `Security.NOISE_KK` names the caller to the server.\n"                            //
    "  timeout_microseconds (int, optional): The budget of this call, queueing and redirects included;\n"   //
    "    0 takes the client's `call_timeout_microseconds`.\n"                                               //
    "  max_retries (int, optional): Connection attempts before sending; 0 takes 3.\n"                       //
    "  max_redirects (int, optional): Redirect hops followed before failing; 0 takes 5.\n"                  //
    "\n"                                                                                                    //
    "Returns:\n"                                                                                            //
    "  Response: The response, whatever its HTTP status.\n"                                                 //
    "\n"                                                                                                    //
    "Raises:\n"                                                                                             //
    "  Error: The exchange failed, such as `Status.CONNECTION_FAILED` or `Status.TIMEOUT`.\n"               //
    "  KeyboardInterrupt: Ctrl+C arrived while waiting; the call completes later, unclaimed.\n"             //
    "\n"                                                                                                    //
    "Example:\n"                                                                                            //
    "  >>> response = client.request(\"POST\", \"http://127.0.0.1:8545/sum\", json={\"a\": 1, \"b\": 2})\n" //
    "  >>> response.status_code\n"                                                                          //
    "  200";

static PyObject* Client_request(Client* self, PyObject* const* values, Py_ssize_t count, PyObject* names) {
    PyObject *verb = NULL, *url = NULL, *body = NULL, *json = NULL, *headers = NULL;
    call_options_t options;
    ucall_py_argument_t const arguments[] = {
        {"verb", &verb},
        {"url", &url},
        {"body", &body},
        {"json", &json},
        {"headers", &headers},
        {"security", &options.security},
        {"noise_peer_key", &options.noise_peer_key},
        {"noise_private_key", &options.noise_private_key},
        {"timeout_microseconds", &options.timeout},
        {"max_retries", &options.retries},
        {"max_redirects", &options.redirects},
    };
    if (ucall_py_parse_fast("request", values, count, names, 2, 3, arguments,
                            sizeof(arguments) / sizeof(arguments[0])) != 0)
        return NULL;
    int verb_value = 0;
    if (ucall_py_enum_from_object(verb, "verb", &ucall_py_verb_enum, &verb_value) != 0) return NULL;
    return client_request(self, (ucall_verb_t)verb_value, url, body, json, headers, &options);
}

/** Parses the arguments of `get` and its siblings, differing in @p verb and where `body` binds. */
static PyObject* client_verb(Client* self, char const* name, ucall_verb_t verb, Py_ssize_t positional_max,
                             PyObject* const* values, Py_ssize_t count, PyObject* names) {
    PyObject *url = NULL, *body = NULL, *json = NULL, *headers = NULL;
    call_options_t options;
    ucall_py_argument_t const arguments[] = {
        {"url", &url},
        {"body", &body},
        {"json", &json},
        {"headers", &headers},
        {"security", &options.security},
        {"noise_peer_key", &options.noise_peer_key},
        {"noise_private_key", &options.noise_private_key},
        {"timeout_microseconds", &options.timeout},
        {"max_retries", &options.retries},
        {"max_redirects", &options.redirects},
    };
    if (ucall_py_parse_fast(name, values, count, names, 1, positional_max, arguments,
                            sizeof(arguments) / sizeof(arguments[0])) != 0)
        return NULL;
    return client_request(self, verb, url, body, json, headers, &options);
}

static char const doc_Client_get[] =                                                                      //
    "get(url, /, *, body=b\"\", json=None, headers=(), security=Security.NONE, noise_peer_key=None,\n"    //
    "    noise_private_key=None, timeout_microseconds=0, max_retries=0, max_redirects=0) -> Response\n"   //
    "\n"                                                                                                  //
    "Sends a GET and waits for its response, as `request` does.\n"                                        //
    "\n"                                                                                                  //
    "Args:\n"                                                                                             //
    "  url (str | bytes): The full URL.\n"                                                                //
    "  **options: `body`, `json`, `headers`, `security`, the keys and limits, as `request` takes them.\n" //
    "\n"                                                                                                  //
    "Returns:\n"                                                                                          //
    "  Response: The response, whatever its HTTP status.\n"                                               //
    "\n"                                                                                                  //
    "Raises:\n"                                                                                           //
    "  Error: The exchange failed.\n"                                                                     //
    "\n"                                                                                                  //
    "Example:\n"                                                                                          //
    "  >>> bytes(client.get(\"http://127.0.0.1:8545/sum?a=1&b=2\").body)\n"                               //
    "  b'3'";

static PyObject* Client_get(Client* self, PyObject* const* values, Py_ssize_t count, PyObject* names) {
    return client_verb(self, "get", ucall_verb_get_k, 1, values, count, names);
}

static char const doc_Client_post[] =                                                                   //
    "post(url, /, body=b\"\", *, json=None, headers=(), security=Security.NONE, noise_peer_key=None,\n" //
    "    noise_private_key=None, timeout_microseconds=0, max_retries=0, max_redirects=0) -> Response\n" //
    "\n"                                                                                                //
    "Sends a POST and waits for its response, as `request` does.\n"                                     //
    "\n"                                                                                                //
    "Args:\n"                                                                                           //
    "  url (str | bytes): The full URL.\n"                                                              //
    "  body (Buffer, optional): Any bytes-like object to send.\n"                                       //
    "  **options: `json`, `headers`, `security`, the keys and limits, as `request` takes them.\n"       //
    "\n"                                                                                                //
    "Returns:\n"                                                                                        //
    "  Response: The response, whatever its HTTP status.\n"                                             //
    "\n"                                                                                                //
    "Raises:\n"                                                                                         //
    "  Error: The exchange failed.\n"                                                                   //
    "\n"                                                                                                //
    "Example:\n"                                                                                        //
    "  >>> bytes(client.post(\"http://127.0.0.1:8545/sum\", json={\"a\": 1, \"b\": 2}).body)\n"         //
    "  b'3.0'";

static PyObject* Client_post(Client* self, PyObject* const* values, Py_ssize_t count, PyObject* names) {
    return client_verb(self, "post", ucall_verb_post_k, 2, values, count, names);
}

static char const doc_Client_put[] =                                                                    //
    "put(url, /, body=b\"\", *, json=None, headers=(), security=Security.NONE, noise_peer_key=None,\n"  //
    "    noise_private_key=None, timeout_microseconds=0, max_retries=0, max_redirects=0) -> Response\n" //
    "\n"                                                                                                //
    "Sends a PUT and waits for its response, as `request` does.\n"                                      //
    "\n"                                                                                                //
    "Args:\n"                                                                                           //
    "  url (str | bytes): The full URL.\n"                                                              //
    "  body (Buffer, optional): Any bytes-like object to send.\n"                                       //
    "  **options: `json`, `headers`, `security`, the keys and limits, as `request` takes them.\n"       //
    "\n"                                                                                                //
    "Returns:\n"                                                                                        //
    "  Response: The response, whatever its HTTP status.\n"                                             //
    "\n"                                                                                                //
    "Raises:\n"                                                                                         //
    "  Error: The exchange failed.\n"                                                                   //
    "\n"                                                                                                //
    "Example:\n"                                                                                        //
    "  >>> client.put(\"http://127.0.0.1:8545/files/notes.txt\", b\"hello\").status_code\n"             //
    "  200";

static PyObject* Client_put(Client* self, PyObject* const* values, Py_ssize_t count, PyObject* names) {
    return client_verb(self, "put", ucall_verb_put_k, 2, values, count, names);
}

static char const doc_Client_delete[] =                                                                   //
    "delete(url, /, *, body=b\"\", json=None, headers=(), security=Security.NONE, noise_peer_key=None,\n" //
    "    noise_private_key=None, timeout_microseconds=0, max_retries=0, max_redirects=0) -> Response\n"   //
    "\n"                                                                                                  //
    "Sends a DELETE and waits for its response, as `request` does.\n"                                     //
    "\n"                                                                                                  //
    "Args:\n"                                                                                             //
    "  url (str | bytes): The full URL.\n"                                                                //
    "  **options: `body`, `json`, `headers`, `security`, the keys and limits, as `request` takes them.\n" //
    "\n"                                                                                                  //
    "Returns:\n"                                                                                          //
    "  Response: The response, whatever its HTTP status.\n"                                               //
    "\n"                                                                                                  //
    "Raises:\n"                                                                                           //
    "  Error: The exchange failed.\n"                                                                     //
    "\n"                                                                                                  //
    "Example:\n"                                                                                          //
    "  >>> client.delete(\"http://127.0.0.1:8545/files/notes.txt\").status_code\n"                        //
    "  204";

static PyObject* Client_delete(Client* self, PyObject* const* values, Py_ssize_t count, PyObject* names) {
    return client_verb(self, "delete", ucall_verb_delete_k, 1, values, count, names);
}

static char const doc_Client_patch[] =                                                                      //
    "patch(url, /, body=b\"\", *, json=None, headers=(), security=Security.NONE, noise_peer_key=None,\n"    //
    "    noise_private_key=None, timeout_microseconds=0, max_retries=0, max_redirects=0) -> Response\n"     //
    "\n"                                                                                                    //
    "Sends a PATCH and waits for its response, as `request` does.\n"                                        //
    "\n"                                                                                                    //
    "Args:\n"                                                                                               //
    "  url (str | bytes): The full URL.\n"                                                                  //
    "  body (Buffer, optional): Any bytes-like object to send.\n"                                           //
    "  **options: `json`, `headers`, `security`, the keys and limits, as `request` takes them.\n"           //
    "\n"                                                                                                    //
    "Returns:\n"                                                                                            //
    "  Response: The response, whatever its HTTP status.\n"                                                 //
    "\n"                                                                                                    //
    "Raises:\n"                                                                                             //
    "  Error: The exchange failed.\n"                                                                       //
    "\n"                                                                                                    //
    "Example:\n"                                                                                            //
    "  >>> client.patch(\"http://127.0.0.1:8545/users/ada\", json={\"alias\": \"countess\"}).status_code\n" //
    "  200";

static PyObject* Client_patch(Client* self, PyObject* const* values, Py_ssize_t count, PyObject* names) {
    return client_verb(self, "patch", ucall_verb_patch_k, 2, values, count, names);
}

static PyMethodDef Client_methods[] = {
    {"request", (PyCFunction)(void (*)(void))Client_request, ucall_py_method_flags_k, doc_Client_request},
    {"get", (PyCFunction)(void (*)(void))Client_get, ucall_py_method_flags_k, doc_Client_get},
    {"post", (PyCFunction)(void (*)(void))Client_post, ucall_py_method_flags_k, doc_Client_post},
    {"put", (PyCFunction)(void (*)(void))Client_put, ucall_py_method_flags_k, doc_Client_put},
    {"delete", (PyCFunction)(void (*)(void))Client_delete, ucall_py_method_flags_k, doc_Client_delete},
    {"patch", (PyCFunction)(void (*)(void))Client_patch, ucall_py_method_flags_k, doc_Client_patch},
    {"submit", (PyCFunction)(void (*)(void))Client_submit, ucall_py_method_flags_k, doc_Client_submit},
    {"take_completed", (PyCFunction)(void (*)(void))Client_take_completed, ucall_py_method_flags_k,
     doc_Client_take_completed},
    {NULL, NULL, 0, NULL},
};

PyTypeObject ClientType = {
    PyVarObject_HEAD_INIT(NULL, 0).tp_name = "ucall.Client",
    .tp_basicsize = sizeof(Client),
    .tp_flags = Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE | Py_TPFLAGS_HAVE_GC,
    .tp_doc = doc_Client,
    .tp_new = Client_new,
    .tp_traverse = (traverseproc)Client_traverse,
    .tp_clear = (inquiry)Client_clear,
    .tp_dealloc = (destructor)Client_dealloc,
    .tp_methods = Client_methods,
};

#pragma endregion Client
