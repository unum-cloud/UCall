/**
 *  @file python/lib.h
 *  @author Ash Vardanian
 *  @date January 30, 2023
 *  @brief Declarations shared by every UCall CPython translation unit.
 *
 *  One extension, one file per header of the C interface: @c types.c owns statuses, enums, the
 *  error type and Noise keys, @c server.c owns interfaces, servers, requests and batch endpoints,
 *  @c client.c owns clients, completions and responses, and @c lib.c owns the argument parsing,
 *  enum mirrors and error mapping every file shares, with the module glue. A Python object's
 *  structure takes its class name, @c Server for @c ucall.Server, and its type object
 *  @c ServerType. A helper shared through this header takes the @c ucall_py_ prefix, and one a
 *  file keeps to itself takes none.
 *
 *  @section python_polling Polling Owners
 *
 *  UCall creates no threads, and neither does this module. Application threads call the polling
 *  verbs, @c Server.take_call, @c take_calls and @c run, @c BatchEndpoint.take_batch and
 *  @c take_batches, and @c Client.take_completed with the blocking calls built on it, each
 *  dropping the interpreter lock for the length of the C call. Endpoint callbacks, batch
 *  callbacks and peer authorizers take it back with @c PyGILState_Ensure on whichever thread is
 *  polling. An exception escaping a handler goes to @c sys.unraisablehook, and every request it
 *  left unanswered gets a 500, so one faulty handler never stops a loop. A call that blocks for
 *  the application, @c run and the blocking client calls, waits in slices of
 *  @c ucall_py_interrupt_period_microseconds_k, checking for signals between them for Ctrl+C.
 *
 *  @section python_handlers Typed Handlers
 *
 *  Registering a handler resolves its signature once, through @c inspect.signature and
 *  @c typing.get_type_hints, into a table of parameters kept in the endpoint's context. A handler
 *  taking one parameter annotated @c Request receives the request object. Any other handler is
 *  called with keyword arguments bound per request in C: a path placeholder, then the query,
 *  percent-decoded, then a JSON object body parsed once, then the default. A value that does not
 *  convert, or a missing one, answers 400 without calling the handler, and no request object is
 *  ever made for such a handler. Return values become replies in C too: bytes-like objects as
 *  binary, @c str as UTF-8 text, None from a typed handler as 204, and everything else as JSON.
 *
 *  @section python_requests Request Lifetime
 *
 *  A @c Request owns its C handle until a reply consumes it, and holds its @c Server so the server
 *  outlives every retained request. Its body is exported through the buffer protocol without a
 *  copy, and a reply is refused while any such view is alive, as a @c bytearray refuses to resize,
 *  because the reply frees the bytes under it. The one view a reply accepts is the request's own
 *  body passed as the reply body, which the reply releases before answering. A request dropped
 *  without a reply answers 500 itself.
 *
 *  @c Request.detach moves the handle into a @c DetachedRequest, the only owner of the verbs whose
 *  replies may defer, so by type a @c Deferred, which waits when released, never comes to be on a
 *  polling thread. A @c Deferred keeps its outcome on the heap with the @c File parts it borrows,
 *  and the memoryview of a part or a body chunk counts among its request's exports as @c body does.
 *
 *  @section python_clients Client Calls
 *
 *  Every accepted call is a @c Completed object whose address is the C cookie. It holds the URL,
 *  headers, body and key the client borrows until retrieval, and links into its client's in-flight
 *  list so a client freed with calls outstanding can release them after @c ucall_client_free
 *  returns. A blocking call polls until its own @c Completed is retrieved and keeps every other one
 *  for the next @c take_completed.
 *
 *  @section python_calling_convention Arguments Parsing
 *
 *  No PyBind11, NanoBind or SWIG, only the CPython API, and never @c PyArg_ParseTupleAndKeywords,
 *  whose format specifiers are parsed at runtime and which cannot use the fast calling convention.
 *  Every verb taking more than one argument is @c METH_FASTCALL | @c METH_KEYWORDS and binds its
 *  arguments through one table of names, @c ucall_py_parse_fast.
 */
#ifndef UNUM_UCALL_PYTHON_LIB_H
#define UNUM_UCALL_PYTHON_LIB_H

#include <Python.h>

#include <stddef.h> // `size_t`, `offsetof`
#include <string.h> // `memcpy`, `memset`, `strlen`

#include "ucall/ucall.h"

#pragma region Free Threading

/** Serializes threads on one object where no interpreter lock does; the lock does it otherwise. */
typedef struct ucall_py_section_t {
#ifdef Py_GIL_DISABLED
    PyCriticalSection section;
#else
    char unused;
#endif
} ucall_py_section_t;

static inline void ucall_py_section_begin([[maybe_unused]] ucall_py_section_t* section,
                                          [[maybe_unused]] PyObject* object) {
#ifdef Py_GIL_DISABLED
    PyCriticalSection_Begin(&section->section, object);
#endif
}

static inline void ucall_py_section_end([[maybe_unused]] ucall_py_section_t* section) {
#ifdef Py_GIL_DISABLED
    PyCriticalSection_End(&section->section);
#endif
}

/** Tells a free-threaded interpreter that @p module runs without its lock; a no-op otherwise. */
static inline int ucall_py_module_without_lock([[maybe_unused]] PyObject* module) {
#ifdef Py_GIL_DISABLED
    return PyUnstable_Module_SetGIL(module, Py_MOD_GIL_NOT_USED);
#else
    return 0;
#endif
}

#pragma endregion Free Threading

#pragma region Arguments

/** Compile-time constants of the binding layer. */
enum {

    /** Fast-call plus keywords, the calling convention of every verb with several arguments. */
    ucall_py_method_flags_k = METH_FASTCALL | METH_KEYWORDS,

    /** The longest a blocking call stays in C, where Python cannot raise @c KeyboardInterrupt. */
    ucall_py_interrupt_period_microseconds_k = 100000,
};

/** One argument a verb takes and the slot its borrowed value lands in; a skipped one stays NULL. */
typedef struct ucall_py_argument_t {

    /** The keyword spelling, which also names the argument in every refusal. */
    char const* name;

    /** Where the borrowed value lands. */
    PyObject** value;
} ucall_py_argument_t;

/**
 *  @brief Binds a fast call's arguments, refusing unknown names, duplicates and missing ones.
 *
 *  The first @p required arguments bind by position alone and must be given; the ones after them
 *  up to @p positional_max bind by position or by name; the rest bind by name alone.
 *
 *  @return 0 on success, -1 with a @c TypeError set otherwise.
 */
int ucall_py_parse_fast(char const* verb, PyObject* const* values, Py_ssize_t values_count, PyObject* names,
                        Py_ssize_t required, Py_ssize_t positional_max, ucall_py_argument_t const* arguments,
                        size_t count);

/** The constructor counterpart of @c ucall_py_parse_fast, reading a tuple and a dictionary. */
int ucall_py_parse_tuple(char const* verb, PyObject* positional, PyObject* keywords, Py_ssize_t required,
                         Py_ssize_t positional_max, ucall_py_argument_t const* arguments, size_t count);

/** Reads a non-negative integer into @p output, leaving it untouched when @p object is NULL. */
int ucall_py_size_from_object(PyObject* object, char const* field, size_t* output);

/** Views @p object, a @c str as UTF-8 or a @c bytes as is; the view lives as long as the object. */
int ucall_py_text_from_object(PyObject* object, char const* field, ucall_bytes_view_t* view);

/** Copies a 32-byte Noise key out of @p object, refusing any other length. */
int ucall_py_key_from_object(PyObject* object, char const* field, ucall_noise_key_t key);

/** Header lines a call borrows: the sequence keeping each line alive and the views over them. */
typedef struct ucall_py_header_lines_t {

    /** The fast sequence of @c str or @c bytes lines, or NULL for none. */
    PyObject* sequence;

    /** One view per line, over the objects @c sequence keeps alive. */
    ucall_bytes_view_t* views;

    /** Entries in @c views. */
    size_t count;
} ucall_py_header_lines_t;

/** Views every "name: value" line of @p object, a sequence of @c str or @c bytes, or NULL. */
int ucall_py_header_lines_from_object(PyObject* object, ucall_py_header_lines_t* lines);

/** Returns what @c ucall_py_header_lines_from_object took, leaving @p lines empty. */
void ucall_py_header_lines_release(ucall_py_header_lines_t* lines);

/** Decodes received bytes as UTF-8, keeping invalid bytes recoverable as surrogate escapes. */
PyObject* ucall_py_text_to_object(ucall_bytes_view_t view);

/** A getter of the optional object field at offset @p closure, answering None while it is NULL. */
PyObject* ucall_py_get_optional(PyObject* self, void* closure);

#pragma endregion Arguments

#pragma region Vocabulary

/** A C enum mirrored as an `enum.IntEnum`, its members spelled by a C name table. */
typedef struct ucall_py_enum_mirror_t {

    /** The class name in the module, such as "Status". */
    char const* name;

    /** The class docstring. */
    char const* doc;

    /** The smallest enumerator. */
    int first;

    /** The largest enumerator; values in between without a spelling have no member. */
    int last;

    /** Spells one value, answering "unrecognized" for a gap. */
    char const* (*spell)(int);

    /** The `enum.IntEnum` subclass, built at module init. */
    PyObject* type;
} ucall_py_enum_mirror_t;

/** The outcome of every verb, as `ucall.Status`. */
extern ucall_py_enum_mirror_t ucall_py_status_enum;

/** The I/O implementations, as `ucall.Backend`. */
extern ucall_py_enum_mirror_t ucall_py_backend_enum;

/** The CPU kernel classes, as `ucall.CPUClass`. */
extern ucall_py_enum_mirror_t ucall_py_cpu_class_enum;

/** The transport security modes, as `ucall.Security`. */
extern ucall_py_enum_mirror_t ucall_py_security_enum;

/** The HTTP methods, as `ucall.Verb`. */
extern ucall_py_enum_mirror_t ucall_py_verb_enum;

/** When an endpoint's callback runs, as @c ucall.BodyDelivery. */
extern ucall_py_enum_mirror_t ucall_py_body_delivery_enum;

/** The severities of log lines, as @c ucall.LogLevel. */
extern ucall_py_enum_mirror_t ucall_py_log_level_enum;

/** The spellings of log lines, as @c ucall.LogFormat. */
extern ucall_py_enum_mirror_t ucall_py_log_format_enum;

/**
 *  @brief Builds every enum mirror as an `enum.IntEnum` and adds it to @p module.
 *  @return 0 on success, or -1 with an exception set.
 */
int ucall_py_enums_register(PyObject* module);

/** Reads a member of @p mirror from an `int` or a name such as "POST" or "linux-epollaio". */
int ucall_py_enum_from_object(PyObject* object, char const* field, ucall_py_enum_mirror_t const* mirror, int* value);

/** The member of @p mirror valued @p value, or a plain `int` for a value it does not name. */
PyObject* ucall_py_enum_to_object(ucall_py_enum_mirror_t const* mirror, long value);

/** Raises a @c ucall.Error for @p status, spelling the message from the status when C gave none. */
PyObject* ucall_py_raise_status(ucall_status_t status, char const* message);

/** Returns 0 for a successful outcome, or -1 with its @c ucall.Error raised. */
int ucall_py_raise_outcome(ucall_outcome_t const* outcome);

/** Reports a handler's exception without stopping the poller, re-arming Ctrl+C for Python. */
void ucall_py_report_handler_failure(PyObject* handler);

/** Hands one log line to the Python callable @p context, as a @c ucall_log_t callback, from
 *  whichever thread wrote it. */
void ucall_py_log(ucall_log_level_t level, ucall_bytes_view_t line, void* context);

/**
 *  @brief Reads the @c log, @c log_level and @c log_format arguments into @p log.
 *  @return 0 on success, or -1 with an exception set.
 */
int ucall_py_log_from_objects(PyObject* callback, PyObject* level, PyObject* format, ucall_log_t* log);

/** Calls a Python `peer_authorizer(static_key)`, truthy to admit, from the handshaking thread. */
ucall_status_t ucall_py_authorize_peer(ucall_noise_key_t const* peer_static_key, void* context);

/** `json.dumps`, imported once at module init, which replies and client calls serialize with. */
extern PyObject* ucall_py_json_dumps;

/** `json.loads`, imported once at module init, which typed handlers parse request bodies with. */
extern PyObject* ucall_py_json_loads;

/** The address a server without interfaces answers on, exported as `ucall.DEFAULT_ADDRESS`. */
extern char const ucall_py_default_address_k[];

/** The module-level Noise key functions, added to the module at init. */
extern PyMethodDef ucall_py_noise_methods[];

/** `ucall.Error`, a @c RuntimeError carrying a @c Status. */
extern PyTypeObject ErrorType;

/** `ucall.Interface`, one address a server answers on. */
extern PyTypeObject InterfaceType;

/** `ucall.Server`, polled by application threads. */
extern PyTypeObject ServerType;

/** The C handle of @p server, a @c ucall.Server. */
ucall_server_t ucall_py_server_handle(PyObject* server);

/** `ucall.Request`, one received request until a reply consumes it. */
extern PyTypeObject RequestType;

/** @c ucall.DetachedRequest, a request taken off its polling thread, with the verbs that may
 *  defer. */
extern PyTypeObject DetachedRequestType;

/** @c ucall.RequestPart, one part of a multipart request body. */
extern PyTypeObject RequestPartType;

/** A view over bytes a request owns, counted among the request's exports. */
extern PyTypeObject RequestBytesType;

/** @c ucall.BodyChunks, the iterator pulling a detached request's body. */
extern PyTypeObject BodyChunksType;

/** @c ucall.File, a byte range of a descriptor the caller opened, as a reply part. */
extern PyTypeObject FileType;

/** @c ucall.Path, a byte range of a file beneath a reply directory, as a reply part. */
extern PyTypeObject PathType;

/** @c ucall.Deferred, a reply still sending file or path parts. */
extern PyTypeObject DeferredType;

/** @c ucall.ReplyStream, a reply sent in appended parts. */
extern PyTypeObject ReplyStreamType;

/** @c ucall.Metrics, where a server sends StatsD datagrams. */
extern PyTypeObject MetricsType;

/** @c ucall.BatchEndpoint, one batching route and its polling verbs. */
extern PyTypeObject BatchEndpointType;

/** The context of one plain route: its handler and the parameter table resolved at registration. */
extern PyTypeObject EndpointType;

/** `ucall.Client`, owned by the thread that created it. */
extern PyTypeObject ClientType;

/** `ucall.Completed`, the final result of one client call. */
extern PyTypeObject CompletedType;

/** `ucall.Response`, one received response. */
extern PyTypeObject ResponseType;

#pragma endregion Vocabulary

#endif // UNUM_UCALL_PYTHON_LIB_H
