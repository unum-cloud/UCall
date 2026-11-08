"""The Mojo binding's tests: the library's name tables and helpers, then a server on a loopback port
driven by a client bound to its event loop, all on one thread.

Mojo has no test discovery, so every check below is registered in `main`, and one that is not
silently never runs.

File: mojo/test.mojo
Author: Ash Vardanian
Date: November 8, 2026
"""

from std.memory import stack_allocation
from std.testing import TestSuite, assert_equal, assert_false, assert_true

from ucall import (
    Backend,
    Batch,
    BytesView,
    CPUClass,
    Client,
    ClientCall,
    ClientOptions,
    Completed,
    HTTPStatus,
    Interface,
    Library,
    Log,
    LogLevel,
    NoiseKey,
    PeerAuthorizer,
    PercentMode,
    ReplyPart,
    Request,
    Security,
    Server,
    ServerOptions,
    Status,
    Verb,
)


def _text(bytes: Span[Byte, _]) -> String:
    """The bytes as a string, for comparing a body against the text expected."""
    return String(unsafe_from_utf8=bytes)


# region Library


def test_names_come_from_the_library() raises:
    """Every enumeration is spelled by the library's own tables, and read back from that spelling."""
    var library = Library()
    assert_equal(library.status_name(Status.OUT_OF_MEMORY), "out-of-memory")
    assert_true(library.status_from_name("would-block") == Status.WOULD_BLOCK, "a status reads back")
    assert_equal(library.io_backend_name(Backend.LINUX_URING618), "linux-uring618")
    assert_true(library.io_backend_from_name("linux-epollaio") == Backend.LINUX_EPOLLAIO, "a backend reads back")
    assert_equal(library.cpu_class_name(CPUClass.AWS_G5), "aws-g5")
    assert_true(library.cpu_class_from_name("serial") == CPUClass.SERIAL, "a CPU class reads back")
    assert_equal(library.version()[0], 1, "the binding loads only its own major")
    assert_true(library.version_name().startswith("1."), "the version name carries the major")


def test_percent_escapes_decode_by_mode() raises:
    """Only a query spells a space '+', and a '%' without two hexadecimal digits is refused."""
    var library = Library()
    assert_equal(_text(library.decode_percent("caf%C3%A9+au+lait".as_bytes(), PercentMode.QUERY)), "café au lait")
    assert_equal(_text(library.decode_percent("a+b".as_bytes(), PercentMode.PATH)), "a+b")
    var refusal = Status.SUCCESS
    try:
        _ = library.decode_percent("100%".as_bytes(), PercentMode.PATH)
    except error:
        refusal = error.status
    assert_true(refusal == Status.INVALID_ARGUMENT, "a dangling '%' is an invalid argument")


def test_generated_noise_keys_derive_back() raises:
    """A generated private key derives the public key generated with it."""
    var library = Library()
    var keys = library.generate_noise_keypair()
    var derived = library.derive_noise_public_key(keys[0])
    for index in range(32):
        assert_equal(derived[index], keys[1][index], "the derived key matches the generated one")


# endregion Library

# region Server and Client


def _owned(bytes: Span[Byte, _]) -> List[Byte]:
    """A copy of borrowed bytes, for a reply that consumes the request they borrow from."""
    var copy = List[Byte](capacity=len(bytes))
    for byte in bytes:
        copy.append(byte)
    return copy^


def hello(var request: Request) raises:
    """Answers every GET with a fixed greeting."""
    request^.reply(HTTPStatus.OK, "Hello!".as_bytes())


def echo(var request: Request) raises:
    """Answers a POST with its own body."""
    var body = _owned(request.body())
    request^.reply(HTTPStatus.OK, body)


def missing(var request: Request) raises:
    """Answers with an error reply of its own."""
    request^.reply_error(HTTPStatus.NOT_FOUND, "no such page")


def failing(var request: Request) raises:
    """Raises instead of replying, so the request drops and answers 500."""
    raise Error("the handler gave up")


def parts(var request: Request) raises:
    """Detaches the request and answers with two byte parts concatenated."""
    var no_headers = List[BytesView[ImmUntrackedOrigin]]()
    var pieces = [ReplyPart.bytes("first, ".as_bytes()), ReplyPart.bytes("second".as_bytes())]
    _ = request^.detach().reply_parts(HTTPStatus.OK, no_headers, pieces)


def chunks(var request: Request) raises:
    """Pulls the body through `body_chunk`, which on a buffered route answers it whole, then empty."""
    var detached = request^.detach()
    var body = List[Byte]()
    while True:
        var chunk = detached.body_chunk()
        if len(chunk) == 0:
            break
        for byte in chunk:
            body.append(byte)
    detached^.reply(HTTPStatus.OK, body)


def score(batch: Batch) raises:
    """Answers every request of a batch with the length of its body."""
    for index in range(len(batch)):
        var request = batch.take(index)
        var length = String(len(request.body()))
        request^.reply(HTTPStatus.OK, length.as_bytes())


def count_line(level: LogLevel, line: StringSlice[ImmUntrackedOrigin], mut lines: Int):
    """Counts the server's log lines."""
    lines += 1


def test_server_answers_a_bound_client() raises:
    """A server on a free loopback port answers plain, detached, chunked and batched routes, polled
    on this thread together with the batch endpoint and the client its event loop drives."""
    var library = Library()
    var lines = stack_allocation[1, Int]().unsafe_origin_cast[MutAnyOrigin]()
    lines[] = 0
    var server_options = ServerOptions()
    server_options.log = Log.to[count_line](lines[])
    var server = Server(library, [Interface("127.0.0.1:0", connections=8)], server_options)
    server.get["/hello", hello]()
    server.post["/echo", echo]()
    server.get["/missing", missing]()
    server.get["/failing", failing]()
    server.get["/parts", parts]()
    server.post["/chunks", chunks]()
    var scores = server.batch["/score", score](Verb.POST)
    var origin = String("http://", server.address(0).value())

    var options = ClientOptions(connections=8)
    options.calls = 7
    var client = Client(server, options, event_loop=0)
    client.submit(ClientCall.get(origin + "/hello"), 0)
    client.submit(ClientCall.post(origin + "/echo", "ping".as_bytes()), 1)
    client.submit(ClientCall.get(origin + "/missing"), 2)
    client.submit(ClientCall.get(origin + "/failing"), 3)
    client.submit(ClientCall.get(origin + "/parts"), 4)
    client.submit(ClientCall.post(origin + "/chunks", "chunked body".as_bytes()), 5)
    client.submit(ClientCall.post(origin + "/score", "seven..".as_bytes()), 6)

    var expected_status: List[UInt32] = [200, 200, 404, 500, 200, 200, 200]
    var expected_body: List[String] = ["Hello!", "ping", "no such page", "", "first, second", "chunked body", "7"]
    var remaining = 7
    var completed = List[Completed]()
    var rounds = 0
    while remaining > 0 and rounds < 500:
        rounds += 1
        _ = server.take_call(0, 10_000)
        scores.take_batch(0)
        client.take_completed(completed)
        for position in range(len(completed)):
            ref done = completed[position]
            assert_false(Bool(done.error), "every call completes with a response")
            ref response = done.response.value()
            var index = Int(done.context)
            remaining -= 1
            assert_equal(response.status_code().code, expected_status[index], String("call ", index))
            if index != 3:
                assert_equal(_text(response.body()), expected_body[index], String("call ", index))
    assert_equal(remaining, 0, "every call was answered within the rounds allowed")
    assert_true(server.event_loop_statistics(0).requests >= 7, "the loop counted every request")
    assert_equal(Int(scores.statistics().requests), 1, "the batch endpoint took its request")
    assert_true(lines[] > 0, "the log sink heard the server")
    # A bound client must go first, as the server is not freed while one lives.
    _ = completed^
    _ = client^
    server.stop()


def admit_every_key(peer_static_key: NoiseKey) -> Bool:
    """Admits every authenticated peer."""
    return True


def reject_every_key(peer_static_key: NoiseKey) -> Bool:
    """Rejects every authenticated peer."""
    return False


def test_noise_authorizers_admit_and_reject() raises:
    """Over Noise XX, an interface whose authorizer admits answers, and one whose authorizer rejects
    fails the call."""
    var library = Library()
    var server_keys = library.generate_noise_keypair()
    var client_keys = library.generate_noise_keypair()
    var admitting = Interface("127.0.0.1:0", connections=8)
    admitting.security = Security.NOISE_XX
    admitting.noise_private_key = server_keys[0]
    admitting.peer_authorizer = PeerAuthorizer.to[admit_every_key]()
    var rejecting = admitting.copy()
    rejecting.peer_authorizer = PeerAuthorizer.to[reject_every_key]()
    var server = Server(library, [admitting^, rejecting^])
    server.get["/hello", hello]()

    var options = ClientOptions(connections=2)
    options.calls = 2
    options.noise_private_key = client_keys[0]
    options.peer_authorizer = PeerAuthorizer.to[admit_every_key]()
    var client = Client(server, options, event_loop=0)
    client.submit(ClientCall.get(String("http+noise://", server.address(0).value(), "/hello")), 0)
    client.submit(ClientCall.get(String("http+noise://", server.address(1).value(), "/hello")), 1)

    var remaining = 2
    var completed = List[Completed]()
    var rounds = 0
    while remaining > 0 and rounds < 500:
        rounds += 1
        _ = server.take_call(0, 10_000)
        client.take_completed(completed)
        for position in range(len(completed)):
            ref done = completed[position]
            remaining -= 1
            if done.context == 0:
                assert_false(Bool(done.error), "the admitting interface answers")
                assert_equal(_text(done.response.value().body()), "Hello!")
            else:
                if done.response:
                    assert_false(
                        done.response.value().status_code() == HTTPStatus.OK, "the rejecting interface never answers"
                    )
    assert_equal(remaining, 0, "both calls completed within the rounds allowed")
    _ = completed^
    _ = client^
    server.stop()


# endregion Server and Client


def main() raises:
    var suite = TestSuite()
    suite.test[test_names_come_from_the_library]()
    suite.test[test_percent_escapes_decode_by_mode]()
    suite.test[test_generated_noise_keys_derive_back]()
    suite.test[test_server_answers_a_bound_client]()
    suite.test[test_noise_authorizers_admit_and_reject]()
    suite^.run()
