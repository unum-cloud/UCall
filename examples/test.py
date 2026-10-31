import random

import requests
import numpy as np
from PIL import Image
from ucall.client import Client, ClientTLS
from login.jsonrpc_client import CaseHTTP, CaseHTTPBatches, CaseTCP


class ClientGeneric:
    """JSON-RPC Client that uses classic sync Python `requests` to pass JSON calls over HTTP"""

    def __init__(self, uri: str = "127.0.0.1", port: int = 8545) -> None:
        self.url = f"http://{uri}:{port}/"

    def __call__(self, jsonrpc: object) -> object:
        return requests.post(self.url, json=jsonrpc).json()


def shuffled_n_identities(class_, count_clients: int = 3, count_cycles: int = 1000):

    clients = [class_(identity=identity) for identity in range(count_clients)]

    for _ in range(count_cycles):
        random.shuffle(clients)
        for client in clients:
            client.send()
        random.shuffle(clients)
        for client in clients:
            client.recv()


def test_shuffled_tcp():
    for connections in range(1, 10):
        shuffled_n_identities(CaseTCP, count_clients=connections)


def test_shuffled_http():
    for connections in range(1, 10):
        shuffled_n_identities(CaseHTTP, count_clients=connections)


def test_shuffled_http_batches():
    for connections in range(1, 10):
        print(connections)
        shuffled_n_identities(CaseHTTPBatches, count_clients=connections)


def test_uniform_batches():
    client = CaseHTTPBatches()
    for batch_size in range(1, 100):
        numbers = [random.randint(1, 1000) for _ in range(batch_size)]
        client.send(numbers, numbers)
        client.recv()


# def test_transform():
#     client = ClientGeneric()
#     identity = 'This is an identity'
#     response = client({
#         'method': 'transform',
#         'params': {'age': 20, 'name': 'Eager', 'value': 3, 'identity': base64.b64encode(identity.encode()).decode()},
#         'jsonrpc': '2.0',
#         'id': 100,
#     })
#     new_id = base64.b64decode(response['val']['identity']).decode()
#     assert new_id == identity + f'_Eager'


def test_normal():
    client = Client()
    response = client.validate_session(user_id=2, session_id=2)
    assert response.json == True


def test_normal_positional():
    client = Client()
    response = client.validate_session(2, 2)
    assert response.json == True


def test_normal_tls():
    client = ClientTLS(allow_self_signed=True)
    response = client.validate_session(user_id=2, session_id=2)
    assert response.json == True


def test_normal_positional_tls():
    client = ClientTLS(allow_self_signed=True)
    response = client.validate_session(2, 2)
    assert response.json == True


def test_notification():
    client = ClientGeneric()
    response = client(
        {
            "method": "validate_session",
            "params": {"user_id": 2, "session_id": 2},
            "jsonrpc": "2.0",
        }
    )
    assert len(response) == 0


def test_method_missing():
    client = ClientGeneric()
    response = client(
        {
            "method": "sumsum",
            "params": {"a": 2, "b": 2},
            "jsonrpc": "2.0",
            "id": 0,
        }
    )
    assert response["error"]["code"] == -32601


def test_param_missing():
    client = ClientGeneric()
    response = client(
        {
            "method": "validate_session",
            "params": {"user_id": 2},
            "jsonrpc": "2.0",
            "id": 0,
        }
    )
    assert response["error"]["code"] == -32602


def test_param_type():
    client = ClientGeneric()
    response = client(
        {
            "method": "validate_session",
            "params": {"user_id": 2.0, "session_id": 3.5},
            "jsonrpc": "2.0",
            "id": 0,
        }
    )
    assert response["error"]["code"] == -32602


def test_non_uniform_batch():
    a = 2
    b = 2
    r_normal = {
        "method": "validate_session",
        "params": {"user_id": a, "session_id": b},
        "jsonrpc": "2.0",
        "id": 0,
    }
    r_notification = {
        "method": "validate_session",
        "params": {"user_id": a, "session_id": b},
        "jsonrpc": "2.0",
    }

    client = ClientGeneric()
    response = client(
        [
            r_normal,
            r_notification,
        ]
    )


def test_numpy():
    a = np.random.randint(0, 101, size=(1, 3, 10))
    b = np.random.randint(0, 101, size=(1, 3, 10))
    res = np.mod(np.logical_xor(a, b), 23)
    client = Client()
    response = client(
        {
            "method": "validate_all_sessions",
            "params": {"user_ids": a, "session_ids": b},
            "jsonrpc": "2.0",
            "id": 100,
        }
    )
    response.raise_for_status()
    assert np.array_equal(response.numpy, res)


def test_pillow():
    img = Image.open("examples/login/original.jpg")
    res = img.rotate(45)
    client = Client()
    response = client.rotate_avatar(image=img)
    response.raise_for_status()
    ar1 = np.asarray(res)
    ar2 = np.asarray(response.image)
    assert np.array_equal(ar1, ar2)


def test_numpy_tls():
    a = np.random.randint(0, 101, size=(1, 3, 10))
    b = np.random.randint(0, 101, size=(1, 3, 10))
    res = np.mod(np.logical_xor(a, b), 23)
    client = ClientTLS(allow_self_signed=True)
    response = client(
        {
            "method": "validate_all_sessions",
            "params": {"user_ids": a, "session_ids": b},
            "jsonrpc": "2.0",
            "id": 100,
        }
    )
    response.raise_for_status()
    assert np.array_equal(response.numpy, res)


def test_pillow_tls():
    img = Image.open("examples/login/original.jpg")
    res = img.rotate(45)
    client = ClientTLS(allow_self_signed=True)
    response = client.rotate_avatar(image=img)
    response.raise_for_status()
    ar1 = np.asarray(res)
    ar2 = np.asarray(response.image)
    assert np.array_equal(ar1, ar2)


if __name__ == "__main__":
    test_normal()
    test_normal_positional()
    # test_normal_tls()
    # test_normal_positional_tls()
    test_shuffled_tcp()
    # test_numpy()
    # test_pillow()
    # test_numpy_tls()
    # test_pillow_tls()
    test_uniform_batches()
    test_shuffled_http_batches()
    test_shuffled_http()
    test_notification()
    test_method_missing()
    test_param_missing()
    test_param_type()
    test_non_uniform_batch()
