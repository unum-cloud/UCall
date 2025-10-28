#!/usr/bin/env python3
import base64
import io
import pytest
import httpx
from PIL import Image
import numpy as np

# Setup base URL
BASE_URL = "http://localhost:8000"


def echo(client, data: str) -> bool:
    response = client.post("/echo", json={"data": data})
    assert response.status_code == 200
    return response.json() == {"data": data}


def test_echo():
    with httpx.Client(base_url=BASE_URL) as client:
        data = "Hello, World!"
        assert echo(client, data)


def validate_session(client, user_id: int, session_id: int) -> bool:
    response = client.post(
        "/validate_session",
        json={"user_id": user_id, "session_id": session_id},
    )
    assert response.status_code == 200
    return response.json() == True


def test_validate_session():
    with httpx.Client(base_url=BASE_URL) as client:
        user_id = 111
        session_id = 111
        assert validate_session(client, user_id, session_id)


def create_user(client, name: str, age: int, bio: str, avatar: str) -> bool:
    data = {"name": name, "age": age, "bio": bio, "avatar": avatar}
    response = client.post("/create_user", json=data)
    assert response.status_code == 200
    return "avatar_size" in response.json()


def test_create_user():
    with httpx.Client(base_url=BASE_URL) as client:
        name = "Jane Doe"
        age = 25
        bio = "Lorem ipsum"
        avatar = create_avatar_base64_string()
        assert create_user(client, name, age, bio, avatar)


def validate_user_identity(
    client, name: str, age: float, user_id: int, access_token: str
) -> bool:
    data = {"name": name, "age": age, "user_id": user_id, "access_token": access_token}
    response = client.post("/validate_user_identity", json=data)
    assert response.status_code == 200
    return True


def test_validate_user_identity():
    with httpx.Client(base_url=BASE_URL) as client:
        name = "John Doe"
        age = 25.0
        user_id = 123
        access_token = base64.b64encode(f"{name} Token".encode()).decode()
        assert validate_user_identity(client, name, age, user_id, access_token)


def set_get(client, key: str, value: str) -> bool:
    set_response = client.post("/set", json={"key": key, "value": value})
    assert set_response.status_code == 200
    assert set_response.json() == True

    get_response = client.post("/get", json={"key": key})
    assert get_response.status_code == 200
    return get_response.json() == value


def test_set_get():
    with httpx.Client(base_url=BASE_URL) as client:
        key = "testkey"
        value = "testvalue"
        assert set_get(client, key, value)


def resize(client, image: str, width: int, height: int) -> bool:
    response = client.post(
        "/resize", json={"image": image, "width": width, "height": height}
    )
    assert response.status_code == 200

    image_bytes = base64.b64decode(response.json())
    pil_image = Image.open(io.BytesIO(image_bytes))
    return pil_image.size == (width, height)


def test_resize():
    with httpx.Client(base_url=BASE_URL) as client:
        width, height = 100, 100
        image = create_avatar_base64_string()
        assert resize(client, image, width, height)


def dot_product(client, a: np.ndarray, b: np.ndarray) -> bool:
    a_base64 = base64.b64encode(a.tobytes()).decode()
    b_base64 = base64.b64encode(b.tobytes()).decode()
    response = client.post("/dot_product", json={"a": a_base64, "b": b_base64})
    assert response.status_code == 200
    expected_dot_product = float(np.dot(a, b))
    return abs(response.json() - expected_dot_product) < 1e-6


def test_dot_product():
    with httpx.Client(base_url=BASE_URL) as client:
        a = np.random.rand(10).astype(np.float32)
        b = np.random.rand(10).astype(np.float32)
        assert dot_product(client, a, b)


def create_avatar_base64_string() -> str:
    image = Image.new("RGB", (10, 10), color="red")
    buf = io.BytesIO()
    image.save(buf, format="PNG")
    byte_im = buf.getvalue()
    return base64.b64encode(byte_im).decode()


if __name__ == "__main__":
    pytest.main()
