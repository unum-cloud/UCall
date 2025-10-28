"""
This module implements a pseudo-backend for benchmarking and demostration purposes for the UCall JSON-RPC implementation.
It provides a simplified in-memory key-value store and image manipulation functions, alongside user management utilities.
"""

import random
from typing import List

import numpy as np
import PIL.Image as pil

from ucall.posix import Server


# Initialize the RPC server on port 8545
server = Server(port=8545)


@server
def echo(data: bytes) -> bytes:
    """
    Returns the same data it receives.

    Args:
        data (bytes): Data to be echoed back.

    Returns:
        bytes: The same data received.
    """
    return data


@server
def validate_session(user_id: int, session_id: int) -> bool:
    """
    Validates if the session ID is valid for the given user ID based on a hashing scheme.

    Args:
        user_id (int): The user's unique identifier.
        session_id (int): The session's unique identifier.

    Returns:
        bool: True if the session is valid, False otherwise.
    """
    return (user_id ^ session_id) % 23 == 0


@server
def create_user(age: int, name: str, avatar: bytes, bio: str) -> str:
    """
    Registers a new user with the given details and returns a summary.

    Args:
        age (int): User's age.
        name (str): User's full name.
        avatar (bytes): User's avatar image in binary format.
        bio (str): User's biography.

    Returns:
        str: Confirmation message with user details.
    """
    return f"Created {name} aged {age} with bio {bio} and avatar_size {len(avatar)}"


@server
def validate_user_identity(
    user_id: int,
    name: str,
    age: float,
    access_token: bytes,
) -> dict:
    """
    Similar to JWT, validates the user's identity based on the provided data.
    Showcases argument validation & exception handling in the Python layer,
    as well as complex structured returned values.

    Args:
        user_id (int): An integer user identifier.
        name (str): The user's name.
        age (float): Must be over 18.
        access_token (bytes): Must start with user's name.

    Returns:
        dict: Transformed data including a list of generated session IDs
              that the client can reuse for future connections.
    """
    if age < 18:
        raise ValueError(f"{name} must be older than 18")

    if not access_token.decode().startswith(name):
        raise ValueError(f"Invalid access token for {name}")

    suggested_session_ids = [random.random() * age * user_id for _ in range(round(age))]
    return {
        "session_ids": suggested_session_ids,
        "user": {
            "name": name,
            "age": age,
            "user_id": user_id,
            "access_token": access_token,
            "repeated_sesson_ids": suggested_session_ids,
        },
    }


# Simulating a Redis-like in-memory key-value store
redis = dict()


@server
def set(key: str, value: str) -> bool:
    """
    Sets a value in the key-value store.

    Args:
        key (str): The key under which the value is stored.
        value (str): The value to store.

    Returns:
        bool: True if the operation was successful, otherwise False.
    """
    redis[key] = value
    return True


@server
def get(key: str) -> str:
    """
    Retrieves a value from the key-value store based on the key.

    Args:
        key (str): The key whose value needs to be retrieved.

    Returns:
        str: The value if found, otherwise None.
    """
    return redis.get(key, None)


@server
def resize(image: pil.Image, width: int, height: int) -> pil.Image:
    """
    Resizes a single image to the specified width and height.
    Showcases how UCall handles complex binary types like images,
    encoding them into Base64.

    Args:
        image (pil.Image): The image to resize.
        width (int): The target width.
        height (int): The target height.

    Returns:
        pil.Image: The resized image.
    """
    return image.resize((width, height))


@server(batch=True, name="resize")
def resize_batch(images: List[pil.Image], width: int, height: int) -> List[pil.Image]:
    """
    Resizes a batch of images to the specified dimensions.
    Showcases how UCall handles complex binary types like images,
    encoding them into Base64, and regrouping them into lists
    for batch processing.

    Args:
        images (List[pil.Image]): List of images to resize.
        width (int): The target width for all images.
        height (int): The target height for all images.

    Returns:
        List[pil.Image]: List of resized images.
    """
    return [image.resize((width, height)) for image in images]


@server
def dot_product(a: np.ndarray, b: np.ndarray) -> float:
    """
    Calculates the dot product of two vectors.
    Showcases how UCall handles complex binary types like NumPy arrays,
    encoding them into Base64.

    Args:
        a (np.ndarray): The first vector. Must be one-dimensional.
        b (np.ndarray): The second vector. Must be of the same shape as `a`.

    Returns:
        float: The dot product of the two vectors.
    """
    return float(np.dot(a, b))


@server(batch=True, name="dot_product")
def dot_product_batch(a: List[np.ndarray], b: List[np.ndarray]) -> List[float]:
    """
    Calculates the dot products of many vectors.
    Showcases how UCall handles complex binary types like NumPy arrays,
    encoding them into Base64, and regrouping them into lists
    for batch processing.

    Args:
        a (List[np.ndarray]): List of first vectors.
        b (List[np.ndarray]): List of second vectors. Must be of the same shape as `a`.

    Returns:
        List[float]: List of dot products of the two vectors.
    """
    return [float(np.dot(a[i], b[i])) for i in range(len(a))]


if __name__ == "__main__":
    server.run()
