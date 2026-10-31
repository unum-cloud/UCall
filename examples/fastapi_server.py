#!/usr/bin/env python
import io
import base64
import random
from typing import List
import logging

import numpy as np
from PIL import Image
from fastapi import FastAPI, HTTPException, Body
from pydantic import BaseModel

app = FastAPI()


class EchoItem(BaseModel):
    data: str


@app.post("/echo")
async def echo(item: EchoItem = Body(...)):
    return {"data": item.data}


class ValidateSessionItem(BaseModel):
    user_id: int
    session_id: int


@app.post("/validate_session")
async def validate_session(item: ValidateSessionItem = Body(...)):
    return (item.user_id ^ item.session_id) % 23 == 0


class CreateUserItem(BaseModel):
    name: str
    age: int
    bio: str
    avatar: str  # in reality - a binary string


@app.post("/create_user")
async def create_user(item: CreateUserItem = Body(...)) -> str:
    avatar_bytes = base64.b64decode(item.avatar)
    return f"Created {item.name} aged {item.age} with bio {item.bio} and avatar_size {len(avatar_bytes)}"


class ValidateUserIdentityItem(BaseModel):
    user_id: int
    name: str
    age: float
    access_token: str


@app.post("/validate_user_identity")
async def validate_user_identity(item: ValidateUserIdentityItem = Body(...)):
    if item.age < 18:
        raise HTTPException(
            status_code=400, detail=f"{item.name} must be older than 18"
        )

    access_token_bytes = base64.b64decode(item.access_token)
    if not access_token_bytes.decode().startswith(item.name):
        raise HTTPException(
            status_code=400, detail=f"Invalid access token for {item.name}"
        )

    suggested_session_ids = [
        random.random() * item.age * item.user_id for _ in range(round(item.age))
    ]
    return {
        "session_ids": suggested_session_ids,
        "user": {
            "name": item.name,
            "age": item.age,
            "user_id": item.user_id,
            "access_token": access_token_bytes,
            "repeated_sesson_ids": suggested_session_ids,
        },
    }


redis = {}


class SetItem(BaseModel):
    key: str
    value: str


@app.post("/set")
async def set(item: SetItem = Body(...)) -> bool:
    redis[item.key] = item.value
    return True


class GetItem(BaseModel):
    key: str


@app.post("/get")
async def get(item: GetItem = Body(...)) -> str:
    return redis.get(item.key, None)


class ResizeItem(BaseModel):
    image: bytes
    width: int
    height: int


@app.post("/resize")
async def resize(item: ResizeItem = Body(...)) -> bytes:
    image_bytes = base64.b64decode(item.image)
    pil_image = Image.open(io.BytesIO(image_bytes))
    resized_image = pil_image.resize((item.width, item.height))
    buf = io.BytesIO()
    resized_image.save(buf, format="PNG")
    image_base64 = base64.b64encode(buf.getvalue()).decode()
    return image_base64


class DotProductItem(BaseModel):
    a: bytes
    b: bytes


@app.post("/dot_product")
async def dot_product(item: DotProductItem = Body(...)) -> float:
    a_array = np.frombuffer(base64.b64decode(item.a), dtype=np.float32)
    b_array = np.frombuffer(base64.b64decode(item.b), dtype=np.float32)
    return float(np.dot(a_array, b_array))


# Setup basic logging
logging.basicConfig(level=logging.INFO)


@app.get("/")
async def root():
    logging.info("Handling request to the root endpoint")
    return {"message": "Hello World"}
