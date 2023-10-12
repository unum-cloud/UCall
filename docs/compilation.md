# Compiling UCall

## For C and C++ Developers

Compiling the default supported backends for your OS:

```sh
cmake -DCMAKE_BUILD_TYPE=Release -B ./build_release  && make -C ./build_release
```

Compiling specific targets and overwriting binary names:

```sh
cmake -DCMAKE_BUILD_TYPE=Release \
    -DUCALL_BUILD_POSIX=1 \
    -DUCALL_BUILD_EPOLL=1 \
    -DUCALL_BUILD_URING=1 \
    -DUCALL_BUILD_PYTHON=1 \
    -DUCALL_BUILD_EXAMPLES=1 \
    -DUCALL_TARGET_NAME_PY_POSIX=py_ucall_posix \
    -DUCALL_TARGET_NAME_PY_EPOLL=py_ucall_epoll \
    -DUCALL_TARGET_NAME_PY_URING=py_ucall_uring \
    -DUCALL_TARGET_NAME_CPP_POSIX=ucall_server_posix \
    -DUCALL_TARGET_NAME_CPP_EPOLL=ucall_server_epoll \
    -DUCALL_TARGET_NAME_CPP_URING=ucall_server_uring \
    -B ./build_release  && make -C ./build_release
```

## For Python Developers

```sh
pip install -e .
```