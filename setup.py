import os
import sys
import re
import platform
from os.path import dirname
import multiprocessing
import subprocess
from setuptools import setup, Extension
from setuptools.command.build_ext import build_ext

__version__ = open("VERSION", "r").read().strip()
__lib_name__ = "ucall"


this_directory = os.path.abspath(dirname(__file__))
with open(os.path.join(this_directory, "README.md")) as f:
    long_description = f.read()


class CMakeExtension(Extension):
    def __init__(self, target_name, *cmake_args, source_dir="."):
        Extension.__init__(self, "ucall." + target_name, sources=[])
        self.target_name = target_name
        self.cmake_args = list(cmake_args)
        self.source_dir = os.path.abspath(source_dir)


class CMakeBuild(build_ext):
    def build_extension(self, ext):
        self.parallel = multiprocessing.cpu_count() // 2
        extension_dir = os.path.abspath(dirname(self.get_ext_fullpath(ext.name)))

        # required for auto-detection & inclusion of auxiliary 'native' libs
        if not extension_dir.endswith(os.path.sep):
            extension_dir += os.path.sep

        cmake_args = ext.cmake_args
        cmake_args += [
            f"CMAKE_LIBRARY_OUTPUT_DIRECTORY={extension_dir}",
            f"CMAKE_ARCHIVE_OUTPUT_DIRECTORY={extension_dir}",
            f"PYTHON_EXECUTABLE={sys.executable}",
            "UCALL_BUILD_AUTO=0",
            "UCALL_BUILD_PYTHON=1",
        ]

        # Adding CMake arguments set as environment variable
        # (needed e.g. to build for ARM OSx on conda-forge)
        if "CMAKE_ARGS" in os.environ:
            cmake_args += [item for item in os.environ["CMAKE_ARGS"].split(" ") if item]

        if sys.platform.startswith("darwin"):
            # Cross-compile support for macOS - respect ARCHFLAGS if set
            archs = re.findall(r"-arch (\S+)", os.environ.get("ARCHFLAGS", ""))
            if archs:
                cmake_args += ["CMAKE_OSX_ARCHITECTURES={}".format(";".join(archs))]

        # Set CMAKE_BUILD_PARALLEL_LEVEL to control the parallel build level
        # across all generators.
        build_args = []
        if sys.platform.startswith("win32"):
            build_args += ["--config", "Release"]

        if "CMAKE_BUILD_PARALLEL_LEVEL" not in os.environ:
            # self.parallel is a Python 3 only way to set parallel jobs by hand
            # using -j in the build_ext call, not supported by pip or PyPA-build.
            if hasattr(self, "parallel") and self.parallel:
                build_args += [f"-j{self.parallel}"]

        cmake_args = ["-D" + arg for arg in cmake_args]
        subprocess.check_call(["cmake", ext.source_dir] + cmake_args)
        subprocess.check_call(["cmake", "--build", "."] + build_args)

    def run(self):
        build_ext.run(self)


extensions = []

if platform.system() == "Linux":
    extensions += [
        CMakeExtension(
            "uring",
            "UCALL_TARGET_NAME_PY_POSIX=uring",
            "UCALL_BUILD_POSIX=1",
        ),
        CMakeExtension(
            "epoll",
            "UCALL_TARGET_NAME_PY_EPOLL=epoll",
            "UCALL_BUILD_EPOLL=1",
        ),
        CMakeExtension(
            "posix",
            "UCALL_TARGET_NAME_PY_URING=posix",
            "UCALL_BUILD_URING=1",
        ),
    ]
elif platform.system() == "Darwin":
    extensions += [
        CMakeExtension(
            "posix",
            "CALL_TARGET_NAME_PY_POSIX=posix",
            "UCALL_BUILD_POSIX=1",
        ),
    ]
elif platform.system() == "Windows":
    extensions += [
        CMakeExtension(
            "posix",
            "CALL_TARGET_NAME_PY_POSIX=posix",
            "UCALL_BUILD_POSIX=1",
        ),
    ]


setup(
    name=__lib_name__,
    version=__version__,
    author="Ash Vardanian",
    author_email="info@unum.cloud",
    url="https://github.com/unum-cloud/ucall",
    description="Up to 100x Faster FastAPI. JSON-RPC with io_uring, SIMD-acceleration, and pure CPython bindings",
    long_description=long_description,
    long_description_content_type="text/markdown",
    license="Apache-2.0",
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Natural Language :: English",
        "Intended Audience :: Developers",
        "Intended Audience :: Information Technology",
        "License :: OSI Approved :: Apache Software License",
        "Programming Language :: Python :: 3 :: Only",
        "Programming Language :: Python :: Implementation :: CPython",
        "Programming Language :: C",
        "Operating System :: Unix",
        "Operating System :: POSIX",
        "Operating System :: POSIX :: Linux",
        "Operating System :: MacOS",
        "Programming Language :: C",
        "Programming Language :: C++",
        "Programming Language :: Python :: Implementation :: CPython",
        "Programming Language :: Python :: 3 :: Only",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Topic :: Communications :: File Sharing",
        "Topic :: Internet :: WWW/HTTP",
        "Topic :: System :: Networking",
    ],
    packages=["ucall"],
    package_dir={"": "src"},
    ext_modules=extensions,
    cmdclass={"build_ext": CMakeBuild},
    entry_points={"console_scripts": ["ucall=ucall.cli:cli"]},
    install_requires=["numpy", "pillow"],
    zip_safe=False,
    python_requires=">=3.9",
)
