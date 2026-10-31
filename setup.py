# Uses CMake to compile UCall with `io_uring` and other CPython bindings.
# That is a multi-step process, that involves:
#       1. Build the C server as one library, like `libucall_server_posix.a`
#       2. Build the C binding, where target `py_ucall_posix` produces `py_ucall_posix.so`
#       3. Rename binding to `posix.cpython-312-x86_64-linux-gnu.so`
import os
import sys
import sysconfig
import re
import glob
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


def print_dir_tree(startpath):
    for root, dirs, files in os.walk(startpath):
        level = root.replace(startpath, "").count(os.sep)
        indent = " " * 4 * (level)
        print(f"{indent}{os.path.basename(root)}/")
        subindent = " " * 4 * (level + 1)
        for f in files:
            print(f"{subindent}{f}")


def get_expected_module_name(module_name):
    # Get the suffix for shared object files (includes Python version and platform)
    so_suffix = sysconfig.get_config_var("EXT_SUFFIX")
    # Construct the expected module filename
    expected_filename = f"{module_name}{so_suffix}"
    return expected_filename


class CMakeExtension(Extension):
    def __init__(self, name, source_dir=""):
        Extension.__init__(self, name, sources=[])
        self.source_dir = os.path.abspath(source_dir)


class CMakeBuild(build_ext):
    def build_extension(self, ext):
        package_name, _, module_name = ext.name.partition(".")
        assert package_name == __lib_name__
        assert module_name in ["uring", "posix"]

        if module_name == "uring" and platform.system() != "Linux":
            return

        self.parallel = multiprocessing.cpu_count() // 2
        extension_dir = os.path.abspath(dirname(self.get_ext_fullpath(ext.name)))

        # required for auto-detection & inclusion of auxiliary 'native' libs
        if not extension_dir.endswith(os.path.sep):
            extension_dir += os.path.sep

        cmake_args = [
            f"-DCMAKE_LIBRARY_OUTPUT_DIRECTORY={extension_dir}",
            f"-DCMAKE_ARCHIVE_OUTPUT_DIRECTORY={extension_dir}",
            f"-DPYTHON_EXECUTABLE={sys.executable}",
        ]

        # Adding CMake arguments set as environment variable
        # (needed e.g. to build for ARM OSx on conda-forge)
        if "CMAKE_ARGS" in os.environ:
            cmake_args += [item for item in os.environ["CMAKE_ARGS"].split(" ") if item]

        if sys.platform.startswith("darwin"):
            # Cross-compile support for macOS - respect ARCHFLAGS if set
            archs = re.findall(r"-arch (\S+)", os.environ.get("ARCHFLAGS", ""))
            if archs:
                cmake_args += ["-DCMAKE_OSX_ARCHITECTURES={}".format(";".join(archs))]

        build_args = []
        if sys.platform.startswith("win32"):
            build_args += ["--config", "Release"]

        # Set CMAKE_BUILD_PARALLEL_LEVEL to control the parallel build level
        # across all generators.
        if "CMAKE_BUILD_PARALLEL_LEVEL" not in os.environ:
            # self.parallel is a Python 3 only way to set parallel jobs by hand
            # using -j in the build_ext call, not supported by pip or PyPA-build.
            if hasattr(self, "parallel") and self.parallel:
                build_args += [f"-j{self.parallel}"]

        # Configure CMake
        try:
            subprocess.check_call(["cmake", ext.source_dir] + cmake_args)
        except subprocess.CalledProcessError as e:
            print(f"CMake for {ext.name} in {ext.source_dir} with args: {cmake_args}")
            print(f"Resulted in error: {e}")
            raise

        # Build with CMake
        try:
            binding_name = "py_ucall_" + module_name
            expected_name = get_expected_module_name(module_name)
            subprocess.check_call(
                [
                    "cmake",
                    "--build",
                    ".",
                    "--target",
                    binding_name,
                ]
                + build_args,
            )

            print(
                f"Directory for `{ext.name}` extension should contain `{package_name}` / `{binding_name}`"
            )
            print_dir_tree(self.build_lib)

            # Match a file in the build directory, that is named like the `binding_name`,
            # regardless of the extension, and rename it to the `expected_name` with the same extension.
            compiled_files_pattern = f"{self.build_lib}/{package_name}/{binding_name}.*"
            compiled_files = list(glob.glob(compiled_files_pattern))
            assert (
                len(compiled_files) == 1
            ), f"Expected to find one file, but found {len(compiled_files)}: {compiled_files}"

            old_name = compiled_files[0]
            new_name = os.path.join(os.path.dirname(old_name), expected_name)
            os.rename(old_name, new_name)

        except subprocess.CalledProcessError as e:
            print(f"Building {ext.name} with arguments: {build_args}")
            print(f"Resulted in error: {e}")
            raise

        print(f"Directory for `{ext.name}` extension should contain `{expected_name}`")
        print_dir_tree(self.build_lib)

    def run(self):
        build_ext.run(self)


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
        "Operating System :: Windows",
        "Programming Language :: C",
        "Programming Language :: C++",
        "Programming Language :: Python :: Implementation :: CPython",
        "Programming Language :: Python :: 3 :: Only",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Topic :: Communications :: File Sharing",
        "Topic :: Internet :: WWW/HTTP",
        "Topic :: System :: Networking",
    ],
    packages=["ucall"],
    package_dir={"": "python"},
    ext_modules=[
        CMakeExtension("ucall.uring"),
        CMakeExtension("ucall.posix"),
    ],
    cmdclass={
        "build_ext": CMakeBuild,
    },
    entry_points={"console_scripts": ["ucall=ucall.cli:cli"]},
    install_requires=["numpy", "pillow"],
    zip_safe=False,
    python_requires=">=3.9",
)
