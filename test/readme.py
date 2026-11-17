"""Holds every binding's README Quickstart to code that runs: the Python block itself, and the C,
Rust and Mojo blocks to the programs their own suites build.

Covers:
    - `python/README.md` runs verbatim, in a temporary working directory.
    - `c/README.md` and the root `README.md` equal `examples/hello.c` without its file header; CI
      builds and links that file.
    - `rust/README.md` equals the crate example in `rust/lib.rs` without its `//! ` prefixes and the
      hidden `# Ok::<(), ucall::Error>(())` line, so `cargo test --doc` runs it.
    - `mojo/README.md` equals the `Quickstart` region of `mojo/test.mojo` without the README's
      imports, which the test file has at its top, the docstrings the test file adds, and
      `test_readme_quickstart` named `main` back.

Run:
    python -m pytest test/readme.py -v

File: test/readme.py
Author: Ash Vardanian
Date: November 16, 2026
"""

import pathlib
import re

import pytest

ROOT: pathlib.Path = pathlib.Path(__file__).resolve().parent.parent
"""The repository checkout the READMEs and mirrors are read from."""


def quickstart(binding: str, language: str) -> str:
    """The first fenced `language` block under the `## Quickstart` heading of `binding/README.md`."""
    text = (ROOT / binding / "README.md").read_text()
    section = text.split("\n## Quickstart\n", 1)[1].split("\n## ", 1)[0]
    return section.split(f"```{language}\n", 1)[1].split("\n```", 1)[0]


def test_readme_quickstart(tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch):
    """The Python README's Quickstart runs as written, in a working directory of its own."""
    monkeypatch.chdir(tmp_path)
    exec(compile(quickstart("python", "python"), "python/README.md", "exec"), {"__name__": "__quickstart__"})


def test_readme_c_mirror():
    """The C and root READMEs' Quickstart is `examples/hello.c` without its file header."""
    source = (ROOT / "examples" / "hello.c").read_text()
    assert source.startswith("/**")
    program = source.split("*/\n", 1)[1]
    assert quickstart("c", "c") == program.strip("\n")
    assert quickstart(".", "c") == program.strip("\n")


def test_readme_rust_mirror():
    """The Rust README's Quickstart is the crate example of `rust/lib.rs` without its hidden lines."""
    source = (ROOT / "rust" / "lib.rs").read_text()
    lines = [line.removeprefix("//!").removeprefix(" ") for line in source.splitlines() if line.startswith("//!")]
    example = "\n".join(lines).split("```\n", 1)[1].split("\n```", 1)[0]
    visible = [line for line in example.splitlines() if not line.startswith("# ")]
    assert quickstart("rust", "rust") == "\n".join(visible)


def test_readme_mojo_mirror():
    """The Mojo README's Quickstart is the `Quickstart` region of `mojo/test.mojo`, its test named `main` back."""
    source = (ROOT / "mojo" / "test.mojo").read_text()
    region = source.split("# region Quickstart\n", 1)[1].split("# endregion Quickstart", 1)[0]
    region = re.sub(r'\n    """.*?"""', "", region, flags=re.DOTALL)
    region = region.replace("def test_readme_quickstart() raises:", "def main() raises:")
    block = quickstart("mojo", "mojo")
    imports, program = block.split("\n\n\n", 1)
    assert all(line.startswith("from ") or not line for line in imports.splitlines())
    assert program == region.strip("\n")
