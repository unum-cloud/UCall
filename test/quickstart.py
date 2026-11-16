"""Holds every binding's README Quickstart to code that runs: the Python block itself, and the C,
Rust and Mojo blocks to the programs their own suites build.

- `python/README.md` runs verbatim, in a temporary working directory.
- `c/README.md` and the root `README.md` equal `examples/hello.c` without its file header; CI builds
  and links that file.
- `rust/README.md` equals the crate example in `rust/lib.rs` without its `//! ` prefixes and the
  hidden `# Ok::<(), ucall::Error>(())` line, so `cargo test --doc` runs it.
- `mojo/README.md` equals the `Quickstart` region of `mojo/test.mojo` without the README's imports,
  which the test file has at its top, the docstrings the test file adds, and `test_quickstart`
  named `main` back.

File: test/quickstart.py
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


def test_quickstart(tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.chdir(tmp_path)
    exec(compile(quickstart("python", "python"), "python/README.md", "exec"), {"__name__": "__quickstart__"})


def test_quickstart_c_mirror():
    source = (ROOT / "examples" / "hello.c").read_text()
    assert source.startswith("/**")
    program = source.split("*/\n", 1)[1]
    assert quickstart("c", "c") == program.strip("\n")
    assert quickstart(".", "c") == program.strip("\n")


def test_quickstart_rust_mirror():
    source = (ROOT / "rust" / "lib.rs").read_text()
    lines = [line.removeprefix("//!").removeprefix(" ") for line in source.splitlines() if line.startswith("//!")]
    example = "\n".join(lines).split("```\n", 1)[1].split("\n```", 1)[0]
    visible = [line for line in example.splitlines() if not line.startswith("# ")]
    assert quickstart("rust", "rust") == "\n".join(visible)


def test_quickstart_mojo_mirror():
    source = (ROOT / "mojo" / "test.mojo").read_text()
    region = source.split("# region Quickstart\n", 1)[1].split("# endregion Quickstart", 1)[0]
    region = re.sub(r'\n    """.*?"""', "", region, flags=re.DOTALL)
    region = region.replace("def test_quickstart() raises:", "def main() raises:")
    block = quickstart("mojo", "mojo")
    imports, program = block.split("\n\n\n", 1)
    assert all(line.startswith("from ") or not line for line in imports.splitlines())
    assert program == region.strip("\n")
