//! Builds the C library through CMake and links what it produced.
//!
//! No C or C++ is compiled here directly: `CMakeLists.txt` owns the CPU classes, their flags, and
//! the backends a platform gets, so this drives CMake and links the archive it leaves behind,
//! together with what that archive's link interface needs.

use std::env;
use std::error::Error;
use std::fs;
use std::path::PathBuf;

/// The siblings CMake fetches by pinned revision unless `FETCHCONTENT_SOURCE_DIR_<NAME>` names a
/// local checkout.
const SIBLINGS: &[&str] = &["STRINGZILLA", "FORKUNION", "SMASHTABLE"];

/// The paths whose contents rebuild the library.
const SOURCES: &[&str] = &["CMakeLists.txt", "VERSION", "c", "include", "src"];

/// Answers the value CMake cached for `name`, whatever its type.
fn cached<'cache>(cache: &'cache str, name: &str) -> Option<&'cache str> {
    cache.lines().find_map(|line| {
        let (key, value) = line.split_once('=')?;
        (key.split_once(':')?.0 == name).then_some(value)
    })
}

fn main() -> Result<(), Box<dyn Error>> {
    let manifest = PathBuf::from(env::var("CARGO_MANIFEST_DIR")?);

    let mut library = cmake::Config::new(&manifest);
    library
        .profile("Release")
        .define("UCALL_BUILD_TEST", "OFF")
        .build_target("ucall");
    for sibling in SIBLINGS {
        let variable = format!("FETCHCONTENT_SOURCE_DIR_{sibling}");
        println!("cargo:rerun-if-env-changed={variable}");
        if let Some(source) = env::var_os(&variable) {
            library.define(&variable, source);
        }
    }

    // `build_target` stops short of installing, and the project collects every archive at the root
    // of its build tree whatever the generator.
    let build = library.build().join("build");
    println!("cargo:rustc-link-search=native={}", build.display());
    println!("cargo:rustc-link-lib=static=ucall");

    // The io_uring backends link liburing publicly: the system's shared library when pkg-config
    // found a recent one, otherwise the archive CMake built from source.
    let cache = fs::read_to_string(build.join("CMakeCache.txt"))?;
    if cached(&cache, "UCALL_WITH_LINUX_URING") == Some("ON") {
        match cached(&cache, "UCALL_URING_FOUND") {
            Some("1") => {
                if let Some(directory) = cached(&cache, "UCALL_URING_LIBDIR") {
                    println!("cargo:rustc-link-search=native={directory}");
                }
                println!("cargo:rustc-link-lib=dylib=uring");
            }
            _ => {
                let source = build.join("_deps").join("liburing-ep").join("src");
                println!("cargo:rustc-link-search=native={}", source.display());
                println!("cargo:rustc-link-lib=static=uring");
            }
        }
    }

    // The archive is C++ over the platform's threads and sockets.
    match env::var("CARGO_CFG_TARGET_OS")?.as_str() {
        "windows" => {
            for system in ["bcrypt", "ws2_32", "mswsock"] {
                println!("cargo:rustc-link-lib=dylib={system}");
            }
        }
        "macos" | "ios" => println!("cargo:rustc-link-lib=dylib=c++"),
        "freebsd" => {
            println!("cargo:rustc-link-lib=dylib=c++");
            println!("cargo:rustc-link-lib=dylib=pthread");
        }
        _ => {
            println!("cargo:rustc-link-lib=dylib=stdc++");
            println!("cargo:rustc-link-lib=dylib=pthread");
        }
    }

    // Cargo scans a watched directory recursively.
    for source in SOURCES {
        println!("cargo:rerun-if-changed={}", manifest.join(source).display());
    }
    Ok(())
}
