# Language guest build recipes (reproducible, version-pinned)

These are the product build instructions for the two optional language guests
that let a user run **their own** Python / JavaScript inside Ephemora-cell after a
documented install (`pip install "ephemora-cell[python]"` / `[javascript]`). Both
guests embed a current interpreter and are pinned by SHA-256; nothing is fetched
at Cell execution time. Build them on a provisioned host into a scratch dir
(`$GB` below), then package + digest. No personal/absolute home paths are
required — use any writable build dir.

## 1. Python guest — modern CPython 3.14 via componentize-py

Toolchain pin: **componentize-py==0.25.1**, built with a host CPython 3.12.
componentize-py embeds its own current CPython (measured `3.14.0`, wasi-sdk).

> **Host interpreter ≠ guest runtime — keep these straight.** The **build host**
> runs a CPython 3.12.x (measured `3.12.13`) purely to execute `componentize-py`;
> that version is a *build-machine* detail and never reaches a user. The
> **produced guest embeds its own CPython**, independent of the host: verified
> from inside the sandbox as `3.14.0 (main, Sep 11 2026) [Clang 22.1.0-wasi-sdk]`.
> A user runs the guest's 3.14.0, not the host's 3.12.x.

`wit/command.wit`:
```wit
package demo:runnable@0.1.0;

world runnable {
  export run: func();
}
```

`app.py` — reads the user script at `/work/main.py` (stdin stays free for the
caller's JSON input) and execs it; user faults are reported with a clean marker
instead of an uncontrolled abort. **Every stdlib module you want available to user
code MUST be imported here at build time** — componentize-py only bundles modules
it can see statically:
```python
import sys
import traceback
import json, hashlib, datetime, decimal, statistics, collections, itertools
import functools, re, os, os.path, math, struct, textwrap, string


class WitWorld:
    def run(self):
        path = "/work/main.py"
        try:
            with open(path) as handle:
                src = handle.read()
        except OSError as exc:
            sys.stderr.write("EPHEMORA_CANNOT_READ_SCRIPT: %s\n" % exc)
            sys.stderr.flush()
            return
        ns = {"__name__": "__main__", "__file__": path}
        try:
            exec(compile(src, path, "exec"), ns)
        except SystemExit:
            return
        except BaseException:
            sys.stderr.write("EPHEMORA_USER_ERROR\n")
            traceback.print_exc()
            sys.stderr.flush()
            return
```

> **What `except SystemExit: return` costs, stated where the recipe lives.** It
> is the reason a script's own exit status never reaches the host on this guest:
> `sys.exit(3)` leaves the export as a clean return, so `run` reports
> `status: success` / `exit_code: 0` and `exit_status_fidelity: "none"`
> (`docs/languages.md`). The recipe is kept as it is because the shipped,
> digest-pinned guest is built from exactly these bytes — propagating the status
> instead (re-raising so the run leaves through `wasi:cli/exit`) is a guest
> rebuild with a new digest and a fresh qualification run, and the component ABI
> would then carry only "exited non-zero", not the number.

Build:
```sh
python -m venv $GB/cpenv && $GB/cpenv/bin/pip install componentize-py==0.25.1
cd $GB/pybuild   # contains wit/ and app.py
$GB/cpenv/bin/componentize-py -d wit -w runnable componentize app -o python_guest.wasm
sha256sum python_guest.wasm   # record; this digest is pinned in the package
```

Supported Python scope (documented limit): the eager-imported modules above plus
builtins. Modules whose C accelerators are not bundled (e.g. third-party, or
stdlib beyond this list) are **unsupported** and fail closed inside the sandbox.
FS access is limited to the granted preopen (`/work`); paths outside preopens are
refused by the WASI capability boundary.

## 2. JavaScript guest — QuickJS (quickjs-ng) via rquickjs → WASI

Toolchain pins: **rquickjs==0.14.0** (vendors quickjs-ng), Rust **1.99.0**, target
**wasm32-wasip1** (`rustup target add wasm32-wasip1`); C toolchain **wasi-sdk 34.0 /
clang 23.1.0** (the committed recipe does not pin the C compiler itself — set it
explicitly as `CC_wasm32_wasip1`).

`Cargo.toml`:
```toml
[package]
name = "qjsrun"
version = "0.1.0"
edition = "2021"
[dependencies]
rquickjs = "0.14.0"
[profile.release]
opt-level = "z"
lto = true
strip = true
```

`src/main.rs` — reads `/work/main.js`, evaluates it, exposes `input` (from
`/work/input.json`) and `console.log`, and reports faults via the `EPHEMORA_USER_ERROR`
marker (do **not** call `std::process::exit` and do **not** use `panic = "abort"` —
both produce an abort backtrace; a normal return is a clean exit 0):
```rust
use rquickjs::{Context, Ctx, Function, Runtime, Value};
use std::fs;
const SRC: &str = "/work/main.js";
const INPUT: &str = "/work/input.json";

fn real_main(ctx: Ctx) {
    let src = match fs::read_to_string(SRC) {
        Ok(s) => s,
        Err(e) => { eprintln!("EPHEMORA_CANNOT_READ_SCRIPT: {}", e); return; }
    };
    let input = fs::read_to_string(INPUT).unwrap_or_else(|_| "null".to_string());
    let g = ctx.globals();
    let logfn = Function::new(ctx.clone(), |s: String| println!("{}", s)).unwrap();
    let _ = g.set("__log", logfn);
    let _ = g.set("__inputJson", input.as_str());
    let shim = "var input=(function(){try{return JSON.parse(__inputJson)}catch(e){return null}})();\
                var console={log:function(){var a=Array.prototype.slice.call(arguments);\
                __log(a.map(function(x){try{return (x&&typeof x==='object')?JSON.stringify(x):String(x)}\
                catch(e){return String(x)}}).join(' '))},error:function(){},warn:function(){}};";
    let combined = format!("{}\n{}", shim, src);
    if let Err(e) = ctx.eval::<Value, _>(combined.as_str()) {
        eprintln!("EPHEMORA_USER_ERROR: {}", e);
    }
}
fn main() {
    if let Ok(rt) = Runtime::new() {
        if let Ok(ctx) = Context::full(&rt) {
            ctx.with(|ctx| real_main(ctx));
        }
    }
}
```

Build (reproducible, in-repo recipe — mirrors the Python script):
```sh
# Build-root remap is REQUIRED for an artifact with no local paths in it
# (measured 2026-10-16): a naive build retained the macOS per-user temp token.
TMPDIR=$GB/btmp CARGO_NET_OFFLINE=true \
CC_wasm32_wasip1=/path/to/wasi-sdk-34/bin/clang \
RUSTFLAGS="--remap-path-prefix=$GB/btmp=/build --remap-path-prefix=$HOME=/home-build \
          --remap-path-prefix=/private/var/folders=/build-tmp --remap-path-prefix=/var/folders=/build-tmp" \
CFLAGS_wasm32_wasip1="-fmacro-prefix-map=$GB/btmp=/build -fmacro-prefix-map=$HOME=/home-build \
                     -fdebug-prefix-map=$GB/btmp=/build -fdebug-prefix-map=$HOME=/home-build" \
python scripts/build_js_interpreter_guest.py --out js_guest.wasm --smoke
# writes Cargo.toml (rquickjs pinned =0.14.0) + src/main.rs, applies the committed
# scripts/data/js_interpreter_guest/Cargo.lock, then `cargo build --locked
# --target wasm32-wasip1`; prints sha256 + size and runs user JS through the sandbox.
# Path hygiene (assert before packaging): 0 hits for /Users/<name> and 0 for
# /private/var|/tmp in `strings -n 6 js_guest.wasm` (measured: old 5+4 -> new 0+0).
```
The committed `Cargo.lock` fixes the **entire graph** (rquickjs/rquickjs-sys 0.14.0,
quickjs-ng via `cc`, hashbrown 0.17.1, serde 1.0.229, …), so a rebuild selects the
same crates. It is **not** bit-deterministic: cargo embeds build paths/metadata, so
`--locked` rebuilds differ byte-to-byte at equal size. The guarantee stays the
digest-pinned shipped artifact plus bring-your-own recompute-and-verify. `scripts/
build_js_guest.py` is a *different* recipe — the pre-compiled Javy 9.1.0 **module**
path, not this interpreter.

Supported JavaScript scope: ES as implemented by quickjs-ng (no Node.js/npm
modules, no `require`/`process`/`Buffer`/`fetch` — measured `undefined` inside the
guest). JSON input via `input`, output via `console.log`.

## 3. Packaging + provenance

Each guest is a small distribution (`ephemora-cell-python-guest` /
`ephemora-cell-javascript-guest`) whose entry point `guest_info()` returns
`{wasm_path, expected_sha256, version, distribution}` (Python/JS guests ship no
`stdlib_dir`; the interpreter is embedded). Build with `uv build --wheel`, install
from a local index (`pip install "ephemora-cell[python]"`), and the core resolves
the guest automatically. Licenses/SBOM: CPython PSF-2.0, quickjs-ng/rquickjs MIT —
see the release SBOM; third-party notices must accompany redistribution.

Pinned artifact digests (the 1.2.0 release-candidate packages, measured 2026-10-16;
`guest.wasm` and the wheel that ships it):
```
python_guest      sha256 42984274746ee96e9855049f5d0370b9515fa13e4ce9610c29083c9a8a558935  (19,812,760 B)
python_guest.whl  sha256 24a11c758fe91bf80ff5a68e7b7bb887c1c17deff3095942af2c674ceee670ad  ( 6,816,156 B)
js_guest          sha256 a192e2308cd3ea6749cc15ff36ef9db9edbe2456bf9520922234c9efc46efed5  (   730,326 B)
js_guest.whl      sha256 f929093af3681b0c31ba672b62da7d787972eab65af4763f512b03352dbf9051  (   319,406 B)
```
The Python guest was already path-clean and is unchanged (same digest/size). The
JS guest is a **clean rebuild** (2026-10-16) that removed the local build paths
the previous artifact carried — the superseded bytes were
`js_guest 53037972…fe5646` (737,959 B). Neither the wasm nor the wheel is
byte-reproducible: an identical JS rebuild produced the same size but a different
digest (`4efe671e…`, 730,326 B), so the guarantee is the digest-pinned shipped
artifact plus bring-your-own recompute-and-verify — not rebuild bit-parity. The
wheel names are `ephemora_cell_python_guest-1.2.0-py3-none-any.whl` and
`ephemora_cell_javascript_guest-1.2.0-py3-none-any.whl`.
The earlier pair — `python_guest 4e8ec2acdf19be0b96c604292050536d975b2ede5ef5a1565098227fe6e42dae`
(19,816,661 B) and `js_guest 88a396971253914762dcdf64d05513a454e68a8bf759f178a48302a2f6f46dc6`
(737,767 B) — are historical pre-1.2.0 builds, kept only as the originally
qualified reference.
(componentize-py is byte-nondeterministic — rebuild may change bytes; the package
pins the digest of the one audited build.)
