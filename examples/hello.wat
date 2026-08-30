;; examples/hello.wat — minimal WASI guest for the README demo.
;; Rebuild:  python -c "import wasmtime; open('examples/hello.wasm','wb').write(wasmtime.wat2wasm(open('examples/hello.wat').read()))"
(module
  (import "wasi_snapshot_preview1" "fd_write"
    (func $fd_write (param i32 i32 i32 i32) (result i32)))
  (memory (export "memory") 1)
  ;; iovec at address 0: {ptr=64, len=26}; nwritten at address 8
  (data (i32.const 64) "Hello from Ephemora Cell!\n")
  (func $main (export "_start")
    (i32.store (i32.const 0) (i32.const 64))
    (i32.store (i32.const 4) (i32.const 26))
    (drop (call $fd_write
      (i32.const 1)   ;; fd 1 = stdout
      (i32.const 0)   ;; iovec pointer
      (i32.const 1)   ;; iovec count
      (i32.const 8)))))  ;; nwritten
