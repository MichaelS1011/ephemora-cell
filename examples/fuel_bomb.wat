;; examples/fuel_bomb.wat — a deliberate compute bomb for enforcement demos:
;; an infinite loop that only ends when the sandbox exhausts its fuel budget.
;; Rebuild: python -c "import wasmtime; open('examples/fuel_bomb.wasm','wb').write(wasmtime.wat2wasm(open('examples/fuel_bomb.wat').read()))"
(module (func (export "_start") (loop $l br $l)))
