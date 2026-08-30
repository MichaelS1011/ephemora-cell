(component
    (core module $m (func (export "run") (result i32) i32.const 0))
    (core instance $i (instantiate $m))
    (func (export "run") (result u32) (canon lift (core func $i "run")))
)
