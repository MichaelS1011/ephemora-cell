(component
    (core module $m (func (export "other") (result i32) i32.const 0))
    (core instance $i (instantiate $m))
    (func (export "other") (result u32) (canon lift (core func $i "other")))
)
