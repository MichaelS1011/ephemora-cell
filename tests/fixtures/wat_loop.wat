(component
    (core module $m
        (func $loop (export "run") (result i32)
            (local $n i32)
            loop $l local.get $n i32.const 1 i32.add local.set $n br $l end
            i32.const 0))
    (core instance $i (instantiate $m))
    (func (export "run") (result u32) (canon lift (core func $i "run")))
)
