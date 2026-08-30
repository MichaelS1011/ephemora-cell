use std::env;

fn main() {
    let args: Vec<String> = env::args().collect();
    println!("hello from wasip2 component");
    if let Some(a) = args.get(1) {
        println!("arg1={a}");
    }
    println!("env_ephemora_test={}", env::var("EPHEMORA_TEST").unwrap_or_default());
}
