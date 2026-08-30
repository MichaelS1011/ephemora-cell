use std::env;

fn main() {
    let args: Vec<String> = env::args().collect();
    println!("hello from wasip2 component");
    if let Some(a) = args.get(1) {
        println!("arg1={a}");
    }
    println!("env_ephemora_test={}", env::var("EPHEMORA_TEST").unwrap_or_default());
    let dir = args.get(1).cloned().unwrap_or_else(|| ".".to_string());
    let target = std::path::Path::new(&dir).join("out.txt");
    std::fs::write(&target, "pwned-by-component\n").expect("write out.txt");
}
