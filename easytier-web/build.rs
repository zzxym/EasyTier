fn main() {
    // enable thunk-rs when target os is windows and arch is x86_64 or i686
    #[cfg(target_os = "windows")]
    if !std::env::var("TARGET")
        .unwrap_or_default()
        .contains("aarch64")
    {
        // Wrap thunk call in a try-catch to handle download failures
        if let Err(e) = std::panic::catch_unwind(|| {
            thunk::thunk();
        }) {
            println!("cargo::warning=thunk-rs initialization failed: {:?}", e);
            println!("cargo::warning=Build will continue without VC-LTL5/YY-Thunks optimizations");
        }
    }
}
