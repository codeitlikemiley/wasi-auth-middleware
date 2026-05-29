#[cfg(not(target_arch = "wasm32"))]
mod app;

#[cfg(not(target_arch = "wasm32"))]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    app::main_impl()
}

#[cfg(target_arch = "wasm32")]
fn main() {}
