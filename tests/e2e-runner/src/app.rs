use anyhow::{Context, Result};
use serde_json::json;
use std::net::TcpListener;
use std::path::PathBuf;
use std::process::Command;
use std::time::Duration;

struct ChildGuard {
    name: String,
    child: std::process::Child,
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        println!(
            "Stopping child process: {} (pid={})",
            self.name,
            self.child.id()
        );
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

struct TempFileGuard {
    path: PathBuf,
}

impl Drop for TempFileGuard {
    fn drop(&mut self) {
        if self.path.exists() {
            println!("Cleaning up temporary file: {:?}", self.path);
            let _ = std::fs::remove_file(&self.path);
        }
    }
}

fn get_unused_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("Failed to bind to dynamic port");
    listener.local_addr().unwrap().port()
}

fn wait_for_port(port: u16, timeout: Duration) -> bool {
    let start = std::time::Instant::now();
    while start.elapsed() < timeout {
        match std::net::TcpStream::connect(format!("127.0.0.1:{}", port)) {
            Ok(_) => return true,
            Err(e) => {
                println!("[wait_for_port] Connecting to {} failed: {:?}", port, e);
            }
        }
        std::thread::sleep(Duration::from_millis(250));
    }
    false
}

fn compile_targets(workspace_root: &std::path::Path) -> Result<()> {
    // Ensure output target directory exists
    let target_debug_dir = workspace_root.join("target/wasm32-wasip2/debug");
    std::fs::create_dir_all(&target_debug_dir)?;

    // a. Build leptos-auth-demo targeting wasm32-wasip2:
    println!("Compiling leptos-auth-demo to wasm32-wasip2...");
    let status = Command::new("cargo")
        .args(&[
            "build",
            "--target",
            "wasm32-wasip2",
            "-p",
            "leptos-auth-demo",
        ])
        .current_dir(workspace_root)
        .status()
        .context("Failed to run cargo build for leptos-auth-demo")?;
    if !status.success() {
        return Err(anyhow::anyhow!("Failed to compile leptos-auth-demo"));
    }

    // b. Build wasi-auth-interceptor targeting wasm32-wasip2 directly.
    println!("Compiling wasi-auth-interceptor to wasm32-wasip2...");
    let status = Command::new("cargo")
        .args(&[
            "build",
            "--target",
            "wasm32-wasip2",
            "-p",
            "wasi-auth-interceptor",
        ])
        .current_dir(workspace_root)
        .status()
        .context("Failed to run cargo build for wasi-auth-interceptor")?;
    if !status.success() {
        return Err(anyhow::anyhow!("Failed to compile wasi-auth-interceptor"));
    }

    // c. Build mock-auth-server targeting the host target.
    println!("Compiling mock-auth-server...");
    let status = Command::new("cargo")
        .args(&["build", "-p", "mock-auth-server"])
        .current_dir(workspace_root)
        .status()
        .context("Failed to run cargo build for mock-auth-server")?;
    if !status.success() {
        return Err(anyhow::anyhow!("Failed to compile mock-auth-server"));
    }

    // Run wasm-tools component wit to inspect both components
    for name in &["wasi_auth_interceptor", "leptos_auth_demo"] {
        let path = workspace_root.join(format!("target/wasm32-wasip2/debug/{}.wasm", name));
        if path.exists() {
            let output = Command::new("wasm-tools")
                .args(&["component", "wit", path.to_str().unwrap()])
                .output();
            if let Ok(out) = output {
                let txt_path = workspace_root.join(format!("target/{}_wit.txt", name));
                std::fs::write(&txt_path, &out.stdout).ok();
            }
        }
    }

    Ok(())
}

fn compose_components(
    workspace_root: &std::path::Path,
    output_path: &std::path::Path,
) -> Result<()> {
    let interceptor_wasm =
        workspace_root.join("target/wasm32-wasip2/debug/wasi_auth_interceptor.wasm");
    let demo_wasm = workspace_root.join("target/wasm32-wasip2/debug/leptos_auth_demo.wasm");

    println!("Composing components using wac plug...");
    let output = Command::new("wac")
        .args(&[
            "plug",
            "--plug",
            demo_wasm.to_str().unwrap(),
            interceptor_wasm.to_str().unwrap(),
            "-o",
            output_path.to_str().unwrap(),
        ])
        .current_dir(workspace_root)
        .output()
        .context("Failed to run wac plug")?;

    if !output.status.success() {
        println!(
            "WAC PLUG STDOUT:\n{}",
            String::from_utf8_lossy(&output.stdout)
        );
        println!(
            "WAC PLUG STDERR:\n{}",
            String::from_utf8_lossy(&output.stderr)
        );
        return Err(anyhow::anyhow!("wac plug failed"));
    }
    Ok(())
}

fn spawn_wasmtime(
    workspace_root: &std::path::Path,
    composed_wasm: &std::path::Path,
    wasm_port: u16,
    mock_auth_port: u16,
    email_sink_port: u16,
) -> Result<std::process::Child> {
    println!(
        "Launching composed Wasm component under Wasmtime serve on port {}...",
        wasm_port
    );
    let child = Command::new("wasmtime")
        .args(&[
            "serve",
            "--addr",
            &format!("127.0.0.1:{}", wasm_port),
            "-S",
            "inherit-network=y",
            "-S",
            "cli=y",
            "-S",
            "inherit-env=y",
            composed_wasm.to_str().unwrap(),
        ])
        .current_dir(workspace_root)
        .stdout(std::process::Stdio::inherit())
        .stderr(std::process::Stdio::inherit())
        .spawn()
        .context("Failed to spawn wasmtime serve")?;
    Ok(child)
}

async fn run_e2e_tests(wasm_port: u16, mock_auth_port: u16, email_sink_port: u16) -> Result<()> {
    let client = reqwest::Client::new();

    // --- TEST 1: Wasm Application Sanity Request (Sanity check pipeline logic) ---
    println!(
        "[E2E Test] Test 1: Sanity request to composed Wasm application on port {}...",
        wasm_port
    );
    let app_url = format!("http://127.0.0.1:{}", wasm_port);
    let res = client
        .get(&app_url)
        .send()
        .await
        .context("Failed to send request to Wasm application")?;

    assert_eq!(
        res.status(),
        reqwest::StatusCode::OK,
        "Wasm app response was not 200 OK"
    );
    let body = res.text().await?;
    println!("[E2E Test] Wasm app response body: {}", body);
    assert!(
        body.contains("Hello from Leptos Auth Demo!"),
        "Response body did not contain expected content"
    );
    println!("[E2E Test] Test 1: PASSED!");

    // --- TEST 2: Email Sink (POST /email/send, GET /email/inbox, DELETE /email/inbox) ---
    println!(
        "[E2E Test] Test 2: Verify Email Sink functionality on port {}...",
        email_sink_port
    );

    // Clear email inbox first
    let delete_url = format!("http://127.0.0.1:{}/email/inbox", email_sink_port);
    let res = client.delete(&delete_url).send().await?;
    assert_eq!(res.status(), reqwest::StatusCode::OK);

    // Send email with OTP
    let send_url = format!("http://127.0.0.1:{}/email/send", email_sink_port);
    let email_payload = json!({
        "to": "user@example.com",
        "subject": "E2E Test OTP",
        "body": "Your security code is 123456. Do not share it."
    });
    let res = client.post(&send_url).json(&email_payload).send().await?;
    assert_eq!(res.status(), reqwest::StatusCode::OK);

    // Query inbox
    let inbox_url = format!(
        "http://127.0.0.1:{}/email/inbox?to=user@example.com",
        email_sink_port
    );
    let res = client.get(&inbox_url).send().await?;
    assert_eq!(res.status(), reqwest::StatusCode::OK);
    let emails: serde_json::Value = res.json().await?;
    let emails_arr = emails
        .as_array()
        .context("Inbox response is not a JSON array")?;
    assert_eq!(emails_arr.len(), 1);

    let msg = &emails_arr[0];
    assert_eq!(msg["to"], "user@example.com");
    assert_eq!(msg["otp"], "123456");
    println!("[E2E Test] Successfully extracted OTP '123456' from Mock Email Inbox!");

    // Clear inbox
    let res = client.delete(&delete_url).send().await?;
    assert_eq!(res.status(), reqwest::StatusCode::OK);

    // Verify inbox is empty
    let res = client.get(&inbox_url).send().await?;
    let emails: serde_json::Value = res.json().await?;
    let emails_arr = emails
        .as_array()
        .context("Inbox response is not a JSON array")?;
    assert!(emails_arr.is_empty());
    println!("[E2E Test] Test 2: PASSED!");

    // --- TEST 3: Mock Behavior (POST /mock/configure-behavior) ---
    println!(
        "[E2E Test] Test 3: Verify Mock Behavior configuration on port {}...",
        mock_auth_port
    );

    // Configure rotation & latency
    let config_url = format!(
        "http://127.0.0.1:{}/mock/configure-behavior",
        mock_auth_port
    );
    let behavior_payload = json!({
        "jwks_key_rotation": true,
        "signature_key_invalid": false,
        "oidc_error": null,
        "latency_ms": 50,
        "network_dropout": false
    });
    let res = client
        .post(&config_url)
        .json(&behavior_payload)
        .send()
        .await?;
    assert_eq!(res.status(), reqwest::StatusCode::OK);

    // Fetch JWKS and confirm rotated key id
    let jwks_url = format!("http://127.0.0.1:{}/jwks", mock_auth_port);
    let res = client.get(&jwks_url).send().await?;
    assert_eq!(res.status(), reqwest::StatusCode::OK);
    let jwks: serde_json::Value = res.json().await?;
    let keys = jwks["keys"].as_array().context("JWKS missing keys array")?;
    assert!(!keys.is_empty());
    let kid = keys[0]["kid"].as_str().context("Key missing kid")?;
    assert_eq!(kid, "mock-key-id-2");
    println!(
        "[E2E Test] Successfully verified rotated JWKS key ID: {}",
        kid
    );
    println!("[E2E Test] Test 3: PASSED!");

    Ok(())
}

pub async fn main_impl() -> Result<(), Box<dyn std::error::Error>> {
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR")?;
    let workspace_root = std::path::Path::new(&manifest_dir)
        .join("../..")
        .canonicalize()?;

    // 1. Compile target crates and mock server
    compile_targets(&workspace_root)?;

    // 2. Identify ports
    let mock_auth_port = get_unused_port();
    let email_sink_port = get_unused_port();
    let wasm_port = get_unused_port();

    println!("[E2E Runner] Dynamic port allocation:");
    println!("  Mock Auth Server Port: {}", mock_auth_port);
    println!("  SMTP/Email Sink Port: {}", email_sink_port);
    println!("  Wasm App Port:        {}", wasm_port);

    // 3. Compose components
    let composed_wasm_path =
        workspace_root.join("target/wasm32-wasip2/debug/composed_app_temp.wasm");
    let _temp_guard = TempFileGuard {
        path: composed_wasm_path.clone(),
    };
    compose_components(&workspace_root, &composed_wasm_path)?;

    // 4. Spawn mock auth server on mock_auth_port
    let mock_server_binary = workspace_root.join("target/debug/mock-auth-server");
    println!("Spawning mock-auth-server on port {}...", mock_auth_port);
    let mut mock_auth_child = Command::new(&mock_server_binary)
        .arg(mock_auth_port.to_string())
        .stdout(std::process::Stdio::inherit())
        .stderr(std::process::Stdio::inherit())
        .spawn()
        .context("Failed to spawn mock auth server")?;
    
    std::thread::sleep(Duration::from_millis(500));
    if let Some(status) = mock_auth_child.try_wait()? {
        println!("ERROR: mock-auth-server exited immediately with status: {:?}", status);
    }

    let _mock_auth_guard = ChildGuard {
        name: "mock-auth-server".to_string(),
        child: mock_auth_child,
    };

    // Spawn mock email server on email_sink_port
    println!("Spawning mock-email-server on port {}...", email_sink_port);
    let mut mock_email_child = Command::new(&mock_server_binary)
        .arg(email_sink_port.to_string())
        .stdout(std::process::Stdio::inherit())
        .stderr(std::process::Stdio::inherit())
        .spawn()
        .context("Failed to spawn mock email server")?;

    std::thread::sleep(Duration::from_millis(500));
    if let Some(status) = mock_email_child.try_wait()? {
        println!("ERROR: mock-email-server exited immediately with status: {:?}", status);
    }

    let _mock_email_guard = ChildGuard {
        name: "mock-email-server".to_string(),
        child: mock_email_child,
    };

    // 5. Wait for mock servers to bind
    if !wait_for_port(mock_auth_port, Duration::from_secs(15)) {
        return Err("Mock auth server failed to bind in time".into());
    }
    if !wait_for_port(email_sink_port, Duration::from_secs(15)) {
        return Err("Mock email server failed to bind in time".into());
    }

    // 6. Launch Wasmtime serve
    let wasmtime_child = spawn_wasmtime(
        &workspace_root,
        &composed_wasm_path,
        wasm_port,
        mock_auth_port,
        email_sink_port,
    )?;
    let _wasmtime_guard = ChildGuard {
        name: "wasmtime serve".to_string(),
        child: wasmtime_child,
    };

    if !wait_for_port(wasm_port, Duration::from_secs(15)) {
        return Err("Wasmtime serve failed to bind in time".into());
    }

    // 7. Run E2E tests
    run_e2e_tests(wasm_port, mock_auth_port, email_sink_port).await?;

    println!("[E2E Runner] All E2E integration tests PASSED successfully!");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_e2e_pipeline() -> Result<()> {
        let manifest_dir = std::env::var("CARGO_MANIFEST_DIR")?;
        let workspace_root = std::path::Path::new(&manifest_dir)
            .join("../..")
            .canonicalize()?;

        compile_targets(&workspace_root)?;

        // Let's test all WAC variations to find the working one!
        let interceptor_wasm = workspace_root.join("target/wasm32-wasip2/debug/wasi_auth_interceptor.wasm");
        let demo_wasm = workspace_root.join("target/wasm32-wasip2/debug/leptos_auth_demo.wasm");
        
        let wac_variations = vec![
            (
                "let demo = new root:component {}; let composed = new wasi:auth-interceptor { \"wasi:http/incoming-handler@0.2.4\": demo }; export composed;",
                vec![
                    ("wasi:auth-interceptor", interceptor_wasm.to_str().unwrap()),
                    ("root:component", demo_wasm.to_str().unwrap())
                ]
            ),
            (
                "let demo = new local:demo {}; let composed = new wasi:auth-interceptor { \"wasi:http/incoming-handler@0.2.4\": demo }; export composed;",
                vec![
                    ("wasi:auth-interceptor", interceptor_wasm.to_str().unwrap()),
                    ("local:demo", demo_wasm.to_str().unwrap())
                ]
            ),
        ];

        for (idx, (wac_src, deps)) in wac_variations.iter().enumerate() {
            let file_path = workspace_root.join(format!("target/wasm32-wasip2/debug/test_var_{}.wac", idx));
            let content = format!("package local:composition;\n\n{}", wac_src);
            std::fs::write(&file_path, content)?;
            
            let mut args = vec!["compose", file_path.to_str().unwrap(), "--import-dependencies"];
            let dep_strs: Vec<String> = deps.iter().map(|(name, path)| format!("{}={}", name, path)).collect();
            for dep_str in &dep_strs {
                args.push("--dep");
                args.push(dep_str);
            }
            args.push("-o");
            let out_wasm = workspace_root.join(format!("target/wasm32-wasip2/debug/out_var_{}.wasm", idx));
            args.push(out_wasm.to_str().unwrap());
            
            let res = Command::new("wac").args(&args).output()?;
            if res.status.success() {
                println!(">>> VARIATION {} SUCCESS!", idx);
            } else {
                println!(">>> VARIATION {} FAILED: {}", idx, String::from_utf8_lossy(&res.stderr));
            }
            std::fs::remove_file(&file_path).ok();
            std::fs::remove_file(&out_wasm).ok();
        }

        let mock_auth_port = get_unused_port();
        let email_sink_port = get_unused_port();
        let wasm_port = get_unused_port();

        let composed_wasm_path =
            workspace_root.join("target/wasm32-wasip2/debug/composed_app_test_temp.wasm");
        let _temp_guard = TempFileGuard {
            path: composed_wasm_path.clone(),
        };
        compose_components(&workspace_root, &composed_wasm_path)?;

        let mock_server_binary = workspace_root.join("target/debug/mock-auth-server");
        let mock_auth_child = Command::new(&mock_server_binary)
            .arg(mock_auth_port.to_string())
            .stdout(std::process::Stdio::inherit())
            .stderr(std::process::Stdio::inherit())
            .spawn()?;
        let _mock_auth_guard = ChildGuard {
            name: "mock-auth-server".to_string(),
            child: mock_auth_child,
        };

        let mock_email_child = Command::new(&mock_server_binary)
            .arg(email_sink_port.to_string())
            .stdout(std::process::Stdio::inherit())
            .stderr(std::process::Stdio::inherit())
            .spawn()?;
        let _mock_email_guard = ChildGuard {
            name: "mock-email-server".to_string(),
            child: mock_email_child,
        };

        if !wait_for_port(mock_auth_port, Duration::from_secs(15))
            || !wait_for_port(email_sink_port, Duration::from_secs(15))
        {
            return Err(anyhow::anyhow!("Mock servers failed to start"));
        }

        let wasmtime_child = spawn_wasmtime(
            &workspace_root,
            &composed_wasm_path,
            wasm_port,
            mock_auth_port,
            email_sink_port,
        )?;
        let _wasmtime_guard = ChildGuard {
            name: "wasmtime serve".to_string(),
            child: wasmtime_child,
        };

        if !wait_for_port(wasm_port, Duration::from_secs(15)) {
            return Err(anyhow::anyhow!("Wasmtime serve failed to start"));
        }

        run_e2e_tests(wasm_port, mock_auth_port, email_sink_port).await?;
        Ok(())
    }

    #[tokio::test]
    async fn test_wac_plug_only() -> Result<()> {
        let manifest_dir = std::env::var("CARGO_MANIFEST_DIR")?;
        let workspace_root = std::path::Path::new(&manifest_dir)
            .join("../..")
            .canonicalize()?;

        compile_targets(&workspace_root)?;

        let interceptor_wasm =
            workspace_root.join("target/wasm32-wasip2/debug/wasi_auth_interceptor.wasm");
        let demo_wasm = workspace_root.join("target/wasm32-wasip2/debug/leptos_auth_demo.wasm");
        let output_path = workspace_root.join("target/wasm32-wasip2/debug/plug_test_composed.wasm");

        println!("Running wac plug test...");
        let output = Command::new("wac")
            .args(&[
                "plug",
                "--plug",
                demo_wasm.to_str().unwrap(),
                interceptor_wasm.to_str().unwrap(),
                "-o",
                output_path.to_str().unwrap(),
            ])
            .current_dir(&workspace_root)
            .output()?;

        println!("WAC PLUG STATUS: {:?}", output.status);
        println!("WAC PLUG STDOUT: {}", String::from_utf8_lossy(&output.stdout));
        println!("WAC PLUG STDERR: {}", String::from_utf8_lossy(&output.stderr));

        assert!(output.status.success(), "wac plug failed");
        Ok(())
    }
}
