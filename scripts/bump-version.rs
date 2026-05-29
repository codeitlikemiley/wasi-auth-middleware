use std::env;
use std::fs;
use std::process::{Command, exit};

fn run_command(cmd: &str, args: &[&str]) {
    println!("Running: {} {}", cmd, args.join(" "));
    let status = Command::new(cmd)
        .args(args)
        .status()
        .unwrap_or_else(|err| {
            eprintln!("Failed to execute command '{}': {}", cmd, err);
            exit(1);
        });
    if !status.success() {
        eprintln!("Error: Command '{}' failed with status: {:?}", cmd, status);
        exit(status.code().unwrap_or(1));
    }
}

fn main() {
    // 1. Run checks first before doing anything
    println!("=== Running pre-bump checks ===");
    run_command("cargo", &["fmt", "--all", "--", "--check"]);
    run_command("cargo", &["clippy", "--all-targets", "--all-features", "--", "-D", "warnings"]);
    run_command("cargo", &["test", "--workspace", "--all-features"]);
    println!("=== Pre-bump checks passed successfully! ===\n");

    // 2. Read current version from wasi-auth-traits/Cargo.toml
    let reference_toml = "wasi-auth-traits/Cargo.toml";
    let content = fs::read_to_string(reference_toml).unwrap_or_else(|err| {
        eprintln!("Error reading {}: {}", reference_toml, err);
        exit(1);
    });

    let mut current_version = None;
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("version =") || trimmed.starts_with("version=") {
            if let Some(start) = line.find('"') {
                if let Some(end) = line[start + 1..].find('"') {
                    current_version = Some(line[start + 1..start + 1 + end].to_string());
                    break;
                }
            }
        }
    }

    let current_version = current_version.unwrap_or_else(|| {
        eprintln!("Error: Could not find version in wasi-auth-traits/Cargo.toml");
        exit(1);
    });

    println!("Current workspace version: {}", current_version);

    // Determine target version
    let args: Vec<String> = env::args().collect();
    let target_version = if args.len() > 1 && !args[1].trim().is_empty() {
        let val = args[1].trim().to_string();
        println!("Bumping to user-specified version: {}", val);
        val
    } else {
        // Auto bump patch version
        let parts: Vec<&str> = current_version.split('.').collect();
        if parts.len() != 3 {
            eprintln!("Error: Current version '{}' is not in standard X.Y.Z semver format.", current_version);
            exit(1);
        }
        let patch: u32 = parts[2].parse().unwrap_or_else(|_| {
            eprintln!("Error: Patch version part '{}' in '{}' is not an integer.", parts[2], current_version);
            exit(1);
        });
        let new_patch = patch + 1;
        let val = format!("{}.{}.{}", parts[0], parts[1], new_patch);
        println!("Auto-bumping patch version: {} -> {}", current_version, val);
        val
    };

    if target_version == current_version {
        println!("⚠️  Version is already {} — nothing to bump.", current_version);
        return;
    }

    // 3. Update all workspace manifests
    let manifests = vec![
        "wasi-auth-traits/Cargo.toml",
        "wasi-auth-core/Cargo.toml",
        "leptos-wasi-auth/Cargo.toml",
        "wasi-auth-interceptor/Cargo.toml",
        "wasi-auth-providers/Cargo.toml",
        "examples/leptos-auth-demo/Cargo.toml",
        "tests/mock-auth-server/Cargo.toml",
        "tests/e2e-runner/Cargo.toml",
    ];

    for manifest_path in &manifests {
        println!("Updating version in {}...", manifest_path);
        let content = fs::read_to_string(manifest_path).unwrap_or_else(|err| {
            eprintln!("Error reading {}: {}", manifest_path, err);
            exit(1);
        });

        let mut lines: Vec<String> = content.lines().map(|s| s.to_string()).collect();
        let mut in_package = false;

        for line in &mut lines {
            let trimmed = line.trim();
            if trimmed == "[package]" {
                in_package = true;
                continue;
            }
            if in_package && trimmed.starts_with('[') {
                in_package = false;
            }

            // Update package version
            if in_package && trimmed.starts_with("version") {
                if let Some(start) = line.find('"') {
                    if let Some(end) = line[start + 1..].find('"') {
                        let prefix = &line[..start + 1];
                        let suffix = &line[start + 1 + end..];
                        *line = format!("{}{}{}", prefix, target_version, suffix);
                    }
                }
            }

            // Update workspace crate dependency references (e.g. wasi-auth-traits = { version = "X.Y.Z" })
            let dependency_prefixes = vec![
                "wasi-auth-traits",
                "wasi-auth-core",
                "leptos-wasi-auth",
                "wasi-auth-providers",
                "wasi-auth-interceptor",
            ];
            for dep in &dependency_prefixes {
                if (trimmed.starts_with(dep) || trimmed.starts_with(&format!("\"{}\"", dep))) && trimmed.contains("version") {
                    if let Some(version_idx) = line.find("version") {
                        if let Some(start) = line[version_idx..].find('"') {
                            let abs_start = version_idx + start;
                            if let Some(end) = line[abs_start + 1..].find('"') {
                                let prefix = &line[..abs_start + 1];
                                let suffix = &line[abs_start + 1 + end..];
                                *line = format!("{}{}{}", prefix, target_version, suffix);
                            }
                        }
                    }
                }
            }
        }

        let new_content = lines.join("\n") + "\n";
        fs::write(manifest_path, new_content).unwrap_or_else(|err| {
            eprintln!("Error writing {}: {}", manifest_path, err);
            exit(1);
        });
    }

    // 4. Update Cargo.lock
    println!("Updating Cargo.lock by running cargo check...");
    run_command("cargo", &["check", "--workspace"]);

    // 5. Git Commit and Tag
    println!("Staging changes...");
    run_command("git", &["add", "Cargo.lock"]);
    for manifest_path in &manifests {
        run_command("git", &["add", manifest_path]);
    }

    let commit_msg = format!("chore: bump version to {}", target_version);
    println!("Committing version bump (excluding git hooks)...");
    run_command("git", &["commit", "-m", &commit_msg, "--no-verify"]);

    let tag_name = format!("v{}", target_version);
    println!("Creating git tag {}...", tag_name);
    run_command("git", &["tag", "-a", &tag_name, "-m", &format!("Release {}", tag_name)]);

    println!("\n=======================================================");
    println!("SUCCESS: Workspace bumped, committed, and tagged locally!");
    println!("New Version: {}", target_version);
    println!("Git Tag:     {}", tag_name);
    println!("=======================================================");
}
