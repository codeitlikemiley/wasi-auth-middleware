import subprocess
import os

wac_variations = [
    # 1. Using package name in quotes
    """package local:composition;
import interceptor: "wasi:auth-interceptor";
import demo: "wasi:auth-interceptor";
let composed = new interceptor {
    "wasi:http/incoming-handler@0.2.4": demo
};
export composed;
""",
    # 2. Using world path as type
    """package local:composition;
import interceptor: wasi:auth-interceptor/interceptor;
import demo: wasi:auth-interceptor/interceptor;
let composed = new interceptor {
    "wasi:http/incoming-handler@0.2.4": demo
};
export composed;
""",
    # 3. Using package name directly but as dependency namespace
    """package local:composition;
import interceptor: wasi:auth-interceptor;
import demo: wasi:auth-interceptor;
let composed = new interceptor {
    "wasi:http/incoming-handler@0.2.4": demo
};
export composed;
""",
    # 4. Using type identifier
    """package local:composition;
import interceptor: interceptor;
import demo: demo;
let composed = new interceptor {
    "wasi:http/incoming-handler@0.2.4": demo
};
export composed;
""",
    # 5. Using type identifier and new with the package path/name
    """package local:composition;
import interceptor: interceptor;
import demo: demo;
let composed = new wasi:auth-interceptor/interceptor {
    "wasi:http/incoming-handler@0.2.4": demo
};
export composed;
""",
    # 6. Using path/name in new
    """package local:composition;
import interceptor: interceptor;
import demo: demo;
let composed = new wasi:auth-interceptor {
    "wasi:http/incoming-handler@0.2.4": demo
};
export composed;
"""
]

workspace_root = "/Users/uriah/.gemini/antigravity/scratch/wasi-auth-middleware"
interceptor_wasm = os.path.join(workspace_root, "target/wasm32-wasip2/debug/wasi_auth_interceptor.wasm")
demo_wasm = os.path.join(workspace_root, "target/wasm32-wasip2/debug/leptos_auth_demo.wasm")

# Ensure files exist (run cargo build target first if needed, but they should exist from our test runs)
if not os.path.exists(interceptor_wasm):
    print("wasi_auth_interceptor.wasm does not exist. Please run cargo build first.")
    exit(1)

for i, wac in enumerate(wac_variations, 1):
    wac_file = f"test_{i}.wac"
    with open(wac_file, "w") as f:
        f.write(wac)
    
    print(f"\n--- Testing Variation {i} ---")
    print(wac)
    
    # We can try different --dep configurations too
    # Let's try key matching the import type or name
    # We'll try: wasi:auth-interceptor = interceptor_wasm
    cmd = [
        "wac", "compose", wac_file,
        "--dep", f"wasi:auth-interceptor={interceptor_wasm}",
        "--dep", f"local:demo={demo_wasm}",
        "-o", "temp_composed.wasm"
    ]
    
    # Let's run it
    res = subprocess.run(cmd, capture_output=True, text=True)
    if res.returncode == 0:
        print(f"Variation {i} SUCCESS with wasi:auth-interceptor and local:demo!")
        os.remove(wac_file)
        if os.path.exists("temp_composed.wasm"):
            os.remove("temp_composed.wasm")
        break
    else:
        print(f"Variation {i} failed: {res.stderr.strip()}")
        
    # Try with --dep matching name=path
    cmd = [
        "wac", "compose", wac_file,
        "--dep", f"interceptor={interceptor_wasm}",
        "--dep", f"demo={demo_wasm}",
        "-o", "temp_composed.wasm"
    ]
    res = subprocess.run(cmd, capture_output=True, text=True)
    if res.returncode == 0:
        print(f"Variation {i} SUCCESS with interceptor and demo!")
        os.remove(wac_file)
        if os.path.exists("temp_composed.wasm"):
            os.remove("temp_composed.wasm")
        break
    else:
        print(f"Variation {i} failed (with interceptor/demo deps): {res.stderr.strip()}")
        
    os.remove(wac_file)
