#!/bin/bash
workspace_root="/Users/uriah/.gemini/antigravity/scratch/wasi-auth-middleware"
interceptor_wasm="$workspace_root/target/wasm32-wasip2/debug/wasi_auth_interceptor.wasm"
demo_wasm="$workspace_root/target/wasm32-wasip2/debug/leptos_auth_demo.wasm"

mkdir -p "$workspace_root/target/wasm32-wasip2/debug"

test_wac() {
    local idx=$1
    local content=$2
    local wac_file="$workspace_root/target/test_$idx.wac"
    local out_wasm="$workspace_root/target/test_$idx.wasm"
    
    echo "$content" > "$wac_file"
    
    echo "--- Testing Variation $idx ---"
    echo "$content"
    wac compose "$wac_file" \
        --dep wasi:auth-interceptor="$interceptor_wasm" \
        --dep local:demo="$demo_wasm" \
        -o "$out_wasm" 2>&1
    
    if [ $? -eq 0 ]; then
        echo ">>> SUCCESS for Variation $idx!"
        rm -f "$wac_file" "$out_wasm"
        exit 0
    else
        echo ">>> FAILED"
    fi
    rm -f "$wac_file" "$out_wasm"
    echo ""
}

# Variation 1
test_wac 1 'package local:composition;
import demo: local:demo/root;
let composed = new wasi:auth-interceptor/root {
    "wasi:http/incoming-handler@0.2.2": demo,
};
export composed;'

# Variation 2
test_wac 2 'package local:composition;
import demo: local:demo;
let composed = new wasi:auth-interceptor/root {
    "wasi:http/incoming-handler@0.2.2": demo,
};
export composed;'

# Variation 3
test_wac 3 'package local:composition;
import demo: local:demo;
let composed = new wasi:auth-interceptor/interceptor {
    "wasi:http/incoming-handler@0.2.2": demo,
};
export composed;'

# Variation 4
test_wac 4 'package local:composition;
import demo: local:demo/root;
let composed = new wasi:auth-interceptor/interceptor {
    "wasi:http/incoming-handler@0.2.2": demo,
};
export composed;'

# Variation 5
test_wac 5 'package local:composition;
import demo: local:demo;
let composed = new wasi:auth-interceptor {
    "wasi:http/incoming-handler@0.2.2": demo,
};
export composed;'

# Variation 6
test_wac 6 'package local:composition;
import demo: local:demo/root;
let composed = new wasi:auth-interceptor {
    "wasi:http/incoming-handler@0.2.2": demo,
};
export composed;'

# Variation 7 (no imports, inline instantiation of demo if allowed, wait: WAC doesn't support that but let's see)
test_wac 7 'package local:composition;
let demo_inst = new local:demo/root {};
let composed = new wasi:auth-interceptor/root {
    "wasi:http/incoming-handler@0.2.2": demo_inst,
};
export composed;'

# Variation 8
test_wac 8 'package local:composition;
let demo_inst = new local:demo {};
let composed = new wasi:auth-interceptor {
    "wasi:http/incoming-handler@0.2.2": demo_inst,
};
export composed;'

echo "All variations failed."
exit 1
