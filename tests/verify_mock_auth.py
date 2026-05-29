import urllib.request
import urllib.error
import json
import sys

class NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def http_error_302(self, req, fp, code, msg, hdrs):
        # Return the response instead of following it
        return fp

def test_endpoints(port):
    base_url = f"http://127.0.0.1:{port}"
    print(f"Testing mock-auth-server at {base_url}...")
    
    # Custom opener to intercept redirects
    opener = urllib.request.build_opener(NoRedirectHandler)
    
    # 1. Test GET /authorize
    auth_url = f"{base_url}/authorize?redirect_uri=http://localhost:3000/callback&state=mystate"
    print("\n--- GET /authorize ---")
    try:
        req = urllib.request.Request(auth_url)
        resp = opener.open(req)
        status = resp.status if hasattr(resp, 'status') else resp.code
        headers = resp.headers
        print(f"Status Code: {status}")
        location = headers.get('Location')
        print(f"Location Header: {location}")
        
        assert status == 302, f"Expected 302, got {status}"
        assert location is not None, "Missing Location header"
        assert "code=mock_code_123" in location, f"Expected authorization code in redirect, got: {location}"
        assert "state=mystate" in location, f"Expected state parameter in redirect, got: {location}"
        print("GET /authorize PASS")
    except Exception as e:
        print(f"GET /authorize FAIL: {e}")
        sys.exit(1)
        
    # 2. Test POST /token
    token_url = f"{base_url}/token"
    print("\n--- POST /token ---")
    try:
        req = urllib.request.Request(token_url, data=b"", method="POST")
        with urllib.request.urlopen(req) as resp:
            status = resp.status if hasattr(resp, 'status') else resp.code
            body = resp.read().decode('utf-8')
            print(f"Status Code: {status}")
            print(f"Response Body: {body}")
            
            assert status == 200, f"Expected 200, got {status}"
            data = json.loads(body)
            assert "access_token" in data, "Missing access_token"
            assert "token_type" in data, "Missing token_type"
            assert data["token_type"] == "Bearer", f"Expected Bearer token_type, got {data['token_type']}"
            assert "expires_in" in data, "Missing expires_in"
            assert "id_token" in data, "Missing id_token"
            assert "refresh_token" in data, "Missing refresh_token"
            print("POST /token PASS")
    except Exception as e:
        print(f"POST /token FAIL: {e}")
        sys.exit(1)
        
    # 3. Test GET /jwks
    jwks_url = f"{base_url}/jwks"
    print("\n--- GET /jwks ---")
    try:
        req = urllib.request.Request(jwks_url)
        with urllib.request.urlopen(req) as resp:
            status = resp.status if hasattr(resp, 'status') else resp.code
            body = resp.read().decode('utf-8')
            print(f"Status Code: {status}")
            print(f"Response Body: {body}")
            
            assert status == 200, f"Expected 200, got {status}"
            data = json.loads(body)
            assert "keys" in data, "Missing keys list"
            assert len(data["keys"]) > 0, "Keys list is empty"
            key = data["keys"][0]
            assert "kty" in key, "Missing kty"
            assert key["kty"] == "RSA", f"Expected RSA, got {key['kty']}"
            assert "use" in key, "Missing use"
            assert key["use"] == "sig", "Expected sig use"
            assert "alg" in key, "Missing alg"
            assert key["alg"] == "RS256", "Expected RS256 alg"
            assert "kid" in key, "Missing kid"
            assert "n" in key, "Missing n modulus"
            assert "e" in key, "Missing e exponent"
            print("GET /jwks PASS")
    except Exception as e:
        print(f"GET /jwks FAIL: {e}")
        sys.exit(1)
        
    # 4. Test GET /userinfo
    userinfo_url = f"{base_url}/userinfo"
    print("\n--- GET /userinfo ---")
    try:
        req = urllib.request.Request(userinfo_url)
        with urllib.request.urlopen(req) as resp:
            status = resp.status if hasattr(resp, 'status') else resp.code
            body = resp.read().decode('utf-8')
            print(f"Status Code: {status}")
            print(f"Response Body: {body}")
            
            assert status == 200, f"Expected 200, got {status}"
            data = json.loads(body)
            assert "sub" in data, "Missing sub"
            assert data["sub"] == "user_id_12345", f"Unexpected sub: {data['sub']}"
            assert "name" in data, "Missing name"
            assert "email" in data, "Missing email"
            assert "roles" in data, "Missing roles"
            assert "user" in data["roles"], "Missing user role"
            print("GET /userinfo PASS")
    except Exception as e:
        print(f"GET /userinfo FAIL: {e}")
        sys.exit(1)

    print("\nAll endpoints verified successfully!")

if __name__ == "__main__":
    port = 8085
    if len(sys.argv) > 1:
        port = int(sys.argv[1])
    test_endpoints(port)
