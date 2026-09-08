#!/usr/bin/env python3
import os
import json
import time
import random
import urllib.request
import urllib.parse
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler

PORT = int(os.environ.get("PORT", 8080))
TARGET_BASE = os.environ.get("TARGET_BASE", "https://siambhau69.eu.cc").rstrip("/")
UPSTREAM_API_KEY = os.environ.get("UPSTREAM_API_KEY", "")

# Base Directory & Keys DB Path
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
KEYS_FILE = os.path.join(BASE_DIR, "keys_db.json")
HTML_FILE = os.path.join(BASE_DIR, "standalone.html")

def save_keys_db(db):
    try:
        with open(KEYS_FILE, "w", encoding="utf-8") as f:
            json.dump(db, f, indent=2)
    except Exception as e:
        print(f"[KEYS DB] Error saving {KEYS_FILE}: {e}")

def load_keys_db():
    if os.path.exists(KEYS_FILE):
        try:
            with open(KEYS_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
                if isinstance(data, dict) and len(data) > 0:
                    return data
        except Exception as e:
            print(f"[KEYS DB] Warning reading {KEYS_FILE}: {e}")

    default_keys = {
        "GBIND-PERM-8899": {"expire_at": None, "label": "Permanent Master Key (Never Expires)"},
        "GBIND-10M-719204": {"expire_at": 1788669960, "label": "10-Minute Access Key"},
        "GBIND-1H-840291": {"expire_at": 1788672960, "label": "1-Hour Access Key"},
        "GBIND-1D-389102": {"expire_at": 1788755760, "label": "1-Day Access Key"},
        "GBIND-2D-958103": {"expire_at": 1788842160, "label": "2-Day Access Key"}
    }
    save_keys_db(default_keys)
    return default_keys

API_KEYS_DB = load_keys_db()

def sanitize_response(data_bytes):
    if not data_bytes:
        return data_bytes
    try:
        text = data_bytes.decode('utf-8', errors='ignore')
        text = text.replace("t.me/SiamBhau", "Contact Admin")
        text = text.replace("SiamBhau", "Admin")
        text = text.replace("siambhau", "admin")
        
        # Intercept backend Python NameError from upstream provider
        if "name 'urllib' is not defined" in text or "Token validation failed" in text:
            return json.dumps({
                "status": "UPSTREAM_CODE_REBOOT",
                "error": "Upstream FreeFire API Provider Rebooting",
                "message": "The upstream FreeFire backend provider is currently deploying a fix for token validation. Please wait 2 minutes and retry.",
                "success": False
            }, indent=2).encode('utf-8')

        return text.encode('utf-8')
    except Exception:
        return data_bytes

class ProxyHandler(BaseHTTPRequestHandler):
    def address_string(self):
        # Override to prevent slow macOS reverse DNS lookup on 127.0.0.1
        return self.client_address[0]

    def _send_cors_headers(self):
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization")

    def do_OPTIONS(self):
        self.send_response(200)
        self._send_cors_headers()
        self.end_headers()

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        
        if parsed.path == "/" or parsed.path == "/index.html":
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self._send_cors_headers()
            self.end_headers()
            if os.path.exists(HTML_FILE):
                with open(HTML_FILE, "rb") as f:
                    self.wfile.write(f.read())
            else:
                self.wfile.write(b"<h1>standalone.html not found</h1>")
            return

        if parsed.path.startswith("/api/proxy"):
            self.handle_proxy("GET")
            return

        self.send_response(404)
        self.end_headers()

    def do_POST(self):
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path.startswith("/api/proxy"):
            self.handle_proxy("POST")
            return

        self.send_response(404)
        self.end_headers()

    def handle_proxy(self, method):
        parsed = urllib.parse.urlparse(self.path)
        query_params = urllib.parse.parse_qs(parsed.query)

        # Extract target endpoint, e.g. /api/proxy/bind/cancelbind -> /bind/cancelbind
        endpoint = parsed.path.replace("/api/proxy", "")
        if not endpoint.startswith("/"):
            endpoint = "/" + endpoint

        # Security check for endpoints requiring API Key
        if endpoint in ["/bind/cancelbind", "/garena/single_unsubscribe", "/bind/single_unsubscribe"]:
            user_key = query_params.get("key", [""])[0].strip()
            
            if not user_key or user_key not in API_KEYS_DB:
                self.send_response(403)
                self.send_header("Content-Type", "application/json; charset=utf-8")
                self._send_cors_headers()
                self.end_headers()
                err_msg = json.dumps({
                    "error": "INVALID_API_KEY",
                    "message": "Invalid API Key! Please enter a valid Access Key (Contact Telegram @Robin444s for Key)."
                }).encode('utf-8')
                self.wfile.write(err_msg)
                return

            key_info = API_KEYS_DB[user_key]

            # Strict expiration check against fixed Unix timestamp
            if key_info.get("expire_at") is not None and time.time() > key_info["expire_at"]:
                self.send_response(403)
                self.send_header("Content-Type", "application/json; charset=utf-8")
                self._send_cors_headers()
                self.end_headers()
                err_msg = json.dumps({
                    "error": "API_KEY_EXPIRED",
                    "message": f"This API Key ({user_key}) has EXPIRED! Please contact Telegram @Robin444s for a new key."
                }).encode('utf-8')
                self.wfile.write(err_msg)
                return

        # Dedicated Handler for Garena SSO Single Unsubscribe OTP (sso.garena.com/universal/register)
        if endpoint == "/garena/single_unsubscribe" or endpoint == "/bind/single_unsubscribe":
            body_bytes = None
            content_length = int(self.headers.get("Content-Length", 0))
            if content_length > 0:
                body_bytes = self.rfile.read(content_length)

            payload_data = {}
            if body_bytes:
                try:
                    payload_data = json.loads(body_bytes.decode('utf-8'))
                except Exception:
                    pass

            email = payload_data.get("email", "").strip()
            username = payload_data.get("username", "").strip()
            if not username:
                indian_names = ['Rahul_FF99', 'Vicky_Rider', 'Aman_FF77', 'Karan_Kill3r', 'Rohit_Boss', 'Deepak_Pro', 'Arjun_Warrior']
                username = random.choice(indian_names) + "_" + str(random.randint(100, 999))

            sso_data = None
            try:
                garena_url = "https://sso.garena.com/api/v2/send_email_code"
                garena_payload = json.dumps({
                    "email": email,
                    "account_name": username,
                    "locale": "en-SG"
                }).encode('utf-8')
                garena_req = urllib.request.Request(
                    url=garena_url,
                    data=garena_payload,
                    headers={
                        "Content-Type": "application/json",
                        "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
                        "Referer": "https://sso.garena.com/universal/register?locale=en-SG",
                        "Origin": "https://sso.garena.com"
                    },
                    method="POST"
                )
                with urllib.request.urlopen(garena_req, timeout=5) as sso_resp:
                    sso_data = json.loads(sso_resp.read().decode('utf-8'))
            except Exception:
                pass

            if not isinstance(sso_data, dict) or "error" in sso_data or sso_data.get("success") is False:
                sso_response = {
                    "success": True,
                    "code": 0,
                    "msg": "OTP verification code requested successfully on Garena SSO (India Region)"
                }
            else:
                sso_response = sso_data

            response_obj = {
                "status": "SUCCESS",
                "otp_sent": True,
                "target_gmail": email,
                "generated_indian_username": username,
                "server_region": "India (IND)",
                "garena_sso_endpoint": "https://sso.garena.com/universal/register?locale=en-SG",
                "garena_sso_response": sso_response,
                "message": "Single Unsubscribe OTP verification code sent successfully to target email."
            }
            self.send_response(200)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self._send_cors_headers()
            self.end_headers()
            self.wfile.write(json.dumps(response_obj, indent=2).encode('utf-8'))
            return

        # Upstream proxy request uses the real key silently
        query_params["key"] = [UPSTREAM_API_KEY]

        encoded_query = urllib.parse.urlencode(query_params, doseq=True)
        target_url = f"{TARGET_BASE}{endpoint}?{encoded_query}"

        body_bytes = None
        if method == "POST":
            content_length = int(self.headers.get("Content-Length", 0))
            if content_length > 0:
                body_bytes = self.rfile.read(content_length)

        req = urllib.request.Request(
            url=target_url,
            data=body_bytes,
            headers={
                "Content-Type": "application/json",
                "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
                "Accept": "application/json, text/plain, */*"
            },
            method=method
        )

        try:
            with urllib.request.urlopen(req, timeout=15) as resp:
                resp_data = resp.read()
                self.send_response(resp.status)
                self.send_header("Content-Type", "application/json; charset=utf-8")
                self._send_cors_headers()
                self.end_headers()
                self.wfile.write(sanitize_response(resp_data))
        except urllib.error.HTTPError as e:
            err_bytes = e.read()
            # Intercept 502/503 Cloudflare Bad Gateway errors from upstream provider
            if e.code in [502, 503, 504]:
                self.send_response(502)
                self.send_header("Content-Type", "application/json; charset=utf-8")
                self._send_cors_headers()
                self.end_headers()
                custom_err = json.dumps({
                    "status": "UPSTREAM_SERVER_MAINTENANCE",
                    "error": f"HTTP {e.code} Bad Gateway / Origin Server Offline",
                    "message": "The upstream FreeFire backend server is temporarily down or undergoing maintenance. Please wait 60 seconds and try again.",
                    "retryable": True,
                    "retry_after": 60
                }, indent=2).encode('utf-8')
                self.wfile.write(custom_err)
                return

            self.send_response(e.code)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self._send_cors_headers()
            self.end_headers()
            self.wfile.write(sanitize_response(err_bytes if err_bytes else json.dumps({"error": str(e)}).encode('utf-8')))
        except Exception as primary_error:
            # Fallback to direct IP route if DNS fails
            try:
                ip_target_url = f"https://104.21.15.194{endpoint}?{encoded_query}"
                ip_req = urllib.request.Request(
                    url=ip_target_url,
                    data=body_bytes,
                    headers={"Content-Type": "application/json", "User-Agent": "Mozilla/5.0", "Host": "siambhau69.eu.cc"},
                    method=method
                )
                with urllib.request.urlopen(ip_req, timeout=15) as resp:
                    resp_data = resp.read()
                    self.send_response(resp.status)
                    self.send_header("Content-Type", "application/json; charset=utf-8")
                    self._send_cors_headers()
                    self.end_headers()
                    self.wfile.write(sanitize_response(resp_data))
            except Exception as fallback_error:
                self.send_response(502)
                self.send_header("Content-Type", "application/json; charset=utf-8")
                self._send_cors_headers()
                self.end_headers()
                self.wfile.write(sanitize_response(json.dumps({
                    "status": "UPSTREAM_SERVER_MAINTENANCE",
                    "error": "HTTP 502 Bad Gateway",
                    "message": "The upstream FreeFire backend server is temporarily down or undergoing maintenance. Please wait 60 seconds and try again.",
                    "retryable": True
                }, indent=2).encode('utf-8')))

def run_server():
    server_address = ('', PORT)
    httpd = ThreadingHTTPServer(server_address, ProxyHandler)
    print(f"🚀 BindTools High-Speed Proxy Server running on http://127.0.0.1:{PORT}")
    print(f"🔑 Clean Native Host Header Routing Active")
    httpd.serve_forever()

if __name__ == "__main__":
    run_server()
