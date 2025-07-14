import http.server
import socketserver
import argparse
import os
import logging
import ssl
import time
import json
import uuid
from dotenv import load_dotenv
from urllib.parse import urlparse, parse_qs
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

# Load environment variables from .env file
load_dotenv()

PORT = int(os.getenv("PORT", 8081))
MODE = os.getenv("MODE", "development").lower()
ACCESS_TOKEN = os.getenv("ACCESS_TOKEN", "")
RATE_LIMIT = int(os.getenv("RATE_LIMIT", 10))
SSL_CERT = os.getenv("SSL_CERT", "")
SSL_KEY = os.getenv("SSL_KEY", "")
CORS_ORIGIN = os.getenv("CORS_ORIGIN", "*")
MIME_TYPES = dict(
    item.split("=") for item in os.getenv("MIME_TYPES", "").split(",") if "=" in item
)
RESPONSE_HEADERS = dict(
    item.split("=") for item in os.getenv("RESPONSE_HEADERS", "").split(",") if "=" in item
)
ADMIN_TOKEN = os.getenv("ADMIN_TOKEN", "")

rate_limit_store = {}
AUDIT_LOG = "audit.log"
SOURCE_DIR = os.getenv("SOURCE_DIR", "source")

# Logging setup
logging.basicConfig(filename='server.log', level=logging.INFO, format='%(asctime)s %(message)s')

def audit_log(action, detail):
    with open(AUDIT_LOG, "a") as f:
        f.write(f"{time.ctime()} | {action} | {detail}\n")

def is_rate_limited(ip):
    now = time.time()
    window = 60  # seconds
    if ip not in rate_limit_store:
        rate_limit_store[ip] = []
    rate_limit_store[ip] = [t for t in rate_limit_store[ip] if now - t < window]
    if len(rate_limit_store[ip]) >= RATE_LIMIT:
        return True
    rate_limit_store[ip].append(now)
    return False

def check_access_token(headers, required_token):
    return headers.get('Authorization') == f"Bearer {required_token}"

def custom_error_page(code, message):
    return f"""<html><head><title>{code} {message}</title></head>
    <body><h1>{code} {message}</h1><p>Custom error page.</p></body></html>"""

def get_mime_type(path):
    ext = os.path.splitext(path)[1]
    return MIME_TYPES.get(ext, None)

def get_request_id():
    return str(uuid.uuid4())

def check_file_access(file_path, token):
    access_file = os.path.join(os.path.dirname(file_path), ".access")
    if not os.path.exists(access_file):
        return True
    with open(access_file, "r") as f:
        allowed = [line.strip() for line in f if line.strip()]
    return token in allowed

class HotReloadHandler(FileSystemEventHandler):
    def __init__(self):
        self.last_event = time.time()
    def on_any_event(self, event):
        self.last_event = time.time()
        logging.info(f"Hot reload: {event.src_path} {event.event_type}")

class SecureHandler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, directory=None, **kwargs):
        super().__init__(*args, directory=directory, **kwargs)

    def end_headers(self):
        self.send_header("Access-Control-Allow-Origin", CORS_ORIGIN)
        self.send_header("Cache-Control", "public, max-age=3600")
        for k, v in RESPONSE_HEADERS.items():
            self.send_header(k, v)
        self.send_header("X-Request-ID", self.request_id)
        super().end_headers()

    def log_message(self, format, *args):
        logging.info("%s - - [%s] %s" % (
            self.client_address[0],
            self.log_date_time_string(),
            format % args
        ))

    def send_custom_error(self, code, message):
        self.send_response(code)
        self.send_header("Content-type", "text/html")
        self.end_headers()
        self.wfile.write(custom_error_page(code, message).encode())
        audit_log("ERROR", f"{code} {message} {self.path}")

    def do_GET(self):
        self.request_id = get_request_id()
        ip = self.client_address[0]
        # Remove rate limiting for development mode
        if MODE == "production" and is_rate_limited(ip):
            self.send_custom_error(429, "Too Many Requests")
            return

        parsed_path = urlparse(self.path)
        token = self.headers.get('Authorization', '').replace("Bearer ", "")

        # Access control for production
        if MODE == "production" and not check_access_token(self.headers, ACCESS_TOKEN):
            self.send_custom_error(401, "Unauthorized")
            return

        # Per-file access control
        file_path = os.path.join(self.directory, parsed_path.path.lstrip("/"))
        if os.path.isfile(file_path) and not check_file_access(file_path, token):
            self.send_custom_error(403, "Forbidden (per-file access)")
            return

        if parsed_path.path == "/api/status":
            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.end_headers()
            status = {
                "mode": MODE,
                "source_dir": self.directory,
                "time": time.ctime(),
                "client_ip": ip,
                "request_id": self.request_id
            }
            self.wfile.write(json.dumps(status).encode())
            audit_log("API", f"Status requested by {ip}")
            return

        if parsed_path.path == "/api/health":
            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"status": "ok", "time": time.ctime()}).encode())
            return

        if parsed_path.path == "/admin":
            if not check_access_token(self.headers, ADMIN_TOKEN):
                self.send_custom_error(401, "Unauthorized (admin)")
                return
            self.send_response(200)
            self.send_header("Content-type", "text/html")
            self.end_headers()
            with open(AUDIT_LOG, "r") as f:
                logs = f.read()
            html = f"""<html><head><title>Admin Dashboard</title></head>
            <body><h1>Admin Dashboard</h1>
            <pre>{logs}</pre>
            </body></html>"""
            self.wfile.write(html.encode())
            return

        if parsed_path.path == "/api/upload" and self.command == "GET":
            self.send_response(405)
            self.end_headers()
            return

        # Serve index.html at root if it exists
        if parsed_path.path == "/" and os.path.isfile(os.path.join(self.directory, "index.html")):
            self.path = "/index.html"
            audit_log("DOWNLOAD", f"{ip} requested {self.path} ({self.request_id})")
            return super().do_GET()

        # Custom directory index (JSON listing)
        if os.path.isdir(file_path):
            if MODE == "production":
                self.send_custom_error(403, "Directory listing not allowed")
                return
            files = os.listdir(file_path)
            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps(files).encode())
            return

        # Custom MIME types
        mime_type = get_mime_type(parsed_path.path)
        if mime_type:
            self.extensions_map[""] = mime_type

        audit_log("DOWNLOAD", f"{ip} requested {self.path} ({self.request_id})")
        super().do_GET()

    def do_HEAD(self):
        self.request_id = get_request_id()
        ip = self.client_address[0]
        # Remove rate limiting for development mode
        if MODE == "production" and is_rate_limited(ip):
            self.send_custom_error(429, "Too Many Requests")
            return
        super().do_HEAD()

    def do_POST(self):
        self.request_id = get_request_id()
        ip = self.client_address[0]
        # Remove rate limiting for developmemt mode
        if MODE == "production" and is_rate_limited(ip):
            self.send_custom_error(429, "Too Many Requests")
            return

        parsed_path = urlparse(self.path)
        token = self.headers.get('Authorization', '').replace("Bearer ", "")

        if parsed_path.path == "/api/upload":
            # Access control for production
            if MODE == "production" and not check_access_token(self.headers, ACCESS_TOKEN):
                self.send_custom_error(401, "Unauthorized")
                return

            content_length = int(self.headers.get('Content-Length', 0))
            if content_length > 10 * 1024 * 1024:  # 10MB limit
                self.send_custom_error(413, "Payload Too Large")
                return

            filename = self.headers.get('X-Filename')
            if not filename:
                self.send_custom_error(400, "Missing X-Filename header")
                return

            file_path = os.path.join(self.directory, filename)
            # File versioning
            if os.path.exists(file_path):
                versioned = f"{file_path}.{int(time.time())}"
                os.rename(file_path, versioned)
                audit_log("VERSION", f"File {filename} versioned as {versioned}")

            with open(file_path, "wb") as f:
                f.write(self.rfile.read(content_length))
            self.send_response(201)
            self.end_headers()
            self.wfile.write(b"File uploaded successfully.")
            audit_log("UPLOAD", f"{ip} uploaded {filename} ({self.request_id})")
            return

        self.send_custom_error(405, "Method Not Allowed")

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", CORS_ORIGIN)
        self.send_header("Access-Control-Allow-Methods", "GET, POST, HEAD, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Authorization, X-Filename, Content-Type")
        self.end_headers()

    def do_PUT(self):
        self.send_custom_error(405, "Method Not Allowed")

    def do_DELETE(self):
        self.send_custom_error(405, "Method Not Allowed")

    def do_PATCH(self):
        self.send_custom_error(405, "Method Not Allowed")

def start_hot_reload(path):
    event_handler = HotReloadHandler()
    observer = Observer()
    observer.schedule(event_handler, path, recursive=True)
    observer.start()
    print(f"Hot reload watching {path}")
    return observer

def main():
    parser = argparse.ArgumentParser(description="Serve files from a specified source directory.")
    parser.add_argument('--source', type=str, default=SOURCE_DIR, help='Directory to serve files from')
    parser.add_argument('--host', type=str, default=os.getenv("HOST", "127.0.0.1"), help='Host to bind the server to')
    parser.add_argument('--mode', type=str, choices=['development', 'production'], default=MODE, help='Server mode: development or production')
    args = parser.parse_args()

    mode = args.mode.lower()
    host = "0.0.0.0" if mode == "production" else args.host
    source_dir = os.path.abspath(args.source)
    if not os.path.isdir(source_dir):
        print(f"Directory '{source_dir}' does not exist. Creating it.")
        os.makedirs(source_dir, exist_ok=True)

    handler = lambda *a, **kw: SecureHandler(*a, directory=source_dir, **kw)

    observer = start_hot_reload(source_dir)

    try:
        with socketserver.TCPServer((host, PORT), handler) as httpd:
            if mode == "production" and SSL_CERT and SSL_KEY:
                httpd.socket = ssl.wrap_socket(httpd.socket, certfile=SSL_CERT, keyfile=SSL_KEY, server_side=True)
                print(f"Serving HTTPS files from {source_dir} at https://{host}:{PORT}")
            else:
                print(f"Serving files from {source_dir} at http://{host}:{PORT}")
            httpd.serve_forever()
    except Exception as e:
        print(f"Server error: {e}")
        logging.error(f"Server error: {e}")
    finally:
        observer.stop()
        observer.join()

if __name__ == "__main__":
    main()
