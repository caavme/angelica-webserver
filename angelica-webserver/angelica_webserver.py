import http.server
import socketserver
import argparse
import os

PORT = 8081

def main():
    parser = argparse.ArgumentParser(description="Serve files from a specified source directory.")
    parser.add_argument('--source', type=str, default='source', help='Directory to serve files from')
    args = parser.parse_args()

    source_dir = os.path.abspath(args.source)
    if not os.path.isdir(source_dir):
        print(f"Error: Directory '{source_dir}' does not exist.")
        return

    class CustomHandler(http.server.SimpleHTTPRequestHandler):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, directory=source_dir, **kwargs)

    with socketserver.TCPServer(("", PORT), CustomHandler) as httpd:
        print(f"Serving files from {source_dir} at http://0.0.0.0:{PORT}")
        httpd.serve_forever()

if __name__ == "__main__":
    main()
