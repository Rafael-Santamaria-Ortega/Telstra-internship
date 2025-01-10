from http.server import BaseHTTPRequestHandler, HTTPServer
import re  # For regular expression matching

host = "localhost"
port = 8000

# Replace with specific patterns you want to block
BLOCKED_HEADERS_PATTERNS = [
    "suffix":"%>//",
    "c1":"Runtime",
    "c2":"<%",
    "DNT":"1",
    "Content-Type":"application/x-www-form-urlencoded"  # Example suspicious header
    # Add more patterns as needed
]

def block_request(self):
    # Check for blocked headers
    if self.path=='/tomcatwar.jsp':
        for pattern in BLOCKED_HEADERS_PATTERNS:
            if any(re.search(pattern, header) for header, _ in self.headers.items()):
                print("Blocking request")
                return True

    return False  # Allow request if no blocking criteria met


def handle_request(self):
    if block_request(self):
        self.send_response(403, "Forbidden")  # Respond with 403 for blocked requests
    else:
        self.send_response(200)  # Allow legitimate requests
    self.send_header("content-type", "text/plain")  # Set appropriate content type
    self.end_headers()
    self.wfile.write(b"Firewall message: Request processed.")


class ServerHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        handle_request(self)

    def do_POST(self):
        handle_request(self)


if __name__ == "__main__":
    server = HTTPServer((host, port), ServerHandler)
    print("[+] Firewall Server (Blocking)")
    print("[+] HTTP Web Server running on: %s:%s" % (host, port))

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass

    server.server_close()
    print("[+] Server terminated. Exiting...")
    exit(0)
