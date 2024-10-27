from http.server import BaseHTTPRequestHandler, HTTPServer
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from urllib.parse import urlparse, parse_qs
import base64
import json
import jwt
import datetime
import sqlite3

# Define the hostname and server port
host_name = "localhost"
server_port = 8080

# Database setup
db_file = "totally_not_my_privateKeys.db"
conn = sqlite3.connect(db_file)
cursor = conn.cursor()

# Create keys table if it doesn't exist
cursor.execute("""
CREATE TABLE IF NOT EXISTS keys (
    kid INTEGER PRIMARY KEY AUTOINCREMENT,
    key BLOB NOT NULL,
    exp INTEGER NOT NULL
)
""")
conn.commit()


# Function to serialize key to PEM format and store in the database
def store_key(key, exp_offset):
    pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
    exp = int((datetime.datetime.now() + exp_offset).timestamp())
    cursor.execute("INSERT INTO keys (key, exp) VALUES (?, ?)", (pem, exp))
    conn.commit()


# Generate keys with different expiration times
store_key(
    rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
    ),
    datetime.timedelta(hours=1)
)
store_key(
    rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
    ),
    -datetime.timedelta(hours=1))


# Function to retrieve key based on expiration requirement
def retrieve_key(expired=False):
    now = int(datetime.datetime.now().timestamp())
    if expired:
        cursor.execute("SELECT key FROM keys WHERE exp < ? LIMIT 1", (now,))
    else:
        cursor.execute("SELECT key FROM keys WHERE exp >= ? LIMIT 1", (now,))
    row = cursor.fetchone()
    if row:
        return serialization.load_pem_private_key(row[0], password=None)
    return None


# JWKS helper function
def int_to_base64(value):
    value_hex = format(value, 'x')
    value_hex = '0' + value_hex if len(value_hex) % 2 == 1 else value_hex
    value_bytes = bytes.fromhex(value_hex)
    return base64.urlsafe_b64encode(value_bytes).rstrip(b'=').decode('utf-8')


# HTTP server class to handle REST API requests for JWTs and JWKS
class MyServer(BaseHTTPRequestHandler):
    def do_POST(self):
        parsed_path = urlparse(self.path)
        params = parse_qs(parsed_path.query)
        if parsed_path.path == "/auth":
            expired = 'expired' in params
            key = retrieve_key(expired=expired)
            if not key:
                self.send_response(404)
                self.end_headers()
                self.wfile.write(b"No suitable key found")
                return
            token_payload = {
                "user": "username",
                "exp":
                    (datetime.datetime.now()+datetime.timedelta(hours=1)).timestamp()
                    if not expired
                    else (datetime.datetime.now()-datetime.timedelta(hours=1)).timestamp()
            }
            headers = {"kid": "expiredKID" if expired else "goodKID"}
            encoded_jwt = jwt.encode(
                token_payload, key, algorithm="RS256", headers=headers
            )
            self.send_response(200)
            self.end_headers()
            self.wfile.write(bytes(encoded_jwt, "utf-8"))
            return
        self.send_response(405)
        self.end_headers()

    # Handle GET requests to serve the JWKS (public keys) response
    def do_GET(self):
        if self.path == "/.well-known/jwks.json":
            # Retrieve all valid (non-expired) keys for JWKS
            now = int(datetime.datetime.now().timestamp())
            cursor.execute("SELECT key FROM keys WHERE exp >= ?", (now,))
            keys = cursor.fetchall()

            # Build JWKS response from retrieved keys
            jwks_keys = []
            for key_pem in keys:
                key = serialization.load_pem_private_key(
                    key_pem[0],
                    password=None
                )
                numbers = key.private_numbers().public_numbers
                jwks_keys.append({
                    "alg": "RS256",
                    "kty": "RSA",
                    "use": "sig",
                    "kid": "goodKID",
                    "n": int_to_base64(numbers.n),
                    "e": int_to_base64(numbers.e),
                })

            # Send JWKS response with JSON content type
            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.end_headers()
            self.wfile.write(bytes(json.dumps({"keys": jwks_keys}), "utf-8"))
            return
        self.send_response(405)
        self.end_headers()

# Start and stop the HTTP server
if __name__ == "__main__":
    web_server = HTTPServer((host_name, server_port), MyServer)
    try:
        web_server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        cursor.execute("DELETE FROM keys")
        conn.commit()
        conn.close()
        web_server.server_close()
