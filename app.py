import os
from flask import Flask, request, jsonify, send_file
import sqlite3
import re
import time

app = Flask(__name__)

FLAG_IMAGE_PATH = "/etc/secrets/img.txt"  # Secure location
VALID_PASSWORD = os.getenv("VALID_PASSWORD", "defaultpassword")  # Use env variable
DB_FILE = "database.db"

def init_db():
    """Initialize the database and create the users table."""
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("CREATE TABLE IF NOT EXISTS users (username TEXT, password TEXT)")
    
    # Insert user only if it doesn't exist
    c.execute("SELECT COUNT(*) FROM users WHERE username = 'admin'")
    if c.fetchone()[0] == 0:
        c.execute("INSERT INTO users VALUES ('admin', ?)", (VALID_PASSWORD,))

    conn.commit()
    conn.close()

@app.before_request
def before_request():
    """Ensure the database is initialized before every request."""
    init_db()

def is_strong_sqli_attempt(data):
    """Detects advanced SQL injection patterns to block."""
    sqli_patterns = [
        # Basic SQL keywords
        r"\bSELECT\b", r"\bUNION\b", r"\bINSERT\b", r"\bDROP\b", r"\bUPDATE\b", 
        r"\bDELETE\b", r"\bORDER\s+BY\b", r"\bHAVING\b", r"\bGROUP\s+BY\b", r"\bCASE\b",
        r"\bWHEN\b", r"\bTHEN\b", r"\bELSE\b", r"\bEND\b", r"\bLIMIT\b", r"\bOFFSET\b",

        # SQL functions used in attacks
        r"\bLENGTH\s*\(", r"\bSUBSTR\s*\(", r"\bASCII\s*\(", r"\bIF\s*\(", r"\bSLEEP\s*\(",
        r"\bDATABASE\s*\(", r"\bVERSION\s*\(", r"\bUSER\s*\(", r"\bBENCHMARK\s*\(",

        # Logical operations and boolean-based injection techniques
        r"\bOR\s+1=1\b", r"\bAND\s+1=1\b", r"\bLIKE\s+'.*%'", r"\bRLIKE\b",

        # Comment abuse
        r"--", r"#", r"/\*.*\*/",

        # System functions and database enumeration
        r"\bINFORMATION_SCHEMA\b", r"\bTABLE_NAME\b", r"\bCOLUMN_NAME\b",
        r"\bXP_CMDSHELL\b", r"\bEXEC\b", r"\bUNION\s+SELECT\b",

        # Hex/Unicode bypasses
        r"0x[0-9A-Fa-f]+", r"CHAR\s*\("
    ]

    for pattern in sqli_patterns:
        if re.search(pattern, data, re.IGNORECASE):
            return True

    return False


@app.route("/api/login", methods=["POST"])
def login():
    data = request.get_json()
    username = data.get("username", "")
    password = data.get("password", "")

    # Strong WAF - Blocks common SQLi patterns
    if is_strong_sqli_attempt(username) or is_strong_sqli_attempt(password):
        return jsonify({"error": "Blocked by WAF!"}), 403

    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()

    # Check if password prefix is correct
    query = "SELECT password FROM users WHERE username = 'admin'"
    c.execute(query)
    stored_password = c.fetchone()
    conn.close()

    if stored_password:
        stored_password = stored_password[0]
        
        if stored_password.startswith(password):
            if password == stored_password:
                time.sleep(5)
                return send_hidden_image()  # Return image only if full password is correct
            else:
                time.sleep(5)  # Introduce a delay to indicate partial correctness
                return jsonify({"error": "Incorrect credentials"}), 401

    return jsonify({"error": "Invalid credentials"}), 401

def send_hidden_image():
    """Serves a custom image as a flag."""
    return send_file(FLAG_IMAGE_PATH, mimetype="image/png")

if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=10000)

