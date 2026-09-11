"""A local notes API, with SQLite persistence and no Chio dependency."""

import argparse
import json
import sqlite3
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit


class Notes(BaseHTTPRequestHandler):
    def setup(self):
        super().setup()
        self.connection.settimeout(10)

    def respond(self, status, payload):
        body = json.dumps(payload, separators=(",", ":")).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        path = urlsplit(self.path).path
        with sqlite3.connect(self.server.database) as database:
            if path == "/healthz":
                return self.respond(200, {"status": "ready"})
            if path == "/notes":
                rows = database.execute(
                    "SELECT id, text FROM notes ORDER BY id DESC LIMIT 100"
                ).fetchall()
                return self.respond(
                    200,
                    {
                        "notes": [{"id": row[0], "text": row[1]} for row in rows],
                        "total": database.execute("SELECT COUNT(*) FROM notes").fetchone()[0],
                    },
                )
            if path.startswith("/notes/") and path[7:].isdigit():
                row = database.execute(
                    "SELECT id, text FROM notes WHERE id = ?", (int(path[7:]),)
                ).fetchone()
                if row:
                    return self.respond(200, {"id": row[0], "text": row[1]})
        self.respond(404, {"error": "note_not_found"})

    def do_POST(self):
        if urlsplit(self.path).path != "/notes":
            return self.respond(404, {"error": "route_not_found"})
        if self.headers.get("Transfer-Encoding"):
            return self.respond(400, {"error": "content_length_required"})
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if not 0 < length <= 8192:
                return self.respond(413, {"error": "body_must_be_1_to_8192_bytes"})
            raw = self.rfile.read(length)
            if len(raw) != length:
                return self.respond(400, {"error": "incomplete_body"})
            payload = json.loads(raw)
            text = payload.get("text") if isinstance(payload, dict) else None
            if not isinstance(text, str) or not 1 <= len(text.strip()) <= 1000:
                return self.respond(400, {"error": "text_must_be_1_to_1000_characters"})
        except (ValueError, UnicodeError):
            return self.respond(400, {"error": "invalid_json_body"})
        with sqlite3.connect(self.server.database) as database:
            cursor = database.execute("INSERT INTO notes(text) VALUES (?)", (text,))
            note_id = cursor.lastrowid
        self.respond(201, {"id": note_id, "text": text})

    def do_DELETE(self):
        path = urlsplit(self.path).path
        if not path.startswith("/notes/") or not path[7:].isdigit():
            return self.respond(404, {"error": "route_not_found"})
        with sqlite3.connect(self.server.database) as database:
            cursor = database.execute("DELETE FROM notes WHERE id = ?", (int(path[7:]),))
        self.respond(200 if cursor.rowcount else 404, {"deleted": cursor.rowcount == 1})


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, default=8087)
    parser.add_argument("--data", type=Path, default=Path(".notes"))
    args = parser.parse_args()
    args.data.mkdir(mode=0o700, parents=True, exist_ok=True)
    database = args.data / "notes.db"
    with sqlite3.connect(database) as connection:
        connection.execute(
            "CREATE TABLE IF NOT EXISTS notes(id INTEGER PRIMARY KEY, text TEXT NOT NULL)"
        )
    server = ThreadingHTTPServer(("127.0.0.1", args.port), Notes)
    server.database = database
    print(f"Notes API: http://127.0.0.1:{args.port}; data: {database}", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
