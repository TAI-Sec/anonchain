"""SQLite session log — portable via paths.py."""
import sqlite3, threading, time, json
from pathlib import Path
from paths import DB_FILE, HOME_DIR, ensure_home

SCHEMA = """
CREATE TABLE IF NOT EXISTS sessions(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts REAL NOT NULL, name TEXT, notes TEXT);
CREATE TABLE IF NOT EXISTS requests(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  session_id INTEGER, ts REAL, proto TEXT, host TEXT,
  port INTEGER, hop_count INTEGER, status TEXT);
CREATE TABLE IF NOT EXISTS events(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  session_id INTEGER, ts REAL, level TEXT, message TEXT);
CREATE INDEX IF NOT EXISTS idx_req_session ON requests(session_id);
CREATE INDEX IF NOT EXISTS idx_evt_session ON events(session_id);
"""


class SessionDB:
    def __init__(self, on_event=None, db_path=None):
        self.on_event = on_event or (lambda *a, **k: None)
        ensure_home()
        self.path = Path(db_path) if db_path else DB_FILE
        self._lock = threading.Lock()
        self.conn = sqlite3.connect(str(self.path), check_same_thread=False)
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.executescript(SCHEMA)
        self.conn.commit()
        self.session_id = None

    def start_session(self, name="session", notes=""):
        with self._lock:
            c = self.conn.cursor()
            c.execute("INSERT INTO sessions(ts,name,notes) VALUES(?,?,?)",
                      (time.time(), name, notes))
            self.conn.commit()
            self.session_id = c.lastrowid
        return self.session_id

    def end_session(self): self.session_id = None

    def log_request(self, proto, host, port, hop_count, status="ok"):
        if not self.session_id: return
        with self._lock:
            self.conn.execute(
                "INSERT INTO requests(session_id,ts,proto,host,port,hop_count,status)"
                " VALUES(?,?,?,?,?,?,?)",
                (self.session_id, time.time(), proto, host, port,
                 hop_count, status))
            self.conn.commit()

    def log_event(self, level, message):
        if not self.session_id: return
        with self._lock:
            self.conn.execute(
                "INSERT INTO events(session_id,ts,level,message) VALUES(?,?,?,?)",
                (self.session_id, time.time(), level, message))
            self.conn.commit()

    def list_sessions(self, limit=50):
        c = self.conn.cursor()
        c.execute("SELECT id,ts,name,notes FROM sessions ORDER BY id DESC LIMIT ?",
                  (limit,))
        return c.fetchall()

    def replay(self, session_id):
        c = self.conn.cursor()
        c.execute("SELECT ts,proto,host,port,hop_count,status FROM requests"
                  " WHERE session_id=? ORDER BY ts", (session_id,))
        return c.fetchall()

    def export_json(self, session_id, path):
        data = {"session": session_id, "requests": [], "events": []}
        for r in self.replay(session_id):
            data["requests"].append({"ts": r[0], "proto": r[1], "host": r[2],
                                     "port": r[3], "hops": r[4],
                                     "status": r[5]})
        c = self.conn.cursor()
        c.execute("SELECT ts,level,message FROM events WHERE session_id=?"
                  " ORDER BY ts", (session_id,))
        for e in c.fetchall():
            data["events"].append({"ts": e[0], "level": e[1], "message": e[2]})
        Path(path).write_text(json.dumps(data, indent=2))
        return True

    def close(self):
        try: self.conn.close()
        except Exception: pass
