import json, os

DB_FILE = "login_history.json"

def load():
    if not os.path.exists(DB_FILE):
        return {}
    with open(DB_FILE) as f:
        return json.load(f)

def save(db):
    with open(DB_FILE, "w") as f:
        json.dump(db, f, indent=2)

def get_history(username):
    return load().get(username, [])

def add_login(username, record):
    db = load()
    db.setdefault(username, []).append(record)
    # Keep only last 50 logins per user
    db[username] = db[username][-50:]
    save(db)

FAIL_DB = "fail_history.json"

def load_fails():
    if not os.path.exists(FAIL_DB):
        return {}
    with open(FAIL_DB) as f:
        return json.load(f)

def save_fails(data):
    with open(FAIL_DB, "w") as f:
        json.dump(data, f, indent=2)

def get_fail_history(username):
    return load_fails().get(username, [])

def add_fail(username, record):
    data = load_fails()
    data.setdefault(username, []).append(record)
    data[username] = data[username][-100:]
    save_fails(data)
