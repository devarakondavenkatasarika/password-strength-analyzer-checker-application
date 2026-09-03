from flask import Flask, render_template, request
import re
import hashlib
import sqlite3

app = Flask(__name__)

# --- Password Strength Check ---
def check_strength(password: str) -> dict:
    score = 0
    feedback = []

    if len(password) >= 12:
        score += 2
    elif len(password) >= 8:
        score += 1
    else:
        feedback.append("Password too short (min 8 chars).")

    if re.search(r"[A-Z]", password):
        score += 1
    else:
        feedback.append("Add uppercase letters.")

    if re.search(r"[a-z]", password):
        score += 1
    else:
        feedback.append("Add lowercase letters.")

    if re.search(r"[0-9]", password):
        score += 1
    else:
        feedback.append("Add digits.")

    if re.search(r"[@$!%*?&]", password):
        score += 1
    else:
        feedback.append("Add special characters (@$!%*?&).")

    return {"score": score, "feedback": feedback}


def suggest_password(password: str) -> str:
    suggestion = password
    if len(suggestion) < 12:
        suggestion += "123!"
    if not re.search(r"[A-Z]", suggestion):
        suggestion += "A"
    if not re.search(r"[a-z]", suggestion):
        suggestion += "a"
    if not re.search(r"[0-9]", suggestion):
        suggestion += "9"
    if not re.search(r"[@$!%*?&]", suggestion):
        suggestion += "@"
    return suggestion


def init_db():
    conn = sqlite3.connect("old_passwords.db")
    c = conn.cursor()
    c.execute("CREATE TABLE IF NOT EXISTS passwords (hash TEXT)")
    conn.commit()
    conn.close()

def is_reused(password: str) -> bool:
    conn = sqlite3.connect("old_passwords.db")
    c = conn.cursor()
    hashed = hashlib.sha256(password.encode()).hexdigest()
    c.execute("SELECT * FROM passwords WHERE hash=?", (hashed,))
    reused = c.fetchone() is not None
    conn.close()
    return reused

def save_password(password: str):
    conn = sqlite3.connect("old_passwords.db")
    c = conn.cursor()
    hashed = hashlib.sha256(password.encode()).hexdigest()
    c.execute("INSERT INTO passwords VALUES (?)", (hashed,))
    conn.commit()
    conn.close()


@app.route("/", methods=["GET", "POST"])
def index():
    init_db()
    result = None
    suggestion = None
    reused = False

    if request.method == "POST":
        password = request.form["password"]

        if is_reused(password):
            reused = True
        else:
            result = check_strength(password)
            suggestion = suggest_password(password)
            save_password(password)

    return render_template("index.html", result=result, suggestion=suggestion, reused=reused)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=10000)
