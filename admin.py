import os
import json
import pandas as pd
import pymysql
import pytz
from datetime import datetime, timedelta, timezone
from flask import Flask, request, jsonify, render_template, make_response, session
from flask_cors import CORS
from dbutils.pooled_db import PooledDB
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
import jwt
from functools import wraps
from collections import defaultdict
import time
from threading import Lock
from apscheduler.schedulers.background import BackgroundScheduler

# ---------- Load environment ----------
from dotenv import load_dotenv
load_dotenv()

app = Flask(__name__, template_folder=".")
CORS(app, supports_credentials=True)
app.config["SECRET_KEY"] = os.environ["admin_secret_key"]
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(hours=2)

IST = pytz.timezone("Asia/Kolkata")

# ---------- Database pool (admin credentials) ----------
admin_pool = PooledDB(
    creator=pymysql,
    maxconnections=1,
    blocking=True,
    host=os.environ.get("db_host", "localhost"),
    user=os.environ["admin"],
    password=os.environ["password"],
    database=os.environ.get("db_name", "iste"),
    autocommit=True,
    charset='utf8mb4'
)

def get_admin_conn():
    return admin_pool.connection()

# ---------- Auth utilities ----------
ph = PasswordHasher()
JWT_SECRET = os.environ["jwt_secret"]
JWT_ALGO = "HS256"

ADMIN_USER = os.environ["admin_user"]
ADMIN_PASSWORD_HASH = os.environ["admin_password"]

# Rate limiting (same logic as student)
failed_attempts = defaultdict(list)
rate_lock = Lock()

def check_rate_limit(identifier, max_attempts=5, base_block_sec=240):
    with rate_lock:
        attempts = failed_attempts[identifier]
        if not attempts:
            return False, 0
        count = len(attempts)
        if count < max_attempts:
            return False, 0
        last_attempt = attempts[-1]
        extra_batches = (count - max_attempts) // 4
        block_sec = base_block_sec * (2 ** extra_batches)
        if time.time() - last_attempt < block_sec:
            wait = block_sec - (time.time() - last_attempt)
            return True, wait
        else:
            failed_attempts[identifier] = []
            return False, 0

def record_failed_attempt(identifier):
    with rate_lock:
        failed_attempts[identifier].append(time.time())
        if len(failed_attempts[identifier]) > 50:
            failed_attempts[identifier] = failed_attempts[identifier][-50:]

def reset_failed_attempts(identifier):
    with rate_lock:
        failed_attempts[identifier] = []

def make_token(uid, is_admin=False):
    payload = {
        "user_id": uid,
        "is_admin": is_admin,
        "exp": datetime.now(timezone.utc) + timedelta(hours=7)
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGO)

def verify_token(token):
    try:
        if not token:
            return None
        if token.startswith('Bearer '):
            token = token[7:]
        return jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGO])
    except:
        return None

def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.cookies.get("token") or request.headers.get("Authorization")
        if not token:
            return jsonify({"error": "Missing token"}), 401
        payload = verify_token(token)
        if not payload or not payload.get("is_admin"):
            return jsonify({"error": "Admin access required"}), 403
        request.user = payload
        return f(*args, **kwargs)
    return decorated

# ---------- Background scheduler (alerts) ----------
def background_checker():
    with app.app_context():
        conn = get_admin_conn()
        cur = conn.cursor(pymysql.cursors.DictCursor)
        now_str = datetime.now(IST).strftime("%Y-%m-%d %H:%M:%S")
        cur.execute("SELECT id, title, start_at, reminders FROM assessments WHERE start_at > %s", (now_str,))
        upcoming = cur.fetchall()
        for u in upcoming:
            reminders = json.loads(u["reminders"]) if u.get("reminders") else []
            start_at = u["start_at"]
            for rem_str in reminders:
                delta = timedelta()
                for part in rem_str.split():
                    if "d" in part: delta += timedelta(days=int(part[:-1]))
                    elif "h" in part: delta += timedelta(hours=int(part[:-1]))
                    elif "m" in part: delta += timedelta(minutes=int(part[:-1]))
                rem_time = start_at - delta
                if IST.localize(rem_time) <= datetime.now(IST) <= IST.localize(rem_time + timedelta(minutes=1)):
                    print(f"!!! ALERT: Assessment '{u['title']}' starts in {rem_str} !!!")
        cur.close()
        conn.close()

scheduler = BackgroundScheduler(timezone=IST)
scheduler.add_job(func=background_checker, trigger="interval", minutes=1)
scheduler.start()

# ---------- Page routes ----------
@app.route("/admin")
def serve_admin():
    token = request.cookies.get("token")
    payload = verify_token(token) if token else None
    if not payload or not payload.get("is_admin"):
        return render_template("admin_login.html")
    return render_template("admin.html")

# ---------- Admin login ----------
@app.route("/admin/login", methods=["POST"])
def admin_login():
    body = request.json
    user = body.get("user")
    password = body.get("password")
    if not user or not password:
        return jsonify({"error": "Missing credentials"}), 400

    identifier = f"admin_{user}"
    blocked, wait = check_rate_limit(identifier)
    if blocked:
        return jsonify({"error": f"Too many attempts. Try again in {int(wait)} seconds."}), 429

    if user != ADMIN_USER:
        record_failed_attempt(identifier)
        return jsonify({"error": "Invalid credentials"}), 401

    try:
        ph.verify(ADMIN_PASSWORD_HASH, password)
    except VerifyMismatchError:
        record_failed_attempt(identifier)
        return jsonify({"error": "Invalid credentials"}), 401

    reset_failed_attempts(identifier)
    token = make_token("admin", is_admin=True)
    session.permanent = True
    session["user_id"] = "admin"
    session["is_admin"] = True
    resp = make_response(jsonify({"status": "Success"}))
    resp.set_cookie("token", token, httponly=True, secure=False, samesite="Lax", max_age=timedelta(hours=6))
    return resp

@app.route("/logout")
def logout():
    session.clear()
    resp = make_response(jsonify({"status": "Logged out"}))
    resp.delete_cookie("token")
    return resp

# ---------- Question Bank ----------
@app.route("/admin/upload_excel", methods=["POST"])
@admin_required
def upload_excel():
    if "file" not in request.files:
        return jsonify({"error": "No file"}), 400
    file = request.files["file"]
    try:
        df = pd.read_csv(file) if file.filename.lower().endswith(".csv") else pd.read_excel(file)
    except Exception as e:
        return jsonify({"error": f"Invalid file: {str(e)}"}), 400

    col_map = {str(c).strip().lower(): str(c) for c in df.columns}
    conn = get_admin_conn()
    cur = conn.cursor(pymysql.cursors.DictCursor)
    all_ids = []
    count = 0

    def get_int(col, default, min_val=None):
        c = col_map.get(col)
        if not c: return default
        val = row.get(c)
        if pd.isna(val) or str(val).strip() == "": return default
        try:
            parsed = int(float(val))
            return max(parsed, min_val) if min_val is not None else abs(parsed)
        except:
            return default

    for _, row in df.iterrows():
        q_type = str(row.get(col_map.get("type", ""), "MCQ")).strip().upper()
        if q_type not in ("MCQ", "MSQ", "INT", "NUM"): continue
        question_text = str(row.get(col_map.get("question", ""), "")).strip()
        if not question_text or question_text.lower() == "nan": continue

        mark = get_int("marks", 1, 1)
        neg_mark = get_int("negative_marks", 0, 0)
        correct_raw = str(row.get(col_map.get("correct", ""), "")).strip().lower()
        if not correct_raw or correct_raw == "nan": continue

        ans_dict = {}
        if q_type in ("MCQ", "MSQ"):
            options = []
            for c in df.columns:
                if len(str(c).strip()) == 1 and str(c).strip().isalpha():
                    val = row.get(c)
                    if pd.notna(val):
                        if isinstance(val, (int, float)) and val == int(val):
                            options.append(str(int(val)))
                        else:
                            s = str(val).strip()
                            if s and s != "nan": options.append(s)
            if len(options) < 2: continue
            ans_dict["options"] = options

            if q_type == "MCQ":
                if correct_raw.isalpha() and len(correct_raw) == 1:
                    idx = ord(correct_raw) - 97
                else:
                    try: idx = int(float(correct_raw))
                    except: continue
                if 0 <= idx < len(options):
                    ans_dict["correct_id"] = idx
                else: continue
            else:
                ids = []
                for v in correct_raw.replace(",", " ").split():
                    v = v.strip()
                    if v.isalpha() and len(v) == 1:
                        idx = ord(v) - 97
                    else:
                        try: idx = int(float(v))
                        except: continue
                    if 0 <= idx < len(options) and idx not in ids:
                        ids.append(idx)
                if not ids: continue
                ans_dict["correct_ids"] = ids

        elif q_type == "INT":
            try: ans_dict["value"] = int(float(correct_raw))
            except: continue
        elif q_type == "NUM":
            if "," in correct_raw:
                try:
                    parts = [float(x.strip()) for x in correct_raw.split(",")]
                    if len(parts) >= 2:
                        ans_dict["range"] = [parts[0], parts[1]]
                    else: continue
                except: continue
            else:
                try: ans_dict["value"] = float(correct_raw)
                except: continue

        q_norm = " ".join(question_text.lower().split())
        cur.execute("SELECT id FROM questions WHERE type=%s", (q_type,))
        existing = cur.fetchall()
        dup_id = None
        for eq in existing:
            cur.execute("SELECT question FROM questions WHERE id=%s", (eq["id"],))
            eq_text = cur.fetchone()["question"]
            if " ".join(eq_text.lower().split()) == q_norm:
                dup_id = eq["id"]
                break
        if dup_id:
            all_ids.append(dup_id)
        else:
            cur.execute("""
                INSERT INTO questions (type, question, answer, mark, negative_mark)
                VALUES (%s, %s, %s, %s, %s)
            """, (q_type, question_text, json.dumps(ans_dict), mark, neg_mark))
            all_ids.append(cur.lastrowid)
            count += 1

    conn.commit()
    cur.close(); conn.close()
    return jsonify({"status": "success", "count": count, "ids": all_ids})

@app.route("/admin/add_question", methods=["POST"])
@admin_required
def add_question():
    data = request.json
    q_type = data.get("type", "MCQ").upper()
    text = data.get("question", "").strip()
    mark = int(data.get("marks", 1))
    neg = int(data.get("negative_marks", 0))
    ans = {}
    if q_type in ("MCQ", "MSQ"):
        ans["options"] = data.get("options", [])
        if q_type == "MCQ":
            ans["correct_id"] = int(data.get("correct_id", 0))
        else:
            ans["correct_ids"] = data.get("correct_ids", [])
    elif q_type == "INT":
        ans["value"] = int(data.get("value", 0))
    elif q_type == "NUM":
        if "range" in data:
            ans["range"] = data["range"]
        else:
            ans["value"] = float(data.get("value", 0))

    conn = get_admin_conn()
    cur = conn.cursor()
    cur.execute("SELECT id, question FROM questions WHERE type=%s", (q_type,))
    existing = cur.fetchall()
    text_norm = " ".join(text.lower().split())
    for eid, eq_text in existing:
        if " ".join(eq_text.lower().split()) == text_norm:
            cur.close(); conn.close()
            return jsonify({"status": "duplicate", "id": eid})

    cur.execute("""
        INSERT INTO questions (type, question, answer, mark, negative_mark)
        VALUES (%s, %s, %s, %s, %s)
    """, (q_type, text, json.dumps(ans), mark, neg))
    new_id = cur.lastrowid
    conn.commit()
    cur.close(); conn.close()
    return jsonify({"status": "success", "id": new_id})

@app.route("/admin/questions", methods=["GET"])
@admin_required
def admin_questions():
    conn = get_admin_conn()
    cur = conn.cursor(pymysql.cursors.DictCursor)
    cur.execute("SELECT id, type, question, answer, mark FROM questions ORDER BY id DESC")
    rows = cur.fetchall()
    cur.close(); conn.close()
    for r in rows:
        if isinstance(r["answer"], str):
            try: r["answer"] = json.loads(r["answer"])
            except: pass
    return jsonify(rows)

# ---------- Assessments ----------
@app.route("/admin/create_assessment", methods=["POST"])
@admin_required
def create_assessment():
    data = request.json
    q_ids = data.get("question_ids", [])
    if not q_ids:
        return jsonify({"error": "No questions selected"}), 400

    conn = get_admin_conn()
    cur = conn.cursor()
    cur.execute("""
        INSERT INTO assessments (seq_num, title, type, start_at, start_until)
        VALUES (%s, %s, %s, %s, %s)
    """, (data.get("seq_num"), data["title"], data["type"], data["start_at"], data["start_until"]))
    aid = cur.lastrowid
    for qid in q_ids:
        cur.execute("INSERT INTO assessment_questions (assessment_id, question_id) VALUES (%s, %s)", (aid, qid))
    duration = min(int(data.get("duration", 60)), len(q_ids))
    cur.execute("UPDATE assessments SET total_duration=%s WHERE id=%s", (duration, aid))
    conn.commit()
    cur.close(); conn.close()
    return jsonify({"status": "Assessment created"})

@app.route("/admin/assessments", methods=["GET"])
@admin_required
def admin_assessments_list():
    conn = get_admin_conn()
    cur = conn.cursor(pymysql.cursors.DictCursor)
    cur.execute("SELECT id, title, type, seq_num, start_at, total_duration FROM assessments ORDER BY start_at DESC")
    rows = cur.fetchall()
    cur.close(); conn.close()
    for r in rows:
        if r["start_at"]:
            r["start_at"] = r["start_at"].isoformat()
    return jsonify(rows)

# ---------- Results ----------
@app.route("/admin/attempts", methods=["GET"])
@admin_required
def admin_attempts():
    user_id = request.args.get("user_id")
    conn = get_admin_conn()
    cur = conn.cursor(pymysql.cursors.DictCursor)
    query = """
        SELECT u.user_id, u.name, a.id as assessment_id, a.title, a.type, a.seq_num,
               IFNULL(sub.total_score,0) as total_score, IFNULL(sub.total_time_sec,0) as total_time_taken_sec,
               (SELECT SUM(q2.mark) FROM assessment_questions aq2 JOIN questions q2 ON aq2.question_id=q2.id WHERE aq2.assessment_id=a.id) as max_marks
        FROM student_submissions sub
        JOIN users u ON sub.user_id=u.user_id
        JOIN assessments a ON sub.assessment_id=a.id
    """
    params = []
    if user_id:
        query += " WHERE u.user_id=%s"
        params.append(user_id)
    query += " ORDER BY a.start_at DESC, sub.total_score DESC"
    cur.execute(query, params)
    rows = cur.fetchall()
    cur.close(); conn.close()
    return jsonify(rows)

@app.route("/admin/attempt_details/<int:uid>/<int:aid>", methods=["GET"])
@admin_required
def admin_attempt_details(uid, aid):
    conn = get_admin_conn()
    cur = conn.cursor(pymysql.cursors.DictCursor)
    cur.execute("SELECT detailed_log FROM student_submissions WHERE user_id=%s AND assessment_id=%s", (uid, aid))
    sub = cur.fetchone()
    log = json.loads(sub["detailed_log"]) if sub else {}
    cur.execute("""
        SELECT q.id, q.question, q.type, q.answer as correct_answer, q.mark, q.negative_mark
        FROM assessment_questions aq
        JOIN questions q ON aq.question_id=q.id
        WHERE aq.assessment_id=%s
    """, (aid,))
    questions = cur.fetchall()
    cur.close(); conn.close()

    result = []
    for q in questions:
        qid = str(q["id"])
        q_log = log.get(qid, {})
        correct = q["correct_answer"]
        if isinstance(correct, str):
            correct = json.loads(correct)
        result.append({
            "question": q["question"],
            "type": q["type"],
            "mark": q["mark"],
            "negative_mark": q["negative_mark"],
            "correct_answer": correct,
            "student_response": q_log.get("resp", {}),
            "score": q_log.get("score", 0),
            "time_taken_sec": q_log.get("time", 0)
        })
    return jsonify(result)

@app.route("/admin/export_assessment/<int:aid>", methods=["GET"])
@admin_required
def export_assessment(aid):
    conn = get_admin_conn()
    cur = conn.cursor(pymysql.cursors.DictCursor)
    cur.execute("""
        SELECT u.user_id, u.name, sub.total_score, sub.total_time_sec, sub.submitted_at
        FROM student_submissions sub
        JOIN users u ON sub.user_id=u.user_id
        WHERE sub.assessment_id=%s
        ORDER BY sub.total_score DESC
    """, (aid,))
    rows = cur.fetchall()
    cur.close(); conn.close()
    for r in rows:
        if r["submitted_at"]:
            r["submitted_at"] = r["submitted_at"].isoformat()
    return jsonify(rows)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5002, debug=False)
