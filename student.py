import os
import json
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

# ---------- Load environment ----------
from dotenv import load_dotenv
load_dotenv()

app = Flask(__name__, template_folder=".")
CORS(app, supports_credentials=True)
app.config["SECRET_KEY"] = os.environ["secret_key"]
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(hours=2)

IST = pytz.timezone("Asia/Kolkata")
ROMAN = {1: "I", 2: "II", 3: "III", 4: "IV", 5: "V", 6: "VI", 7: "VII", 8: "VIII", 9: "IX", 10: "X"}

# ---------- Database pool (student credentials) ----------
student_pool = PooledDB(
    creator=pymysql,
    maxconnections=50,
    maxcached=20,
    blocking=True,
    host=os.environ.get("db_host", "localhost"),
    user=os.environ["student"],
    password=os.environ["stud_pwd"],
    database=os.environ.get("db_name", "iste"),
    autocommit=True,
    charset='utf8mb4'
)

def get_student_conn():
    return student_pool.connection()

ph = PasswordHasher()
JWT_SECRET = os.environ["jwt_secret"]
JWT_ALGO = "HS256"

failed_attempts = defaultdict(list)
rate_lock = Lock()

def check_rate_limit(identifier, max_attempts=5, base_block_sec=240):
    """Return (blocked, wait_seconds). Block time doubles every 4 additional failures."""
    with rate_lock:
        now = time.time()
        attempts = failed_attempts.get(identifier, [])

        attempts = [t for t in attempts if now - t < 86400]
        failed_attempts[identifier] = attempts

        count = len(attempts)

        if count == 0:
            return False, 0

        if count < max_attempts:
            return False, 0

        last_attempt = attempts[-1]

        extra_attempts = count - max_attempts
        block_multiplier = 2 ** (extra_attempts // 4)
        block_sec = base_block_sec * block_multiplier

        time_since_last = now - last_attempt

        if time_since_last < block_sec:
            wait = block_sec - time_since_last
            return True, wait
        else:
            cutoff_time = now - block_sec
            recent_attempts = [t for t in attempts if t > cutoff_time]

            if len(recent_attempts) == 0:
                failed_attempts[identifier] = attempts[:max_attempts]
            else:
                failed_attempts[identifier] = recent_attempts

            return False, 0

def record_failed_attempt(identifier):
    with rate_lock:
        failed_attempts[identifier].append(time.time())
        if len(failed_attempts[identifier]) > 100:
            failed_attempts[identifier] = failed_attempts[identifier][-100:]

def reset_failed_attempts(identifier):
    """Only call this on successful login"""
    with rate_lock:
        if identifier in failed_attempts:
            del failed_attempts[identifier]

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

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.cookies.get("token") or request.headers.get("Authorization")
        if not token:
            return jsonify({"error": "Missing token"}), 401
        payload = verify_token(token)
        if not payload:
            return jsonify({"error": "Invalid token"}), 401
        request.user = payload
        return f(*args, **kwargs)
    return decorated

# ---------- Page routes ----------
@app.route("/")
def serve_index():
    token = request.cookies.get("token")
    if token and verify_token(token):
        return render_template("dashboard.html", user=get_my_info())
    return render_template("index.html")

@app.route("/dashboard")
def serve_dashboard():
    token = request.cookies.get("token")
    if not token or not verify_token(token):
        return render_template("index.html")
    return render_template("dashboard.html", user=get_my_info())

@app.route("/test")
def serve_test():
    token = request.cookies.get("token")
    if not token or not verify_token(token):
        return render_template("index.html")
    return render_template("test.html", user=get_my_info())

# ---------- Student profile ----------
def get_my_info():
    try:
        token = request.cookies.get("token") or request.headers.get("Authorization")
        if not token:
            if session.get("user_id"):
                uid = session.get("user_id")
            else:
                return {"error": "No token"}
        else:
            payload = verify_token(token)
            if not payload:
                return {"error": "Invalid token"}
            uid = payload.get("user_id")

        conn = get_student_conn()
        cur = conn.cursor(pymysql.cursors.DictCursor)
        cur.execute("SELECT user_id, name, details FROM users WHERE user_id=%s", (uid,))
        user = cur.fetchone()
        cur.close()
        conn.close()

        if not user:
            return {"error": "User not found"}

        details = json.loads(user.get("details", "{}"))
        year = ROMAN.get(int(details.get("year", 1)), "I")
        degree = details.get("degree", "")
        stream = details.get("stream", "")
        course = f"{year} - {degree} ({stream})" if stream else f"{year} - {degree}"

        return {
            "name": str(user["name"]).title(),
            "reg_no": str(user["user_id"]),
            "course": course
        }
    except Exception as e:
        print("Profile error:", e)
        return {"error": "Unauthorized"}

@app.route("/student/me", methods=["GET"])
def route_get_my_info():
    info = get_my_info()
    if "error" in info:
        return jsonify(info), 401
    return jsonify(info)

@app.route("/student/login", methods=["POST"])
def student_login():
    body = request.json
    user_id = body.get("user_id")
    password = body.get("password")
    if not user_id or not password:
        return jsonify({"error": "Missing credentials"}), 400

    identifier = f"student_{user_id}"
    blocked, wait = check_rate_limit(identifier)

    if blocked:
        wait_minutes = (wait + 59) // 60
        return jsonify({
            "error": f"Too many attempts. Try again in {wait_minutes} minute{'s' if wait_minutes != 1 else ''}.",
            "blocked": True,
            "wait_seconds": wait
        }), 429

    conn = None
    cur = None

    try:
        conn = get_student_conn()
        cur = conn.cursor(pymysql.cursors.DictCursor)
        cur.execute("SELECT user_id, password FROM users WHERE user_id=%s", (user_id,))
        user = cur.fetchone()

        if not user:
            record_failed_attempt(identifier)
            return jsonify({"error": "Invalid credentials"}), 401

        try:
            ph.verify(user["password"], password)
        except VerifyMismatchError:
            record_failed_attempt(identifier)
            return jsonify({"error": "Invalid credentials"}), 401

        reset_failed_attempts(identifier)
        token = make_token(user["user_id"], is_admin=False)
        session.permanent = True
        session["user_id"] = user["user_id"]
        session["is_admin"] = False
        resp = make_response(jsonify({"status": "Success"}))
        resp.set_cookie("token", token, httponly=True, secure=False, samesite="Lax", max_age=timedelta(hours=6))
        return resp

    except Exception as e:
        print(f"Login error: {e}")
        return jsonify({"error": "Server error"}), 500

    finally:
        if cur:
            cur.close()
        if conn:
            conn.close()

@app.route("/logout")
def logout():
    session.clear()
    resp = make_response(jsonify({"status": "Logged out"}))
    resp.delete_cookie("token")
    return resp

@app.route("/student/upcoming_reminders", methods=["GET"])
@token_required
def upcoming_reminders():
    uid = request.user["user_id"]
    conn = get_student_conn()
    cur = conn.cursor(pymysql.cursors.DictCursor)
    now = datetime.now(IST)
    cur.execute("""
        SELECT a.id, a.title, a.type, a.seq_num, a.start_at, a.reminders
        FROM assessments a
        LEFT JOIN student_submissions sub ON a.id = sub.assessment_id AND sub.user_id = %s
        WHERE sub.assessment_id IS NULL AND a.start_until >= %s
    """, (uid, now.strftime("%Y-%m-%d %H:%M:%S")))
    assessments = cur.fetchall()
    cur.close()
    conn.close()

    reminders = []
    for a in assessments:
        if not a.get("start_at"):
            continue
        start = a["start_at"]
        title = f"{a['type']} {a['seq_num']}: {a['title']}" if a.get('seq_num') else a['title']
        rem_list = json.loads(a.get("reminders") or "[]")
        for rem_str in rem_list:
            delta = timedelta()
            for part in rem_str.split():
                if "d" in part: delta += timedelta(days=int(part[:-1]))
                elif "h" in part: delta += timedelta(hours=int(part[:-1]))
                elif "m" in part: delta += timedelta(minutes=int(part[:-1]))
            trigger_time = start - delta
            if trigger_time > now:
                reminders.append({
                    "id": f"{a['id']}_{rem_str}",
                    "title": title,
                    "body": f"Starts in {rem_str}",
                    "trigger_at": trigger_time.isoformat(),
                    "assessment_id": a["id"]
                })
    return jsonify(reminders)

@app.route("/student/active", methods=["GET"])
@token_required
def active_assessment():
    uid = request.user["user_id"]
    conn = get_student_conn()
    cur = conn.cursor(pymysql.cursors.DictCursor)
    now = datetime.now(IST).strftime("%Y-%m-%d %H:%M:%S")
    cur.execute("""
        SELECT a.id, a.type, a.seq_num, a.title, a.start_at, a.start_until, a.total_duration
        FROM assessments a
        LEFT JOIN student_submissions sub ON a.id = sub.assessment_id AND sub.user_id = %s
        WHERE a.start_until >= %s AND sub.assessment_id IS NULL
        ORDER BY a.start_at ASC
    """, (uid, now))
    rows = cur.fetchall()
    cur.close()
    conn.close()
    for r in rows:
        if r["start_at"]:
            r["start_at"] = r["start_at"].isoformat()
        if r["start_until"]:
            r["start_until"] = r["start_until"].isoformat()
    return jsonify(rows)

# ---------- Questions ----------
@app.route("/student/questions/<int:aid>", methods=["GET"])
@token_required
def get_questions(aid):
    uid = request.user["user_id"]
    conn = get_student_conn()
    cur = conn.cursor(pymysql.cursors.DictCursor)
    cur.execute("SELECT user_id FROM student_submissions WHERE user_id=%s AND assessment_id=%s", (uid, aid))
    if cur.fetchone():
        cur.close(); conn.close()
        return jsonify({"error": "Already submitted"}), 403

    cur.execute("""
        SELECT q.id, q.type, q.question, q.answer, q.mark, q.negative_mark
        FROM assessment_questions aq
        JOIN questions q ON aq.question_id = q.id
        WHERE aq.assessment_id = %s
    """, (aid,))
    rows = cur.fetchall()
    cur.close(); conn.close()

    if not rows:
        return jsonify({"error": "No questions found"}), 404

    formatted = []
    for r in rows:
        ans = r["answer"]
        if isinstance(ans, (bytes, bytearray)):
            ans = ans.decode("utf-8")
        if isinstance(ans, str):
            ans = json.loads(ans)
        q_dict = {
            "id": r["id"],
            "type": r["type"],
            "question": r["question"],
            "mark": float(r.get("mark", 1)),
            "negative_mark": float(r.get("negative_mark", 0))
        }
        if r["type"] in ("MCQ", "MSQ"):
            q_dict["options"] = ans.get("options", [])
        formatted.append(q_dict)
    return jsonify(formatted)

# ---------- Submit test ----------
@app.route("/student/submit", methods=["POST"])
@token_required
def submit_test():
    uid = request.user["user_id"]
    if request.user.get("is_admin"):
        return jsonify({"error": "Admins cannot submit"}), 403

    body = request.json
    aid = body.get("assessment_id")
    responses = body.get("responses", {})
    times = body.get("times", {})

    conn = get_student_conn()
    cur = conn.cursor(pymysql.cursors.DictCursor)
    cur.execute("SELECT user_id FROM student_submissions WHERE user_id=%s AND assessment_id=%s", (uid, aid))
    if cur.fetchone():
        cur.close(); conn.close()
        return jsonify({"error": "Already submitted"}), 403

    cur.execute("""
        SELECT q.id, q.type, q.mark, q.negative_mark, q.answer
        FROM assessment_questions aq
        JOIN questions q ON aq.question_id = q.id
        WHERE aq.assessment_id = %s
    """, (aid,))
    questions = cur.fetchall()

    total_score = 0.0
    total_time = 0
    detailed_log = {}

    for q in questions:
        qid = str(q["id"])
        correct = q["answer"]
        if isinstance(correct, str):
            correct = json.loads(correct)
        resp = responses.get(qid, {})
        time_taken = int(times.get(qid, 0))
        q_type = q["type"]

        score = 0.0
        is_answered = bool(resp)
        if is_answered:
            is_correct = False
            try:
                if q_type == "MCQ":
                    is_correct = (resp.get("selected_id") == correct.get("correct_id"))
                elif q_type == "MSQ":
                    s_ids = set(resp.get("selected_ids", []))
                    c_ids = set(correct.get("correct_ids", []))
                    is_correct = (s_ids == c_ids and len(s_ids) > 0)
                elif q_type == "INT":
                    is_correct = (int(resp.get("value", 0)) == int(correct.get("value", 0)))
                elif q_type == "NUM":
                    val = float(resp.get("value", 0))
                    if "range" in correct:
                        is_correct = correct["range"][0] <= val <= correct["range"][1]
                    else:
                        is_correct = abs(val - float(correct.get("value", 0))) <= float(correct.get("tolerance", 0.1))
            except:
                pass
            score = float(q["mark"]) if is_correct else -float(q["negative_mark"])

        total_score += score
        total_time += time_taken
        detailed_log[qid] = {"score": score, "time": time_taken, "resp": resp if is_answered else {}}

    now_str = datetime.now(IST).strftime("%Y-%m-%d %H:%M:%S")
    cur.execute("""
        INSERT INTO student_submissions
        (user_id, assessment_id, total_score, total_time_sec, detailed_log, submitted_at)
        VALUES (%s, %s, %s, %s, %s, %s)
    """, (uid, aid, total_score, total_time, json.dumps(detailed_log), now_str))
    conn.commit()
    cur.close(); conn.close()
    return jsonify({"status": "Success"})

# ---------- Attempt history ----------
@app.route("/student/attempts", methods=["GET"])
@token_required
def student_history():
    uid = request.user["user_id"]
    conn = get_student_conn()
    cur = conn.cursor(pymysql.cursors.DictCursor)
    now_str = datetime.now(IST).strftime("%Y-%m-%d %H:%M:%S")
    cur.execute("""
        SELECT a.title, a.type, a.seq_num, a.start_at, a.start_until, a.total_duration, a.id as assessment_id,
               IFNULL(sub.total_score, 0) as total_score,
               IFNULL(sub.total_time_sec, 0) as total_time_taken_sec,
               IF(sub.user_id IS NOT NULL, 1, 0) as is_attempted,
               (SELECT COUNT(*) FROM assessment_questions aq WHERE aq.assessment_id = a.id) as total_questions,
               (SELECT SUM(q2.mark) FROM assessment_questions aq2 JOIN questions q2 ON aq2.question_id = q2.id WHERE aq2.assessment_id = a.id) as max_marks
        FROM assessments a
        LEFT JOIN student_submissions sub ON a.id = sub.assessment_id AND sub.user_id = %s
        WHERE a.start_at <= %s OR sub.user_id IS NOT NULL
        ORDER BY a.start_at DESC
    """, (uid, now_str))
    rows = cur.fetchall()
    cur.close(); conn.close()

    now = datetime.now(IST)
    for r in rows:
        if r["start_until"]:
            deadline = r["start_until"] + timedelta(minutes=(r["total_duration"] or 60))
            r["results_available"] = now > IST.localize(deadline)
        else:
            r["results_available"] = True
        if r["start_at"]:
            r["start_at"] = r["start_at"].isoformat()
        if r["start_until"]:
            r["start_until"] = r["start_until"].isoformat()
    return jsonify(rows)

@app.route("/student/attempt_details/<int:aid>", methods=["GET"])
@token_required
def student_attempt_details(aid):
    uid = request.user["user_id"]
    conn = get_student_conn()
    cur = conn.cursor(pymysql.cursors.DictCursor)
    cur.execute("SELECT start_at, total_duration FROM assessments WHERE id=%s", (aid,))
    a = cur.fetchone()
    if not a:
        return jsonify({"error": "Not found"}), 404
    deadline = a["start_at"] + timedelta(minutes=(a["total_duration"] or 60))
    if datetime.now(IST) < IST.localize(deadline):
        return jsonify({"error": "Results pending"}), 403

    cur.execute("SELECT detailed_log FROM student_submissions WHERE user_id=%s AND assessment_id=%s", (uid, aid))
    sub = cur.fetchone()
    log_data = json.loads(sub["detailed_log"]) if sub else {}

    cur.execute("""
        SELECT q.id, q.question, q.type, q.answer as correct_answer, q.mark, q.negative_mark
        FROM assessment_questions aq
        JOIN questions q ON aq.question_id = q.id
        WHERE aq.assessment_id = %s
    """, (aid,))
    questions = cur.fetchall()
    cur.close(); conn.close()

    result = []
    for q in questions:
        qid = str(q["id"])
        q_log = log_data.get(qid, {})
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

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
