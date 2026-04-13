import base64
import io
import json
import jwt
import os
import pymysql
import pytz
import random
import string
import time

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from dbutils.pooled_db import PooledDB
from dotenv import load_dotenv
from flask import Flask, request, jsonify, render_template, make_response, session, redirect
from flask_cors import CORS
from threading import Lock
from flask_minify import Minify
from flask_compress import Compress
from functools import wraps
from waitress import serve

load_dotenv()

app = Flask(__name__, template_folder=".")
Compress(app)
Minify(app=app, html=True, js=True, cssless=True)


CORS(app,
     origins=["https://iste-ws2k.onrender.com"],
     supports_credentials=True,
     allow_headers=["Content-Type", "Authorization"],
     methods=["GET", "POST", "PUT", "DELETE"])

app.config["SECRET_KEY"] = os.environ["secret_key"]
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(hours=2)
app.config['SERVER_NAME'] = None
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024

IST = pytz.timezone("Asia/Kolkata")
ROMAN = {1: "I", 2: "II", 3: "III", 4: "IV", 5: "V", 6: "VI", 7: "VII", 8: "VIII", 9: "IX", 10: "X"}

_active_cache = {"data": None, "expiry": datetime.min}
_cache_lock = Lock()

student_pool = PooledDB(
    creator=pymysql,
    maxconnections=50,
    maxcached=20,
    blocking=True,
    host=os.environ["host"],
    port=int(os.environ["port"]),
    user=os.environ["student"],
    password=os.environ["stud_pwd"],
    database=os.environ["db"],
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
    with rate_lock:
        now = time.time()
        attempts = failed_attempts.get(identifier, [])
        attempts = [t for t in attempts if now - t < 86400]
        failed_attempts[identifier] = attempts
        count = len(attempts)
        if count == 0: return False, 0
        if count < max_attempts: return False, 0
        last_attempt = attempts[-1]
        extra_attempts = count - max_attempts
        block_sec = base_block_sec * (2 ** (extra_attempts // 4))
        if now - last_attempt < block_sec:
            return True, block_sec - (now - last_attempt)
        else:
            cutoff = now - block_sec
            recents = [t for t in attempts if t > cutoff]
            if len(recents) == 0:
                failed_attempts[identifier] = attempts[:max_attempts]
            else:
                failed_attempts[identifier] = recents
            return False, 0

def record_failed_attempt(identifier):
    with rate_lock:
        failed_attempts[identifier].append(time.time())
        if len(failed_attempts[identifier]) > 100:
            failed_attempts[identifier] = failed_attempts[identifier][-100:]

def reset_failed_attempts(identifier):
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
        if not token: return None
        if token.startswith('Bearer '): token = token[7:]
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


@app.route("/")
def serve_index():
    token = request.cookies.get("token")
    if token and verify_token(token):
        ui = get_my_info()
        if "error" not in ui:
            return render_template("dashboard.html", user=ui)
    return render_template("index.html")

@app.route("/dashboard")
def serve_dashboard():
    token = request.cookies.get("token")
    if not token or not verify_token(token):
        return render_template("index.html")
    ui = get_my_info()
    if "error" in ui:
        return render_template("index.html")
    return render_template("dashboard.html", user=ui)

@app.route("/test")
def serve_test():
    token = request.cookies.get("token")
    if not token or not verify_token(token):
        return render_template("index.html")
    ui = get_my_info()
    if "error" in ui:
        return render_template("index.html")
    return render_template("test.html", user=ui)

def get_my_info():
    try:
        token = request.cookies.get("token") or request.headers.get("Authorization")
        if not token:
            uid = session.get("user_id")
            if not uid: return {"error": "No token"}
        else:
            payload = verify_token(token)
            if not payload: return {"error": "Invalid token"}
            uid = payload.get("user_id")

        conn = get_student_conn()
        cur = conn.cursor(pymysql.cursors.DictCursor)
        try:
            cur.execute("SELECT user_id, name, details FROM users WHERE user_id=%s", (uid,))
            user = cur.fetchone()
        finally:
            cur.close()
            conn.close()

        if not user:
            return {"error": "User not found"}

        details = json.loads(user.get("details", "{}"))
        year = ROMAN.get(int(details.get("year", 1)), "I")
        stream = details.get("stream", "")
        course = f"{year} - {details.get('degree', '')}" + (f" ({stream})" if stream else "")

        return {"name": str(user["name"]).title(), "reg_no": str(user["user_id"]), "course": course}
    except:
        return {"error": "Unauthorized"}

@app.route("/student/me", methods=["GET"])
def route_get_my_info():
    info = get_my_info()
    if "error" in info: return jsonify(info), 401
    return jsonify(info)

@app.route("/student/login", methods=["POST"])
def student_login():
    body = request.json
    user_id = body.get("user_id")
    password = body.get("password")
    if not user_id or not password: return jsonify({"error": "Missing credentials"}), 400

    identifier = f"student_{user_id}"
    blocked, wait = check_rate_limit(identifier)

    if blocked:
        w = (wait + 59) // 60
        return jsonify({"error": f"Too many attempts. Try again in {w} minute{'s' if w != 1 else ''}.","blocked": True,"wait_seconds": wait}), 429

    conn, cur = None, None
    try:
        conn = get_student_conn()
        cur = conn.cursor(pymysql.cursors.DictCursor)
        cur.execute("SELECT user_id, password FROM users WHERE user_id=%s", (user_id,))
        user = cur.fetchone()

        if not user:
            record_failed_attempt(identifier)
            return jsonify({"error": "Invalid credentials"}), 401

        captcha = body.get("captcha")
        if not captcha or captcha != session.get('captcha_ans', ''):
            return jsonify({"error": "Invalid security code"}), 403

        try:
            ph.verify(user["password"], password)
        except VerifyMismatchError:
            record_failed_attempt(identifier)
            return jsonify({"error": "Invalid credentials"}), 401

        reset_failed_attempts(identifier)
        session.pop('captcha_ans', None)
        token = make_token(user["user_id"], is_admin=False)
        session.permanent = True
        session["user_id"] = user["user_id"]
        session["is_admin"] = False

        fcm_token = body.get("fcm_token")
        if fcm_token:
            try:
                cur.execute(
                    "INSERT INTO user_devices (user_id, fcm_token) VALUES (%s, %s) ON DUPLICATE KEY UPDATE fcm_token = VALUES(fcm_token)",
                    (user["user_id"], fcm_token)
                )
                conn.commit()
            except Exception as e:
                app.logger.error(f"FCM registration failed: {str(e)}")

        resp = make_response(jsonify({"status": "Success"}))
        resp.set_cookie("token", token, httponly=True, secure=True, samesite="Lax", max_age=timedelta(hours=2))
        return resp
    except Exception as e:
        app.logger.error(f"Login failed: {str(e)}")
        return jsonify({"error": "Server error"}), 500
    finally:
        if cur: cur.close()
        if conn: conn.close()

@app.route("/logout")
def logout():
    session.clear()
    resp = make_response(jsonify({"status": "Logged out"}))
    resp.delete_cookie("token")
    return resp

@app.route("/student/register_device", methods=["POST"])
@token_required
def register_device():
    uid = request.user["user_id"]
    token = request.json.get("fcm_token")
    if not token: return jsonify({"error": "Missing token"}), 400
    conn = get_student_conn()
    cur = conn.cursor()
    try:
        cur.execute("INSERT INTO user_devices (user_id, fcm_token) VALUES (%s, %s) ON DUPLICATE KEY UPDATE user_id = VALUES(user_id)", (uid, token))
        conn.commit()
    finally:
        cur.close()
        conn.close()
    return jsonify({"status": "success"})

@app.route("/student/gen_captcha")
def gen_captcha():
    """Generates a secure captcha answer and stores it in the session."""
    code = ''.join(random.choices(string.ascii_letters + "23456789" + "@#$&*", k=5))
    session['captcha_ans'] = code
    return jsonify({"captcha_val": code})

@app.route("/student/captcha", methods=["POST"])
@token_required
def verify_captcha():
    """Verifies the captcha answer against the session."""
    user_ans = request.json.get("answer")
    if user_ans and user_ans == session.get("captcha_ans", ""):
        return jsonify({"status": "success"})
    return jsonify({"error": "Invalid captcha"}), 403

@app.route("/student/active", methods=["GET"])
@token_required
def get_active_assessments():
    uid = request.user["user_id"]
    """Returns cached assessment list to prevent DB spam from 600 devices."""
    global _active_cache
    now = datetime.now()

    rows = None
    with _cache_lock:
        if _active_cache["data"] and _active_cache["expiry"] > now:
            rows = _active_cache["data"]

    conn = get_student_conn()
    cur = conn.cursor(pymysql.cursors.DictCursor)
    try:
        if not rows:
            cur.execute("""
                SELECT id, title, type, seq_num, start_at, end_at, total_duration
                FROM assessments
                WHERE end_at >= NOW() ORDER BY start_at ASC
            """)
            rows = cur.fetchall()
            for r in rows:
                if r["start_at"]: r["start_at"] = r["start_at"].isoformat()
                if r["end_at"]: r["end_at"] = r["end_at"].isoformat()

            with _cache_lock:
                _active_cache = {"data": rows, "expiry": now + timedelta(minutes=3)}

        cur.execute("SELECT assessment_id FROM student_submissions WHERE user_id=%s", (uid,))
        submitted = {r["assessment_id"] for r in cur.fetchall()}

        result = []
        for r in rows:
            copy = r.copy()
            copy["is_attempted"] = r["id"] in submitted
            result.append(copy)

        return jsonify(result)
    finally:
        cur.close(); conn.close()

@app.route("/student/upcoming_reminders", methods=["GET"])
@token_required
def upcoming_reminders():
    uid = request.user["user_id"]
    conn = get_student_conn()
    cur = conn.cursor(pymysql.cursors.DictCursor)
    try:
        now = datetime.now(IST)
        cur.execute("""
            SELECT a.id, a.title, a.type, a.seq_num, a.start_at, a.reminders
            FROM assessments a
            LEFT JOIN student_submissions sub ON a.id = sub.assessment_id AND sub.user_id = %s
            WHERE sub.assessment_id IS NULL AND a.end_at >= %s
        """, (uid, now.strftime("%Y-%m-%d %H:%M:%S")))
        assessments = cur.fetchall()
        reminders = []
        for a in assessments:
            if not a.get("start_at"): continue
            start = a["start_at"]
            if start.tzinfo is None: start = IST.localize(start)
            title = f"{a['type']} {a['seq_num']}: {a['title']}" if a.get('seq_num') else a['title']
            for rem_str in json.loads(a.get("reminders") or "[]"):
                delta = timedelta()
                for part in rem_str.split():
                    if "d" in part: delta += timedelta(days=int(part[:-1]))
                    elif "h" in part: delta += timedelta(hours=int(part[:-1]))
                    elif "m" in part: delta += timedelta(minutes=int(part[:-1]))
                trigger_time = start - delta
                if trigger_time > now:
                    reminders.append({"id": f"{a['id']}_{rem_str}", "title": title, "body": f"Starts in {rem_str}", "trigger_at": trigger_time.isoformat(), "assessment_id": a["id"], "reminder_str": rem_str})
        return jsonify(reminders)
    finally:
        cur.close()
        conn.close()

@app.route("/student/notification_sent", methods=["POST"])
@token_required
def notification_sent():
    uid = request.user["user_id"]
    data = request.json
    conn = get_student_conn()
    cur = conn.cursor()
    try:
        cur.execute("INSERT INTO sent_notifications (user_id, assessment_id, reminder_str) VALUES (%s, %s, %s)", (uid, data.get("assessment_id"), data.get("reminder_str")))
        conn.commit()
        return jsonify({"status": "success"})
    finally:
        cur.close()
        conn.close()

@app.route("/get_pending_notifications", methods=["GET"])
@token_required
def get_pending_notifications():
    uid = request.user["user_id"]
    conn = get_student_conn()
    cur = conn.cursor(pymysql.cursors.DictCursor)
    try:
        cur.execute("SELECT id, title, start_at, total_duration, reminders FROM assessments WHERE start_at > NOW() - INTERVAL 1 DAY")
        assessments = cur.fetchall()
        cur.execute("SELECT assessment_id, reminder_str FROM sent_notifications WHERE user_id = %s", (uid,))
        sent_data = {row['assessment_id']: row['reminder_str'] for row in cur.fetchall()}

        pending = []
        now = datetime.now(IST)
        for a in assessments:
            aid, start_at = a['id'], a['start_at']
            if start_at.tzinfo is None: start_at = IST.localize(start_at)
            reminders = json.loads(a.get('reminders') or "[]") if isinstance(a.get('reminders'), str) else (a.get('reminders') or [])
            latest_milestone = "CREATED"
            for r in reminders:
                r_sec = 0
                if "d" in r: r_sec = int(r[:-1]) * 86400
                elif "h" in r: r_sec = int(r[:-1]) * 3600
                elif "m" in r: r_sec = int(r[:-1]) * 60

                if now >= (start_at - timedelta(seconds=r_sec)):
                    latest_milestone = f"REMINDER_{r}"

            if now >= (start_at - timedelta(seconds=15)): latest_milestone = "STARTED"

            if sent_data.get(aid) != latest_milestone and (now < start_at + timedelta(minutes=a['total_duration'] or 60)):
                pending.append({"assessment_id": aid, "title": a['title'], "milestone": latest_milestone})
        return jsonify(pending)
    finally:
        cur.close()
        conn.close()

@app.route("/ack_notification", methods=["POST"])
@token_required
def ack_notification():
    uid = request.user["user_id"]
    data = request.json
    if not data.get("assessment_id") or not data.get("milestone"): return jsonify({"error": "Bad request"}), 400
    conn = get_student_conn()
    cur = conn.cursor()
    try:
        cur.execute("INSERT INTO sent_notifications (user_id, assessment_id, reminder_str, sent_at) VALUES (%s, %s, %s, NOW()) ON DUPLICATE KEY UPDATE reminder_str = VALUES(reminder_str), sent_at = NOW()", (uid, data.get("assessment_id"), data.get("milestone")))
        conn.commit()
        return jsonify({"success": True})
    finally:
        cur.close()
        conn.close()

@app.route("/student/questions/<int:aid>", methods=["GET"])
@token_required
def get_questions(aid):
    uid = request.user["user_id"]
    conn = get_student_conn()
    cur = conn.cursor(pymysql.cursors.DictCursor)
    try:
        cur.execute("SELECT user_id FROM student_submissions WHERE user_id=%s AND assessment_id=%s", (uid, aid))
        if cur.fetchone(): return jsonify({"error": "Already submitted"}), 403

        cur.execute("SELECT q.id, q.type, q.question, q.answer, q.mark, q.negative_mark FROM assessment_questions aq JOIN questions q ON aq.question_id = q.id WHERE aq.assessment_id = %s", (aid,))
        rows = cur.fetchall()
        if not rows: return jsonify({"error": "No questions found"}), 404

        formatted = []
        for r in rows:
            ans = json.loads(r["answer"]) if isinstance(r["answer"], str) else (r["answer"].decode("utf-8") if isinstance(r["answer"], bytes) else r["answer"])
            q_dict = {"id": r["id"], "type": r["type"], "question": r["question"], "mark": float(r.get("mark", 1)), "negative_mark": float(r.get("negative_mark", 0))}
            if r["type"] in ("MCQ", "MSQ"): q_dict["options"] = ans.get("options", [])
            formatted.append(q_dict)
        return jsonify(formatted)
    finally:
        cur.close()
        conn.close()

@app.route("/student/submit", methods=["POST"])
@token_required
def submit_test():
    uid = request.user["user_id"]
    if request.user.get("is_admin"): return jsonify({"error": "Admins cannot submit"}), 403
    body = request.json
    aid = body.get("assessment_id")
    conn = get_student_conn()
    cur = conn.cursor(pymysql.cursors.DictCursor)
    try:
        cur.execute("SELECT user_id FROM student_submissions WHERE user_id=%s AND assessment_id=%s", (uid, aid))
        if cur.fetchone(): return jsonify({"error": "Already submitted"}), 403

        cur.execute("SELECT q.id, q.type, q.mark, q.negative_mark, q.answer FROM assessment_questions aq JOIN questions q ON aq.question_id = q.id WHERE aq.assessment_id = %s", (aid,))
        questions = cur.fetchall()
        total_score, total_time, detailed_log = 0.0, 0, {}

        for q in questions:
            qid = str(q["id"])
            correct = json.loads(q["answer"]) if isinstance(q["answer"], str) else q["answer"]
            resp = body.get("responses", {}).get(qid, {})
            time_taken = int(body.get("times", {}).get(qid, 0))
            score = 0.0
            if resp:
                is_correct = False
                try:
                    if q["type"] == "MCQ": is_correct = (resp.get("selected_id") == correct.get("correct_id"))
                    elif q["type"] == "MSQ": is_correct = (set(resp.get("selected_ids", [])) == set(correct.get("correct_ids", [])) and len(resp.get("selected_ids", [])) > 0)
                    elif q["type"] == "INT": is_correct = (int(resp.get("value", 0)) == int(correct.get("value", 0)))
                    elif q["type"] == "NUM":
                        v = float(resp.get("value", 0))
                        is_correct = correct["range"][0] <= v <= correct["range"][1] if "range" in correct else abs(v - float(correct.get("value", 0))) <= float(correct.get("tolerance", 0.1))
                except: pass
                score = float(q["mark"]) if is_correct else -float(q["negative_mark"])
            total_score += score
            total_time += time_taken
            detailed_log[qid] = {"score": score, "time": time_taken, "resp": resp if resp else {}}

        cur.execute("INSERT INTO student_submissions (user_id, assessment_id, total_score, total_time_sec, detailed_log, submitted_at) VALUES (%s, %s, %s, %s, %s, %s)", (uid, aid, total_score, total_time, json.dumps(detailed_log), datetime.now(IST).strftime("%Y-%m-%d %H:%M:%S")))
        conn.commit()
        return jsonify({"status": "Success"})
    finally:
        cur.close()
        conn.close()

@app.route("/student/attempts", methods=["GET"])
@token_required
def student_history():
    uid = request.user["user_id"]
    conn = get_student_conn()
    cur = conn.cursor(pymysql.cursors.DictCursor)
    try:
        cur.execute("SELECT a.title, a.type, a.seq_num, a.start_at, a.end_at, a.total_duration, a.id as assessment_id, IFNULL(sub.total_score, 0) as total_score, IFNULL(sub.total_time_sec, 0) as total_time_taken_sec, IF(sub.user_id IS NOT NULL, 1, 0) as is_attempted, (SELECT COUNT(*) FROM assessment_questions aq WHERE aq.assessment_id = a.id) as total_questions, (SELECT SUM(q2.mark) FROM assessment_questions aq2 JOIN questions q2 ON aq2.question_id = q2.id WHERE aq2.assessment_id = a.id) as max_marks FROM assessments a LEFT JOIN student_submissions sub ON a.id = sub.assessment_id AND sub.user_id = %s WHERE a.start_at <= %s OR sub.user_id IS NOT NULL ORDER BY a.start_at DESC", (uid, datetime.now(IST).strftime("%Y-%m-%d %H:%M:%S")))
        rows, now = cur.fetchall(), datetime.now(IST)
        for r in rows:
            r["results_available"] = now > IST.localize(r["end_at"] + timedelta(minutes=(r["total_duration"] or 60))) if r["end_at"] else True
            if r["start_at"]: r["start_at"] = r["start_at"].isoformat()
            if r["end_at"]: r["end_at"] = r["end_at"].isoformat()
        return jsonify(rows)
    finally:
        cur.close()
        conn.close()

@app.route("/student/attempt_details/<int:aid>", methods=["GET"])
@token_required
def student_attempt_details(aid):
    uid = request.user["user_id"]
    conn = get_student_conn()
    cur = conn.cursor(pymysql.cursors.DictCursor)
    try:
        cur.execute("SELECT start_at, total_duration FROM assessments WHERE id=%s", (aid,))
        a = cur.fetchone()
        if not a: return jsonify({"error": "Not found"}), 404
        if datetime.now(IST) < IST.localize(a["start_at"] + timedelta(minutes=(a["total_duration"] or 60))): return jsonify({"error": "Results pending"}), 403

        cur.execute("SELECT detailed_log FROM student_submissions WHERE user_id=%s AND assessment_id=%s", (uid, aid))
        sub = cur.fetchone()
        log_data = json.loads(sub["detailed_log"]) if sub else {}

        cur.execute("SELECT q.id, q.question, q.type, q.answer as correct_answer, q.mark, q.negative_mark FROM assessment_questions aq JOIN questions q ON aq.question_id = q.id WHERE aq.assessment_id = %s", (aid,))
        result = []
        for q in cur.fetchall():
            qid = str(q["id"])
            q_log = log_data.get(qid, {})
            result.append({"question": q["question"], "type": q["type"], "mark": q["mark"], "negative_mark": q["negative_mark"], "correct_answer": json.loads(q["correct_answer"]) if isinstance(q["correct_answer"], str) else q["correct_answer"], "student_response": q_log.get("resp", {}), "score": q_log.get("score", 0), "time_taken_sec": q_log.get("time", 0)})
        return jsonify(result)
    finally:
        cur.close()
        conn.close()

if __name__ == "__main__":
    app.config.update(
        SESSION_COOKIE_SECURE=True,
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE='Lax'
    )
    serve(app, host="0.0.0.0", threads=64, port=5000)
