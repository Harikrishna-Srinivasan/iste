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
from flask import Blueprint, request, jsonify, render_template, make_response, session, redirect, current_app
from threading import Lock
from functools import wraps

student_bp = Blueprint('student', __name__)

IST = pytz.timezone("Asia/Kolkata")
ROMAN = {1: "I", 2: "II", 3: "III", 4: "IV", 5: "V", 6: "VI", 7: "VII", 8: "VIII", 9: "IX", 10: "X"}

student_pool = None
get_student_conn = None
ph = PasswordHasher()
JWT_SECRET = None
JWT_ALGO = "HS256"

_active_cache = {"data": None, "expiry": datetime.min}
_cache_lock = Lock()

failed_attempts = defaultdict(list)
rate_lock = Lock()

get_admin_conn = None

def init_student(app, env, admin_conn_fn):
    global student_pool, get_student_conn, JWT_SECRET, get_admin_conn

    app.config["SECRET_KEY"] = env["secret_key"]
    app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(hours=2)
    app.config["SERVER_NAME"] = None
    app.config["MAX_CONTENT_LENGTH"] = 16 * 1024 * 1024

    student_pool = PooledDB(
        creator=pymysql,
        maxconnections=50,
        maxcached=20,
        blocking=True,
        host=env["host"],
        port=int(env["port"]),
        user=env["student"],
        password=env["stud_pwd"],
        database=env["db"],
        autocommit=True,
        charset="utf8mb4"
    )

    def _get_student_conn():
        return student_pool.connection()
    get_student_conn = _get_student_conn

    JWT_SECRET = env["jwt_secret"]
    get_admin_conn = admin_conn_fn


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
        if token.startswith("Bearer "): token = token[7:]
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

@student_bp.route("/")
def serve_index():
    token = request.cookies.get("token")
    if token and verify_token(token):
        ui = get_my_info()
        if "error" not in ui:
            return render_template("dashboard.html", user=ui)
    return render_template("index.html")

@student_bp.route("/dashboard")
def serve_dashboard():
    token = request.cookies.get("token")
    if not token or not verify_token(token):
        return redirect("/")
    ui = get_my_info()
    if "error" in ui:
        return redirect("/")
    return render_template("dashboard.html", user=ui)

@student_bp.route("/test")
def serve_test():
    token = request.cookies.get("token")
    if not token or not verify_token(token):
        return redirect("/")
    return render_template("test.html")

@student_bp.route("/health")
def health():
    return jsonify({"status": "ok"})

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

@student_bp.route("/student/me", methods=["GET"])
def route_get_my_info():
    info = get_my_info()
    if "error" in info: return jsonify(info), 401
    return jsonify(info)

@student_bp.route("/student/register", methods=["POST"])
def student_register():
    body = request.json
    user_id = body.get("user_id")
    password = body.get("password")
    name = body.get("name", "").strip()
    year = body.get("year")
    degree = body.get("degree", "").strip()
    stream = body.get("stream", "").strip()

    if not user_id or not password or not name or not year or not degree:
        return jsonify({"error": "All required fields must be filled"}), 400

    if len(password) < 6:
        return jsonify({"error": "Password must be at least 6 characters"}), 400

    try:
        user_id = int(user_id)
        year = int(year)
    except (ValueError, TypeError):
        return jsonify({"error": "Invalid user_id or year"}), 400

    if year < 1 or year > 4:
        return jsonify({"error": "Year must be between 1 and 4"}), 400

    conn = get_admin_conn()
    cur = conn.cursor(pymysql.cursors.DictCursor)
    try:
        cur.execute("SELECT user_id FROM users WHERE user_id=%s", (user_id,))
        if cur.fetchone():
            return jsonify({"error": "Registration ID already exists"}), 409

        hashed = ph.hash(password)
        details = {"year": year, "degree": degree, "stream": stream}
        cur.execute(
            "INSERT INTO users (user_id, name, details, password) VALUES (%s, %s, %s, %s)",
            (user_id, name, json.dumps(details), hashed)
        )
        conn.commit()
        return jsonify({"status": "Registration successful"}), 201
    except Exception as e:
        current_app.logger.error(f"Registration failed: {str(e)}")
        return jsonify({"error": "Server error"}), 500
    finally:
        cur.close()
        conn.close()

@student_bp.route("/student/login", methods=["POST"])
def student_login():
    body = request.json
    user_id = body.get("user_id")
    password = body.get("password")
    captcha = body.get("captcha")

    if not user_id or not password:
        return jsonify({"error": "Missing credentials"}), 400

    identifier = f"student_{user_id}"
    blocked, wait = check_rate_limit(identifier)
    if blocked:
        return jsonify({"error": f"Too many attempts. Try again in {int(wait)} seconds."}), 429

    if not captcha or captcha != session.get('captcha_ans', ''):
        return jsonify({"error": "Invalid security code"}), 403

    conn = get_student_conn()
    cur = conn.cursor(pymysql.cursors.DictCursor)
    try:
        cur.execute("SELECT user_id, name, password FROM users WHERE user_id=%s", (user_id,))
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
        session.pop('captcha_ans', None)
        token = make_token(user["user_id"])
        session.permanent = True
        session["user_id"] = user["user_id"]
        resp = make_response(jsonify({"status": "Success"}))
        resp.set_cookie("token", token, httponly=True, secure=False, samesite="Lax", max_age=timedelta(hours=6))
        return resp
    finally:
        cur.close()
        conn.close()

@student_bp.route("/logout")
def logout():
    session.clear()
    resp = make_response(jsonify({"status": "Logged out"}))
    resp.delete_cookie("token")
    return resp

@student_bp.route("/student/register_device", methods=["POST"])
@token_required
def register_device():
    data = request.json
    fcm_token = data.get("fcm_token")
    if not fcm_token:
        return jsonify({"error": "Missing fcm_token"}), 400

    uid = request.user.get("user_id")
    conn = get_student_conn()
    cur = conn.cursor()
    try:
        cur.execute("INSERT INTO user_devices (user_id, fcm_token) VALUES (%s, %s) "
                     "ON DUPLICATE KEY UPDATE fcm_token=%s", (uid, fcm_token, fcm_token))
        conn.commit()
        return jsonify({"status": "registered"})
    finally:
        cur.close()
        conn.close()

@student_bp.route("/student/gen_captcha")
def gen_captcha():
    code = ''.join(random.choices(string.ascii_letters + "23456789" + "@#$&*", k=5))
    session['captcha_ans'] = code
    return jsonify({"captcha_val": code})

@student_bp.route("/student/active", methods=["GET"])
@token_required
def student_active():
    conn = get_student_conn()
    cur = conn.cursor(pymysql.cursors.DictCursor)
    try:
        now_str = datetime.now(IST).strftime("%Y-%m-%d %H:%M:%S")
        cur.execute("""
            SELECT id, title, type, seq_num, start_at, total_duration, reminders
            FROM assessments WHERE start_at > %s ORDER BY start_at ASC
        """, (now_str,))
        rows = cur.fetchall()
        for r in rows:
            if r["start_at"]:
                r["start_at"] = r["start_at"].isoformat()
        return jsonify(rows)
    finally:
        cur.close()
        conn.close()

@student_bp.route("/student/upcoming_reminders", methods=["GET"])
@token_required
def upcoming_reminders():
    uid = request.user.get("user_id")
    conn = get_student_conn()
    cur = conn.cursor(pymysql.cursors.DictCursor)
    try:
        now_str = datetime.now(IST).strftime("%Y-%m-%d %H:%M:%S")
        cur.execute("SELECT id, title, start_at, reminders FROM assessments WHERE start_at > %s", (now_str,))
        upcoming = cur.fetchall()

        cur.execute("SELECT assessment_id FROM student_submissions WHERE user_id=%s", (uid,))
        submitted = {row["assessment_id"] for row in cur.fetchall()}

        notifications = []
        for a in upcoming:
            if a["id"] in submitted:
                continue
            reminders = json.loads(a["reminders"]) if a.get("reminders") else []
            start_at = a["start_at"]
            if start_at.tzinfo is None:
                start_at = IST.localize(start_at)
            sec_diff = (start_at - datetime.now(IST)).total_seconds()

            if 0 < sec_diff <= 20:
                notifications.append({"title": f"Starting Soon: {a['title']}", "body": "The assessment is starting in just a few seconds! Tap here to join."})

            for r in reminders:
                r_sec = 0
                if "d" in r: r_sec = int(r[:-1]) * 86400
                elif "h" in r: r_sec = int(r[:-1]) * 3600
                elif "m" in r: r_sec = int(r[:-1]) * 60

                if 0 < (sec_diff - r_sec) <= 65:
                    notifications.append({"title": f"Reminder: {a['title']}", "body": f"Your assessment starts in {r}. Tap here to prepare."})

        return jsonify(notifications)
    finally:
        cur.close()
        conn.close()

@student_bp.route("/student/notification_sent", methods=["POST"])
@token_required
def mark_notification_sent():
    uid = request.user.get("user_id")
    data = request.json
    aid = data.get("assessment_id")
    title = data.get("title")
    if not aid or not title:
        return jsonify({"error": "Missing data"}), 400

    conn = get_student_conn()
    cur = conn.cursor()
    try:
        cur.execute("INSERT IGNORE INTO sent_notifications (user_id, assessment_id, reminder_str, sent_at) VALUES (%s, %s, %s, NOW())",
                     (uid, aid, title))
        conn.commit()
        return jsonify({"status": "marked"})
    finally:
        cur.close()
        conn.close()

@student_bp.route("/get_pending_notifications", methods=["GET"])
def get_pending_notifications():
    if "user_id" not in session:
        return jsonify([])

    uid = session["user_id"]
    conn = get_student_conn()
    cur = conn.cursor(pymysql.cursors.DictCursor)
    try:
        cur.execute("SELECT assessment_id, reminder_str FROM sent_notifications WHERE user_id=%s", (uid,))
        sent = {(row["assessment_id"], row["reminder_str"]) for row in cur.fetchall()}

        now_str = datetime.now(IST).strftime("%Y-%m-%d %H:%M:%S")
        cur.execute("SELECT id, title, start_at, reminders FROM assessments WHERE start_at > %s", (now_str,))
        upcoming = cur.fetchall()

        cur.execute("SELECT assessment_id FROM student_submissions WHERE user_id=%s", (uid,))
        submitted = {row["assessment_id"] for row in cur.fetchall()}

        notifications = []
        for a in upcoming:
            if a["id"] in submitted:
                continue
            reminders = json.loads(a["reminders"]) if a.get("reminders") else []
            start_at = a["start_at"]
            if start_at.tzinfo is None:
                start_at = IST.localize(start_at)
            sec_diff = (start_at - datetime.now(IST)).total_seconds()

            if 0 < sec_diff <= 20:
                key = (a["id"], f"Starting Soon: {a['title']}")
                if key not in sent:
                    notifications.append({"title": f"Starting Soon: {a['title']}", "body": "The assessment is starting in just a few seconds! Tap here to join.", "assessment_id": a["id"]})

            for r in reminders:
                r_sec = 0
                if "d" in r: r_sec = int(r[:-1]) * 86400
                elif "h" in r: r_sec = int(r[:-1]) * 3600
                elif "m" in r: r_sec = int(r[:-1]) * 60

                if 0 < (sec_diff - r_sec) <= 65:
                    reminder_title = f"Reminder: {a['title']}"
                    key = (a["id"], reminder_title)
                    if key not in sent:
                        notifications.append({"title": reminder_title, "body": f"Your assessment starts in {r}. Tap here to prepare.", "assessment_id": a["id"]})

        return jsonify(notifications)
    finally:
        cur.close()
        conn.close()

@student_bp.route("/ack_notification", methods=["POST"])
def ack_notification():
    if "user_id" not in session:
        return jsonify({"error": "Unauthorized"}), 401

    uid = session["user_id"]
    data = request.json
    aid = data.get("assessment_id")
    title = data.get("title")
    if not aid or not title:
        return jsonify({"error": "Missing data"}), 400

    conn = get_student_conn()
    cur = conn.cursor()
    try:
        cur.execute("INSERT IGNORE INTO sent_notifications (user_id, assessment_id, reminder_str, sent_at) VALUES (%s, %s, %s, NOW())",
                     (uid, aid, title))
        conn.commit()
        return jsonify({"status": "acknowledged"})
    finally:
        cur.close()
        conn.close()

@student_bp.route("/student/questions/<int:aid>", methods=["GET"])
@token_required
def get_questions(aid):
    uid = request.user.get("user_id")
    conn = get_student_conn()
    cur = conn.cursor(pymysql.cursors.DictCursor)
    try:
        cur.execute("SELECT start_at, total_duration, title FROM assessments WHERE id=%s", (aid,))
        assessment = cur.fetchone()
        if not assessment:
            return jsonify({"error": "Assessment not found"}), 404

        start_at = assessment["start_at"]
        if start_at.tzinfo is None:
            start_at = IST.localize(start_at)
        now = datetime.now(IST)
        if now < start_at:
            return jsonify({"error": "Assessment not started"}), 403

        end_at = start_at + timedelta(minutes=assessment["total_duration"])
        if now > end_at:
            return jsonify({"error": "Assessment ended"}), 403

        cur.execute("SELECT q.id, q.question, q.type, q.answer, q.mark, q.negative_mark "
                     "FROM assessment_questions aq "
                     "JOIN questions q ON aq.question_id=q.id "
                     "WHERE aq.assessment_id=%s", (aid,))
        questions = cur.fetchall()

        cur.execute("SELECT detailed_log FROM student_submissions WHERE user_id=%s AND assessment_id=%s", (uid, aid))
        sub = cur.fetchone()
        log = json.loads(sub["detailed_log"]) if sub and sub.get("detailed_log") else {}

        for q in questions:
            qid = str(q["id"])
            if qid in log:
                q["student_response"] = log[qid].get("resp", {})
            else:
                q["student_response"] = {}
            if isinstance(q["answer"], str):
                try: q["answer"] = json.loads(q["answer"])
                except: pass

        return jsonify({
            "assessment_id": aid,
            "title": assessment["title"],
            "total_duration": assessment["total_duration"],
            "start_at": start_at.isoformat(),
            "end_at": end_at.isoformat(),
            "questions": questions
        })
    finally:
        cur.close()
        conn.close()

@student_bp.route("/student/submit", methods=["POST"])
@token_required
def submit_assessment():
    if request.user.get("is_admin"):
        return jsonify({"error": "Admins cannot submit"}), 403

    uid = request.user.get("user_id")
    data = request.json
    aid = data.get("assessment_id")
    responses = data.get("responses", {})
    time_taken = data.get("time_taken_sec", 0)

    if not aid:
        return jsonify({"error": "Missing assessment_id"}), 400

    conn = get_student_conn()
    cur = conn.cursor(pymysql.cursors.DictCursor)
    try:
        cur.execute("SELECT id FROM student_submissions WHERE user_id=%s AND assessment_id=%s", (uid, aid))
        if cur.fetchone():
            return jsonify({"error": "Already submitted"}), 409

        cur.execute("SELECT q.id, q.answer, q.mark, q.negative_mark, q.type "
                     "FROM assessment_questions aq "
                     "JOIN questions q ON aq.question_id=q.id "
                     "WHERE aq.assessment_id=%s", (aid,))
        questions = cur.fetchall()

        total_score = 0
        detailed_log = {}

        for q in questions:
            qid = str(q["id"])
            correct = q["answer"]
            if isinstance(correct, str):
                try: correct = json.loads(correct)
                except: pass

            resp = responses.get(qid, {})
            score = 0

            if q["type"] == "MCQ":
                student_ans = resp.get("option_id") if isinstance(resp, dict) else resp
                correct_id = correct.get("correct_id") if isinstance(correct, dict) else None
                if student_ans is not None and correct_id is not None and int(student_ans) == int(correct_id):
                    score = q["mark"]
                else:
                    score = -q["negative_mark"]
            elif q["type"] == "MSQ":
                student_ids = set(resp.get("option_ids", [])) if isinstance(resp, dict) else set()
                correct_ids = set(correct.get("correct_ids", [])) if isinstance(correct, dict) else set()
                if student_ids and student_ids == correct_ids:
                    score = q["mark"]
                elif student_ids:
                    score = -q["negative_mark"]
            elif q["type"] == "INT":
                try:
                    if int(resp) == int(correct.get("value", -999999) if isinstance(correct, dict) else correct):
                        score = q["mark"]
                    else:
                        score = -q["negative_mark"]
                except: score = -q["negative_mark"]
            elif q["type"] == "NUM":
                try:
                    val = float(resp)
                    if isinstance(correct, dict):
                        if "range" in correct:
                            if correct["range"][0] <= val <= correct["range"][1]:
                                score = q["mark"]
                            else:
                                score = -q["negative_mark"]
                        else:
                            if val == float(correct.get("value", -999999)):
                                score = q["mark"]
                            else:
                                score = -q["negative_mark"]
                    else:
                        if val == float(correct):
                            score = q["mark"]
                        else:
                            score = -q["negative_mark"]
                except: score = -q["negative_mark"]

            total_score += score
            detailed_log[qid] = {"resp": resp, "score": score, "time": 0}

        cur.execute(
            "INSERT INTO student_submissions (user_id, assessment_id, total_score, total_time_sec, detailed_log, submitted_at) "
            "VALUES (%s, %s, %s, %s, %s, NOW())",
            (uid, aid, total_score, time_taken, json.dumps(detailed_log))
        )
        conn.commit()
        return jsonify({"status": "submitted", "total_score": total_score})
    except Exception as e:
        current_app.logger.error(f"Submit failed: {str(e)}")
        return jsonify({"error": "Server error"}), 500
    finally:
        cur.close()
        conn.close()

@student_bp.route("/student/attempts", methods=["GET"])
@token_required
def student_attempts():
    uid = request.user.get("user_id")
    conn = get_student_conn()
    cur = conn.cursor(pymysql.cursors.DictCursor)
    try:
        cur.execute("""
            SELECT a.id as assessment_id, a.title, a.type, a.seq_num,
                   IFNULL(sub.total_score,0) as total_score,
                   IFNULL(sub.total_time_sec,0) as total_time_sec,
                   sub.submitted_at, sub.detailed_log,
                   (SELECT COUNT(*) FROM assessment_questions aq WHERE aq.assessment_id=a.id) as total_questions,
                   (SELECT SUM(q.mark) FROM assessment_questions aq2 JOIN questions q ON aq2.question_id=q.id WHERE aq2.assessment_id=a.id) as max_marks
            FROM assessments a
            LEFT JOIN student_submissions sub ON sub.assessment_id=a.id AND sub.user_id=%s
            ORDER BY a.start_at DESC
        """, (uid,))
        rows = cur.fetchall()
        for r in rows:
            if r["submitted_at"]:
                r["submitted_at"] = r["submitted_at"].isoformat()
            if r.get("detailed_log"):
                log = json.loads(r["detailed_log"]) if isinstance(r["detailed_log"], str) else r["detailed_log"]
                r["attended"] = sum(1 for v in log.values() if v.get("resp"))
            else:
                r["attended"] = 0
            r.pop("detailed_log", None)
        return jsonify(rows)
    finally:
        cur.close()
        conn.close()

@student_bp.route("/student/attempt_details/<int:aid>", methods=["GET"])
@token_required
def student_attempt_details(aid):
    uid = request.user.get("user_id")
    conn = get_student_conn()
    cur = conn.cursor(pymysql.cursors.DictCursor)
    try:
        cur.execute("SELECT detailed_log FROM student_submissions WHERE user_id=%s AND assessment_id=%s", (uid, aid))
        sub = cur.fetchone()
        log = json.loads(sub["detailed_log"]) if sub and sub.get("detailed_log") else {}

        cur.execute("""
            SELECT q.id, q.question, q.type, q.answer as correct_answer, q.mark, q.negative_mark
            FROM assessment_questions aq
            JOIN questions q ON aq.question_id=q.id
            WHERE aq.assessment_id=%s
        """, (aid,))
        questions = cur.fetchall()

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
    finally:
        cur.close()
        conn.close()
