import json
import os
import time
import firebase_admin
import jwt
import pandas as pd
import pymysql
import pytz
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from functools import wraps
from threading import Thread, Lock
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from apscheduler.schedulers.background import BackgroundScheduler
from dbutils.pooled_db import PooledDB
from dotenv import load_dotenv
from firebase_admin import credentials, messaging
from flask import (
    Flask,
    jsonify,
    make_response,
    render_template,
    request,
    session
)
from flask_compress import Compress
from flask_cors import CORS
from flask_minify import Minify

load_dotenv()

cred = credentials.Certificate(os.environ["firebase_json"])
firebase_admin.initialize_app(cred)

app = Flask(__name__, template_folder=".")
Compress(app)
Minify(app=app, html=True, js=True, cssless=True)

CORS(app, supports_credentials=True)
app.config["SECRET_KEY"] = os.environ["admin_secret_key"]
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(hours=2)

IST = pytz.timezone("Asia/Kolkata")

# ---------- Database pool ----------
admin_pool = PooledDB(
    creator=pymysql,
    maxconnections=2,
    blocking=True,
    host=os.environ["host"],
    port=int(os.environ["port"]),
    user=os.environ["admin"],
    password=os.environ["password"],
    database=os.environ["db"],
    autocommit=True,
    charset="utf8mb4",
)

def get_admin_conn():
    return admin_pool.connection()

# ---------- Auth utilities ----------
ph = PasswordHasher()
JWT_SECRET = os.environ["admin_jwt_secret"]
JWT_ALGO = "HS256"

ADMIN_USER = os.environ["admin"]
ADMIN_PASSWORD_HASH = os.environ["admin_password"]

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
            if start_at.tzinfo is None: start_at = IST.localize(start_at)
            now = datetime.now(IST)
            sec_diff = (start_at - now).total_seconds()

            milestones = []
            if 0 < sec_diff <= 20:
                milestones.append({"title": f"Starting Soon: {u['title']}", "body": "The assessment is starting in just a few seconds! Tap here to join."})

            for r in reminders:
                r_sec = 0
                if "d" in r: r_sec = int(r[:-1]) * 86400
                elif "h" in r: r_sec = int(r[:-1]) * 3600
                elif "m" in r: r_sec = int(r[:-1]) * 60

                if 0 < (sec_diff - r_sec) <= 65:
                    milestones.append({"title": f"Reminder: {u['title']}", "body": f"Your assessment starts in {r}. Tap here to prepare."})

            for ms in milestones:
                cur.execute("SELECT id FROM push_queue WHERE assessment_id=%s AND title=%s", (u["id"], ms["title"]))
                if not cur.fetchone():
                    cur.execute("INSERT INTO push_queue (assessment_id, title, body) VALUES (%s, %s, %s)",
                                (u["id"], ms["title"], ms["body"]))

        cur.close()
        conn.close()

scheduler = BackgroundScheduler(timezone=IST)
scheduler.add_job(func=background_checker, trigger="interval", minutes=3)
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

    captcha = body.get("captcha")
    if not captcha or captcha != session.get('captcha_ans', ''):
        return jsonify({"error": "Invalid security code"}), 403

    try:
        ph.verify(ADMIN_PASSWORD_HASH, password)
    except VerifyMismatchError:
        record_failed_attempt(identifier)
        return jsonify({"error": "Invalid credentials"}), 401

    reset_failed_attempts(identifier)
    session.pop('captcha_ans', None)
    token = make_token("admin", is_admin=True)
    session.permanent = True
    session["user_id"] = "admin"
    session["is_admin"] = True
    resp = make_response(jsonify({"status": "Success"}))
    resp.set_cookie("token", token, httponly=True, secure=False, samesite="Lax", max_age=timedelta(hours=6))
    return resp

@app.route("/admin/gen_captcha")
def gen_captcha():
    import random, string
    code = ''.join(random.choices(string.ascii_letters + "23456789" + "@#$&*", k=5))
    session['captcha_ans'] = code
    return jsonify({"captcha_val": code})

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


def send_scheduled_push(aid, title, body, milestone):
    """Worker function with a strict 'Send Once' lock."""
    conn = get_admin_conn()
    cur = conn.cursor()
    try:
        cur.execute("SELECT id FROM sent_notifications WHERE assessment_id=%s AND reminder_str=%s", (aid, milestone))
        if cur.fetchone(): return

        cur.execute("INSERT INTO push_queue (assessment_id, title, body) VALUES (%s, %s, %s)", (aid, title, body))

        cur.execute("INSERT INTO sent_notifications (user_id, assessment_id, reminder_str, sent_at) VALUES (0, %s, %s, NOW())", (aid, milestone))

        conn.commit()
        trigger_push_processing()
    except Exception as e: print(f"Scheduled Push Error: {e}")
    finally:
        cur.close(); conn.close()

def schedule_assessment_alerts(aid, title, start_at, reminders_raw):
    """Calculates milestones and adds specific 'date' jobs to the scheduler."""
    if start_at.tzinfo is None: start_at = IST.localize(start_at)

    try:
        reminders = json.loads(reminders_raw) if isinstance(reminders_raw, str) else (reminders_raw or [])
    except: reminders = []
    trigger_30s = start_at - timedelta(seconds=30)
    if trigger_30s > datetime.now(IST):
        scheduler.add_job(
            func=send_scheduled_push,
            trigger='date',
            run_date=trigger_30s,
            args=[aid, f"Starting in 30s: {title}", "Assessment begins in 30 seconds! Get ready.", "START_30S"],
            id=f"start_{aid}",
            replace_existing=True
        )

    for r in reminders:
        r_sec = 0
        if "d" in r: r_sec = int(r[:-1]) * 86400
        elif "h" in r: r_sec = int(r[:-1]) * 3600
        elif "m" in r: r_sec = int(r[:-1]) * 60

        trigger_rem = start_at - timedelta(seconds=r_sec)
        if trigger_rem > datetime.now(IST):
            scheduler.add_job(
                func=send_scheduled_push,
                trigger='date',
                run_date=trigger_rem,
                args=[aid, f"Reminder: {title}", f"Assessment starts in {r}.", f"REM_{r}"],
                id=f"rem_{aid}_{r}",
                replace_existing=True
            )

def sync_all_future_alerts():
    """Runs on startup to ensure all future assessments have their jobs in the scheduler."""
    conn = get_admin_conn()
    cur = conn.cursor(pymysql.cursors.DictCursor)
    try:
        cur.execute("SELECT id, title, start_at, reminders FROM assessments WHERE start_at > NOW()")
        for a in cur.fetchall():
            schedule_assessment_alerts(a['id'], a['title'], a['start_at'], a['reminders'])
    except Exception as e: print(f"Sync Error: {e}")
    finally:
        cur.close(); conn.close()

scheduler = BackgroundScheduler()
scheduler.start()

sync_all_future_alerts()


def trigger_push_processing():
    """Immediately start processing the push queue in a separate thread to avoid blocking the request."""
    Thread(target=process_push_queue).start()

def process_push_queue():
    conn = get_admin_conn()
    cur = conn.cursor(pymysql.cursors.DictCursor)
    try:
        cur.execute("SELECT id, assessment_id, title, body FROM push_queue WHERE status = 'PENDING'")
        pending_pushes = cur.fetchall()
        if not pending_pushes: return

        cur.execute("SELECT fcm_token FROM user_devices WHERE fcm_token IS NOT NULL AND fcm_token NOT LIKE 'WEB_BROWSER_%'")
        tokens = [row['fcm_token'] for row in cur.fetchall()]
        if not tokens: return

        for push in pending_pushes:
            for i in range(0, len(tokens), 500):
                chunk = tokens[i:i+500]
                message = messaging.MulticastMessage(
                    notification=messaging.Notification(
                        title=push['title'],
                        body=push['body'],
                    ),
                    data={
                        "assessment_id": str(push['assessment_id']),
                        "click_action": "FLUTTER_NOTIFICATION_CLICK"
                    },
                    tokens=chunk,
                    android=messaging.AndroidConfig(
                        priority='high',
                        notification=messaging.AndroidNotification(
                            channel_id='assessment_channel',
                            priority='max',
                            default_vibrate_timings=True,
                            default_sound=True
                        )
                    ),
                    apns=messaging.APNSConfig(
                        payload=messaging.APNSPayload(
                            aps=messaging.Aps(sound='default', badge=1, content_available=True)
                        )
                    )
                )
                response = messaging.send_each_for_multicast(message)

        if pending_pushes:
            cur.executemany("UPDATE push_queue SET status = 'SENT' WHERE id = %s", [(p['id'],) for p in pending_pushes])
            conn.commit()
    except Exception as e: print(f"Push Processing Error: {e}")
    finally:
        cur.close(); conn.close()


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
        INSERT INTO assessments (seq_num, title, type, start_at, end_at, reminders)
        VALUES (%s, %s, %s, %s, %s, %s)
    """, (data.get("seq_num"), data["title"], data["type"], data["start_at"], data["end_at"], json.dumps(data.get("reminders", []))))
    aid = cur.lastrowid
    for qid in q_ids:
        cur.execute("INSERT INTO assessment_questions (assessment_id, question_id) VALUES (%s, %s)", (aid, qid))

    start_at_str = data["start_at"].replace('T', ' ')
    if len(start_at_str) == 16: start_at_str += ":00"
    start_at_dt = datetime.strptime(start_at_str, "%Y-%m-%d %H:%M:%S")
    schedule_assessment_alerts(aid, data["title"], start_at_dt, data.get("reminders", []))
    duration = min(int(data.get("duration", 60)), len(q_ids))
    cur.execute("UPDATE assessments SET total_duration=%s WHERE id=%s", (duration, aid))

    cur.execute("INSERT INTO push_queue (assessment_id, title, body) VALUES (%s, %s, %s)",
                (aid, f"New Assessment: {data['title']}", "A new assessment has been scheduled. Open the app to view details."))
    conn.commit()

    cur.close()
    conn.close()

    trigger_push_processing()

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
    app.run(host="0.0.0.0", port=5002, debug=False, threaded=True)
