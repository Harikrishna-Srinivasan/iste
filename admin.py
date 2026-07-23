import json
import os
import firebase_admin
import jwt
import pandas as pd
import pymysql
import pytz
from datetime import datetime, timedelta, timezone
from functools import wraps
from threading import Thread, Lock
from argon2 import PasswordHasher
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
    send_from_directory,
    session
)
from flask_compress import Compress
from flask_cors import CORS
from flask_minify import Minify
from waitress import serve

load_dotenv()

cred = credentials.Certificate(os.environ["firebase_json"])
firebase_admin.initialize_app(cred)

app = Flask(__name__, template_folder=".", static_folder=".", static_url_path="")
Compress(app)
Minify(app=app, html=True, js=True, cssless=True)

CORS(app, supports_credentials=True)
app.config["SECRET_KEY"] = os.environ["admin_secret_key"]
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(days=16)

IST = pytz.timezone("Asia/Kolkata")

# ---------- Database pool ----------
admin_pool = PooledDB(
    creator=pymysql,
    maxconnections=10,
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

def make_token(uid, is_admin=False):
    payload = {
        "user_id": uid,
        "is_admin": is_admin,
        "exp": datetime.now(timezone.utc) + timedelta(days=16)
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


def _now_str():
    return datetime.now(IST).strftime("%Y-%m-%d %H:%M:%S")


def _parse_dt(value):
    if not value:
        return None
    if isinstance(value, datetime):
        return value
    text = str(value).strip().replace("T", " ")
    if len(text) == 16:
        text += ":00"
    return datetime.strptime(text, "%Y-%m-%d %H:%M:%S")


def _format_dt(value):
    return value.isoformat() if value else None


def _assessment_started(row):
    start_at = row.get("start_at") if isinstance(row, dict) else None
    if not start_at:
        return False
    if isinstance(start_at, str):
        try:
            start_at = datetime.fromisoformat(start_at)
        except Exception:
            return False
    if start_at.tzinfo is None:
        start_at = IST.localize(start_at)
    return datetime.now(IST) >= start_at


def _parse_question_ids(raw_ids):
    if raw_ids is None:
        return []
    if isinstance(raw_ids, list):
        values = raw_ids
    else:
        values = str(raw_ids).replace(";", ",").replace("\n", ",").split(",")
    result = []
    seen = set()
    for value in values:
        try:
            qid = int(str(value).strip())
        except Exception:
            continue
        if qid > 0 and qid not in seen:
            seen.add(qid)
            result.append(qid)
    return result


def _fetch_question_ids(cur, aid):
    cur.execute("SELECT question_id FROM assessment_questions WHERE assessment_id=%s ORDER BY question_id ASC", (aid,))
    return [row["question_id"] for row in cur.fetchall()]


def _fetch_assessment_submission_rows(cur, aid):
    cur.execute("""
        SELECT
            sub.user_id,
            u.name,
            a.id AS assessment_id,
            a.title,
            a.type,
            a.series_no,
            IFNULL(sub.total_score, 0) AS total_score,
            IFNULL(sub.total_time_sec, 0) AS total_time_taken_sec,
            sub.submitted_at,
            sub.detailed_log,
            (SELECT COUNT(*) FROM assessment_questions aq WHERE aq.assessment_id = a.id) AS total_questions,
            (SELECT SUM(q2.mark) FROM assessment_questions aq2 JOIN questions q2 ON aq2.question_id = q2.id WHERE aq2.assessment_id = a.id) AS max_marks,
            CASE WHEN sub.submitted_at IS NOT NULL THEN 1 + (
                SELECT COUNT(DISTINCT sub2.total_score)
                FROM student_submissions sub2
                WHERE sub2.assessment_id = a.id
                  AND sub2.submitted_at IS NOT NULL
                  AND sub2.total_score > sub.total_score
            ) ELSE NULL END AS rank_pos
        FROM student_submissions sub
        JOIN users u ON sub.user_id=u.user_id
        JOIN assessments a ON sub.assessment_id=a.id
        WHERE sub.assessment_id=%s
        ORDER BY sub.submitted_at IS NOT NULL DESC, sub.total_score DESC, sub.total_time_sec ASC, sub.user_id ASC
    """, (aid,))
    rows = cur.fetchall()
    for row in rows:
        if row.get("submitted_at") is None:
            row["attended"] = 0
            row["percentage"] = 0
            row["attempt_start_at"] = None
            row["submitted_at"] = None
            continue
        log = json.loads(row["detailed_log"]) if row.get("detailed_log") and isinstance(row["detailed_log"], str) else (row.get("detailed_log") or {})
        row["attended"] = sum(1 for v in log.values() if v.get("resp")) if log else 0
        row["percentage"] = round((float(row.get("total_score") or 0) / float(row.get("max_marks") or 1)) * 100, 2) if row.get("max_marks") else 0
        submitted_at_dt = row.get("submitted_at")
        row["attempt_start_at"] = None
        if submitted_at_dt and hasattr(submitted_at_dt, 'strftime'):
            row["submitted_at"] = _format_dt(submitted_at_dt)
            row["attempt_start_at"] = _format_dt(submitted_at_dt - timedelta(seconds=int(row.get("total_time_taken_sec") or 0)))
        else:
            row["submitted_at"] = _format_dt(submitted_at_dt)
            row.pop("detailed_log", None)
    return rows

# ---------- Question Import ----------
@app.route("/admin/upload_excel", methods=["POST"])
@admin_required
def upload_excel():
    if "file" not in request.files:
        return jsonify({"error": "No file"}), 400

    file = request.files["file"]
    try:
        if file.filename.lower().strip().endswith(".csv"):
            df = pd.read_csv(file, keep_default_na=False)
        else:
            df = pd.read_excel(file, keep_default_na=False)
    except Exception:
        app.logger.exception("Invalid file upload in /admin/upload_excel")
        return jsonify({"error": "Invalid file format or content"}), 400

    col_map = {str(c).strip().lower(): str(c) for c in df.columns}
    conn = get_admin_conn()
    cur = conn.cursor(pymysql.cursors.DictCursor)
    all_ids = []
    count = 0

    def get_int(col, default, min_val=None):
        c = col_map.get(col)
        if not c:
            return default
        val = row.get(c)
        if pd.isna(val) or str(val).strip() == "":
            return default
        try:
            parsed = int(float(val))
            return max(parsed, min_val) if min_val is not None else abs(parsed)
        except Exception:
            return default

    for _, row in df.iterrows():
        type_col = col_map.get("type")
        raw_type = row.get(type_col, "MCQ") if type_col else "MCQ"
        if pd.isna(raw_type) or str(raw_type).strip() == "":
            q_type = "MCQ"
        else:
            q_type = str(raw_type).strip().upper()

        if q_type not in ("MCQ", "MSQ", "INT", "NUM"):
            continue
        question_text = str(row.get(col_map.get("question", ""), "")).strip()
        if not question_text or question_text.lower() == "nan":
            continue

        mark = get_int("marks", 1, 1)
        neg_mark = get_int("negative_marks", 0, 0)
        correct_raw = str(row.get(col_map.get("correct", ""), "")).strip().lower()
        if not correct_raw or correct_raw == "nan":
            continue

        ans_dict = {}
        if q_type in ("MCQ", "MSQ"):
            options = []
            for c in df.columns:
                if len(str(c).strip()) == 1 and str(c).strip().isalpha():
                    val = row.get(c)
                    s = str(val).strip()
                    if s.lower() in ["nan", ""]:
                        continue
                    if isinstance(val, (int, float)) and val == int(val) and s.lower() != "none":
                        options.append(str(int(val)))
                    else:
                        options.append(s)

            if len(options) < 2:
                continue
            ans_dict["options"] = options

            if q_type == "MCQ":
                if correct_raw.isalpha() and len(correct_raw) == 1:
                    idx = ord(correct_raw) - 97
                else:
                    try:
                        idx = int(float(correct_raw))
                    except Exception:
                        continue
                if 0 <= idx < len(options):
                    ans_dict["correct_id"] = idx
                else:
                    continue
            else:
                ids = []
                for v in correct_raw.replace(",", " ").split():
                    v = v.strip()
                    if v.isalpha() and len(v) == 1:
                        idx = ord(v) - 97
                    else:
                        try:
                            idx = int(float(v))
                        except Exception:
                            continue
                    if 0 <= idx < len(options) and idx not in ids:
                        ids.append(idx)
                if not ids:
                    continue
                ans_dict["correct_ids"] = ids

        elif q_type == "INT":
            try:
                ans_dict["value"] = int(float(correct_raw))
            except Exception:
                continue
        elif q_type == "NUM":
            if "," in correct_raw:
                try:
                    parts = [float(x.strip()) for x in correct_raw.split(",")]
                    if len(parts) >= 2:
                        ans_dict["range"] = [parts[0], parts[1]]
                    else:
                        continue
                except Exception:
                    continue
            else:
                try:
                    ans_dict["value"] = float(correct_raw)
                except Exception:
                    continue

        q_norm = " ".join(question_text.lower().split())
        cur.execute("SELECT id, question, mark, negative_mark, answer FROM questions WHERE type=%s", (q_type,))
        existing = cur.fetchall()
        dup_id = None

        for eq in existing:
            if " ".join(eq["question"].lower().split()) != q_norm:
                continue
            if eq["mark"] != mark or eq["negative_mark"] != neg_mark:
                continue

            if q_type in ("MCQ", "MSQ"):
                try:
                    eq_ans = json.loads(eq["answer"]) if isinstance(eq["answer"], str) else eq["answer"]
                    eq_options = eq_ans.get("options", [])
                except Exception:
                    eq_options = []

                norm_opts = [str(o).strip().lower() for o in options]
                norm_eq_opts = [str(o).strip().lower() for o in eq_options]
                if norm_opts != norm_eq_opts:
                    continue

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
    cur.close()
    conn.close()
    return jsonify({"status": "success", "count": count, "ids": all_ids})


# ---------- Image Upload ----------
UPLOAD_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "uploads")
os.makedirs(UPLOAD_DIR, exist_ok=True)
ALLOWED_EXT = {".png", ".jpg", ".jpeg", ".gif", ".webp"}

@app.route("/admin/upload_image", methods=["POST"])
@admin_required
def upload_image():
    if "file" not in request.files:
        return jsonify({"error": "No file"}), 400
    f = request.files["file"]
    ext = os.path.splitext(f.filename)[1].lower()
    if ext not in ALLOWED_EXT:
        return jsonify({"error": "Unsupported image type"}), 400
    import uuid
    filename = f"{uuid.uuid4().hex}{ext}"
    f.save(os.path.join(UPLOAD_DIR, filename))
    return jsonify({"url": f"/uploads/{filename}"})


@app.route("/uploads/<path:filename>")
def serve_upload(filename):
    return send_from_directory(UPLOAD_DIR, filename)


# ---------- Question Create / Update ----------
@app.route("/admin/questions_by_ids", methods=["POST"])
@admin_required
def questions_by_ids():
    data = request.json
    ids = data.get("ids", [])
    if not ids:
        return jsonify([])
    conn = get_admin_conn()
    cur = conn.cursor(pymysql.cursors.DictCursor)
    placeholders = ','.join(['%s'] * len(ids))
    cur.execute(f"SELECT id, type, question, answer, mark, negative_mark, question_image, option_images FROM questions WHERE id IN ({placeholders})", ids)
    rows = cur.fetchall()
    cur.close(); conn.close()
    for q in rows:
        if isinstance(q.get("answer"), str):
            try: q["answer"] = json.loads(q["answer"])
            except: pass
        if q.get("option_images") and isinstance(q["option_images"], str):
            try: q["option_images"] = json.loads(q["option_images"])
            except: pass
    return jsonify(rows)


@app.route("/admin/create_question", methods=["POST"])
@admin_required
def create_question():
    data = request.json
    q_type = data.get("type", "MCQ")
    question_text = data.get("question", "").strip()
    question_image = data.get("question_image") or None
    if not question_text and not question_image:
        return jsonify({"error": "Question text or image required"}), 400

    mark = int(data.get("mark", 1) or 1)
    neg_mark = int(data.get("negative_mark", 0) or 0)
    option_images = data.get("option_images") or None

    ans_dict = {}
    if q_type == "MCQ":
        options = data.get("options", [])
        correct_id = data.get("correct_id", 0)
        if len(options) < 2:
            return jsonify({"error": "MCQ needs at least 2 options"}), 400
        ans_dict = {"options": options, "correct_id": int(correct_id)}
    elif q_type == "MSQ":
        options = data.get("options", [])
        correct_ids = data.get("correct_ids", [])
        if len(options) < 2:
            return jsonify({"error": "MSQ needs at least 2 options"}), 400
        ans_dict = {"options": options, "correct_ids": [int(i) for i in correct_ids]}
    elif q_type == "INT":
        value = data.get("value")
        if value is None:
            return jsonify({"error": "Integer answer required"}), 400
        ans_dict = {"value": int(value)}
    elif q_type == "NUM":
        value = data.get("value")
        tolerance = data.get("tolerance")
        rng = data.get("range")
        if rng and len(rng) == 2:
            ans_dict = {"range": [float(rng[0]), float(rng[1])]}
        elif value is not None:
            ans_dict = {"value": float(value)}
            if tolerance is not None:
                ans_dict["tolerance"] = float(tolerance)
        else:
            return jsonify({"error": "Numeric answer required"}), 400
    else:
        return jsonify({"error": "Invalid question type"}), 400

    conn = get_admin_conn()
    cur = conn.cursor(pymysql.cursors.DictCursor)
    try:
        cur.execute(
            "INSERT INTO questions (type, question, answer, mark, negative_mark, question_image, option_images) VALUES (%s, %s, %s, %s, %s, %s, %s)",
            (q_type, question_text, json.dumps(ans_dict), mark, neg_mark, question_image, json.dumps(option_images) if option_images else None)
        )
        conn.commit()
        qid = cur.lastrowid
    finally:
        cur.close()
        conn.close()
    return jsonify({"status": "success", "id": qid})


@app.route("/admin/update_question/<int:qid>", methods=["PUT"])
@admin_required
def update_question(qid):
    data = request.json
    conn = get_admin_conn()
    cur = conn.cursor(pymysql.cursors.DictCursor)
    try:
        cur.execute("SELECT id FROM questions WHERE id=%s", (qid,))
        if not cur.fetchone():
            return jsonify({"error": "Question not found"}), 404

        fields = []
        vals = []
        if "question" in data:
            fields.append("question=%s"); vals.append(data["question"])
        if "mark" in data:
            fields.append("mark=%s"); vals.append(int(data["mark"]))
        if "negative_mark" in data:
            fields.append("negative_mark=%s"); vals.append(int(data["negative_mark"]))
        if "question_image" in data:
            fields.append("question_image=%s"); vals.append(data["question_image"] or None)
        if "option_images" in data:
            fields.append("option_images=%s"); vals.append(json.dumps(data["option_images"]) if data["option_images"] else None)
        if "answer" in data:
            fields.append("answer=%s"); vals.append(json.dumps(data["answer"]))

        if not fields:
            return jsonify({"error": "No fields to update"}), 400

        vals.append(qid)
        cur.execute(f"UPDATE questions SET {', '.join(fields)} WHERE id=%s", vals)
        conn.commit()
    finally:
        cur.close()
        conn.close()
    return jsonify({"status": "updated"})
@app.route("/")
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

    if user != ADMIN_USER:
        return jsonify({"error": "Invalid credentials"}), 401

    try:
        ph.verify(ADMIN_PASSWORD_HASH, password)
    except Exception:
        return jsonify({"error": "Invalid credentials"}), 401

    token = make_token("admin", is_admin=True)
    session.permanent = True
    session["user_id"] = "admin"
    session["is_admin"] = True
    resp = make_response(jsonify({"status": "Success"}))
    resp.set_cookie("token", token, httponly=True, secure=False, samesite="Lax", max_age=timedelta(days=16))
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

def send_scheduled_push(aid, title, body, milestone):
    """Worker function with a strict 'Send Once' lock."""
    conn = get_admin_conn()
    cur = conn.cursor()
    try:
        cur.execute("SELECT id FROM sent_notifications WHERE assessment_id=%s AND reminder_str=%s", (aid, milestone))
        if cur.fetchone(): return

        cur.execute("INSERT INTO push_queue (assessment_id, title, body) VALUES (%s, %s, %s)", (aid, title, body))

        try:
            cur.execute("INSERT INTO sent_notifications (user_id, assessment_id, reminder_str, sent_at) VALUES (0, %s, %s, NOW())", (aid, milestone))
        except Exception:
            conn.rollback()
            cur.execute("SELECT id FROM sent_notifications WHERE assessment_id=%s AND reminder_str=%s", (aid, milestone))
            if cur.fetchone(): return

        conn.commit()
        trigger_push_processing()
    except Exception as e:
        app.logger.error(f"Scheduled Push Error for assessment {aid}, milestone {milestone}: {e}")
    finally:
        cur.close(); conn.close()

def schedule_assessment_alerts(aid, title, start_at, reminders_raw, end_at=None):
    """Calculates milestones and adds specific 'date' jobs to the scheduler."""
    if start_at.tzinfo is None: start_at = IST.localize(start_at)
    if end_at is None: start_at + timedelta(minutes=15)
    if end_at and end_at.tzinfo is None: end_at = IST.localize(end_at)

    try:
        reminders = json.loads(reminders_raw) if isinstance(reminders_raw, str) else (reminders_raw or [])
    except: reminders = []

    trigger_15s = start_at - timedelta(seconds=15)
    if trigger_15s > datetime.now(IST):
        scheduler.add_job(
            func=send_scheduled_push,
            trigger='date',
            run_date=trigger_15s,
            args=[aid, f"Starting in 15s: {title}", "Assessment begins in 15 seconds! Get ready.", "START_15S"],
            id=f"start_{aid}",
            replace_existing=True
        )

    if start_at > datetime.now(IST):
        scheduler.add_job(
            func=send_scheduled_push,
            trigger='date',
            run_date=start_at,
            args=[aid, f"Exam Live: {title}", "The assessment is now live! You can start attempting.", "START_LIVE"],
            id=f"start_live_{aid}",
            replace_existing=True
        )

    if end_at:
        trigger_close = end_at - timedelta(minutes=1)
        if trigger_close > datetime.now(IST):
            scheduler.add_job(
                func=send_scheduled_push,
                trigger='date',
                run_date=trigger_close,
                args=[aid, f"Closing Soon: {title}", "Assessment window closes in 1 minute! Submit now.", "END_1MIN"],
                id=f"end_1min_{aid}",
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

scheduler = BackgroundScheduler()
scheduler.start()

def sync_all_future_alerts():
    """Runs on startup to ensure all future assessments have their jobs in the scheduler."""
    conn = get_admin_conn()
    cur = conn.cursor(pymysql.cursors.DictCursor)
    try:
        cur.execute("SELECT id, title, start_at, end_at, reminders FROM assessments WHERE start_at > NOW()")
        for a in cur.fetchall():
            schedule_assessment_alerts(a['id'], a['title'], a['start_at'], a['reminders'], a.get('end_at'))
    except Exception as e: print("Sync Error")
    finally:
        cur.close(); conn.close()

sync_all_future_alerts()


_push_lock = Lock()

def trigger_push_processing():
    """Immediately start processing the push queue in a separate thread to avoid blocking the request."""
    if _push_lock.locked():
        return
    Thread(target=process_push_queue).start()

def process_push_queue():
    if not _push_lock.acquire(blocking=False):
        return
    try:
        conn = get_admin_conn()
        cur = conn.cursor(pymysql.cursors.DictCursor)

        cur.execute("SELECT id, assessment_id, title, body FROM push_queue WHERE status = 'PENDING' AND (scheduled_at IS NULL OR scheduled_at <= NOW())")
        pending_pushes = cur.fetchall()
        if not pending_pushes: return

        cur.execute("SELECT fcm_token FROM user_devices WHERE fcm_token IS NOT NULL")
        tokens = [row['fcm_token'] for row in cur.fetchall()]
        if not tokens: return

        invalid_tokens = []
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
                for idx, resp in enumerate(response.responses):
                    if not resp.success and resp.exception and hasattr(resp.exception, 'code') and resp.exception.code in ('messaging/registration-token-not-registered', 'messaging/invalid-registration-token'):
                        invalid_tokens.append(chunk[idx])

        if invalid_tokens:
            for t in invalid_tokens:
                cur.execute("DELETE FROM user_devices WHERE fcm_token = %s", (t,))
            conn.commit()

        if pending_pushes:
            cur.executemany("UPDATE push_queue SET status = 'SENT' WHERE id = %s", [(p['id'],) for p in pending_pushes])
            conn.commit()
    except Exception as e: print("Push Processing Error")
    finally:
        cur.close(); conn.close()
        _push_lock.release()


def _periodic_queue_processor():
    """Periodic job: process due push_queue items (scheduled messages + assessment alerts)."""
    try:
        process_push_queue()
    except Exception as e:
        print("Periodic push processor error")

scheduler.add_job(
    func=_periodic_queue_processor,
    trigger='interval',
    seconds=30,
    id='periodic_push_processor',
    replace_existing=True,
    max_instances=2
)


# ---------- Assessments ----------
@app.route("/admin/create_assessment", methods=["POST"])
@admin_required
def create_assessment():
    data = request.json
    q_ids = _parse_question_ids(data.get("question_ids"))
    if not q_ids:
        return jsonify({"error": "No questions selected"}), 400

    title = str(data.get("title", "")).strip()
    if not title:
        return jsonify({"error": "Title is required"}), 400

    start_at = _parse_dt(data.get("start_at"))
    if not start_at:
        return jsonify({"error": "Start time is required"}), 400

    end_at = _parse_dt(data.get("end_at"))
    if not end_at:
        end_at = start_at + timedelta(minutes=15)

    duration = max(int(data.get("duration", 30) or 30), 1)

    conn = get_admin_conn()
    cur = conn.cursor()
    cur.execute("""
        INSERT INTO assessments (series_no, title, type, start_at, end_at, reminders, total_duration)
        VALUES (%s, %s, %s, %s, %s, %s, %s)
    """, (data.get("series_no"), title, data.get("type", "WEEK"), start_at.strftime("%Y-%m-%d %H:%M:%S"), end_at.strftime("%Y-%m-%d %H:%M:%S"), json.dumps(data.get("reminders", [])), duration))
    aid = cur.lastrowid
    for qid in q_ids:
        cur.execute("INSERT INTO assessment_questions (assessment_id, question_id) VALUES (%s, %s)", (aid, qid))

    schedule_assessment_alerts(aid, title, start_at, data.get("reminders", []), end_at)

    cur.execute("INSERT INTO push_queue (assessment_id, title, body) VALUES (%s, %s, %s)",
                (aid, f"New Assessment: {title}", "A new assessment has been scheduled. Open the app to view details."))
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
    cur.execute("""
        SELECT a.id, a.title, a.type, a.series_no, a.start_at, a.end_at, a.total_duration,
               (SELECT COUNT(*) FROM assessment_questions aq WHERE aq.assessment_id = a.id) AS question_count,
               (SELECT COUNT(*) FROM student_submissions sub WHERE sub.assessment_id = a.id AND sub.submitted_at IS NOT NULL) AS submission_count,
               (SELECT COUNT(*) FROM student_submissions sub WHERE sub.assessment_id = a.id) AS entry_count,
               (SELECT ROUND(AVG(sub2.total_score), 2) FROM student_submissions sub2 WHERE sub2.assessment_id = a.id AND sub2.submitted_at IS NOT NULL) AS avg_score
        FROM assessments a
        ORDER BY a.start_at DESC
    """)
    rows = cur.fetchall()
    cur.close(); conn.close()
    for r in rows:
        r["is_started"] = _assessment_started(r)
        r["editable"] = not r["is_started"] and int(r.get("submission_count") or 0) == 0
        if r["start_at"]:
            r["start_at"] = r["start_at"].isoformat()
        if r.get("end_at"):
            r["end_at"] = r["end_at"].isoformat()
    return jsonify(rows)


@app.route("/admin/assessment/<int:aid>", methods=["GET"])
@admin_required
def admin_assessment_detail(aid):
    conn = get_admin_conn()
    cur = conn.cursor(pymysql.cursors.DictCursor)
    cur.execute("SELECT * FROM assessments WHERE id=%s", (aid,))
    row = cur.fetchone()
    if not row:
        cur.close(); conn.close()
        return jsonify({"error": "Assessment not found"}), 404

    question_ids = _fetch_question_ids(cur, aid)

    cur.execute("""
        SELECT q.id, q.type, q.question, q.answer, q.mark, q.negative_mark, q.question_image, q.option_images
        FROM assessment_questions aq
        JOIN questions q ON aq.question_id = q.id
        WHERE aq.assessment_id = %s
        ORDER BY aq.question_id ASC
    """, (aid,))
    questions = cur.fetchall()
    for q in questions:
        if isinstance(q.get("answer"), str):
            try:
                q["answer"] = json.loads(q["answer"])
            except Exception:
                pass
        if q.get("option_images") and isinstance(q["option_images"], str):
            try:
                q["option_images"] = json.loads(q["option_images"])
            except Exception:
                pass

    student_rows = _fetch_assessment_submission_rows(cur, aid)
    cur.close(); conn.close()

    result = dict(row)
    result["question_ids"] = question_ids
    result["questions"] = questions
    result["students"] = student_rows
    submitted_count = sum(1 for s in student_rows if s.get("submitted_at") is not None)
    result["editable"] = not _assessment_started(result) and submitted_count == 0
    result["start_at"] = _format_dt(result.get("start_at"))
    result["end_at"] = _format_dt(result.get("end_at"))
    end_dt = result.get("end_at")
    if end_dt and isinstance(end_dt, str):
        try:
            end_parsed = datetime.fromisoformat(end_dt)
            if end_parsed.tzinfo is None:
                end_parsed = IST.localize(end_parsed)
            result["results_available"] = datetime.now(IST) > end_parsed + timedelta(minutes=int(result.get("total_duration") or 0))
        except Exception:
            result["results_available"] = False
    else:
        result["results_available"] = False
    return jsonify(result)


@app.route("/admin/update_assessment/<int:aid>", methods=["PUT"])
@admin_required
def update_assessment(aid):
    data = request.json or {}
    conn = get_admin_conn()
    cur = conn.cursor(pymysql.cursors.DictCursor)
    cur.execute("SELECT * FROM assessments WHERE id=%s", (aid,))
    existing = cur.fetchone()
    if not existing:
        cur.close(); conn.close()
        return jsonify({"error": "Assessment not found"}), 404
    if _assessment_started(existing):
        cur.close(); conn.close()
        return jsonify({"error": "Assessment has already started"}), 400

    title = str(data.get("title", existing["title"]) or "").strip()
    if not title:
        cur.close(); conn.close()
        return jsonify({"error": "Title is required"}), 400

    series_no = data.get("series_no", existing.get("series_no"))
    duration = int(data.get("total_duration", existing.get("total_duration") or 30) or 30)
    question_ids = _parse_question_ids(data.get("question_ids"))
    if not question_ids:
        question_ids = _fetch_question_ids(cur, aid)

    start_at = data.get("start_at")
    end_at = data.get("end_at")
    if start_at:
        try:
            dt = datetime.fromisoformat(start_at)
            if dt.tzinfo is None:
                dt = IST.localize(dt)
            start_at = dt.astimezone(IST).strftime("%Y-%m-%d %H:%M:%S")
        except Exception:
            start_at = None
    if end_at:
        try:
            dt = datetime.fromisoformat(end_at)
            if dt.tzinfo is None:
                dt = IST.localize(dt)
            end_at = dt.astimezone(IST).strftime("%Y-%m-%d %H:%M:%S")
        except Exception:
            end_at = None

    if start_at and end_at:
        cur.execute("UPDATE assessments SET title=%s, series_no=%s, total_duration=%s, start_at=%s, end_at=%s WHERE id=%s",
                     (title, series_no, duration, start_at, end_at, aid))
    elif start_at:
        cur.execute("UPDATE assessments SET title=%s, series_no=%s, total_duration=%s, start_at=%s WHERE id=%s",
                     (title, series_no, duration, start_at, aid))
    elif end_at:
        cur.execute("UPDATE assessments SET title=%s, series_no=%s, total_duration=%s, end_at=%s WHERE id=%s",
                     (title, series_no, duration, end_at, aid))
    else:
        cur.execute("UPDATE assessments SET title=%s, series_no=%s, total_duration=%s WHERE id=%s",
                     (title, series_no, duration, aid))
    cur.execute("DELETE FROM assessment_questions WHERE assessment_id=%s", (aid,))
    for qid in question_ids:
        cur.execute("INSERT INTO assessment_questions (assessment_id, question_id) VALUES (%s, %s)", (aid, qid))

    conn.commit()
    cur.close(); conn.close()

    if start_at or data.get("reminders") is not None or end_at:
        new_start = None
        if start_at:
            try:
                new_start = datetime.fromisoformat(start_at)
                if new_start.tzinfo is None:
                    new_start = IST.localize(new_start)
            except Exception:
                pass
        if not new_start:
            new_start = existing["start_at"]
            if hasattr(new_start, 'replace') and new_start.tzinfo is None:
                new_start = IST.localize(new_start)

        new_end = None
        if end_at:
            try:
                new_end = datetime.fromisoformat(end_at)
                if new_end.tzinfo is None:
                    new_end = IST.localize(new_end)
            except Exception:
                pass
        if not new_end:
            new_end = existing.get("end_at")
            if new_end and hasattr(new_end, 'replace') and new_end.tzinfo is None:
                new_end = IST.localize(new_end)

        new_reminders = data.get("reminders") if data.get("reminders") is not None else existing.get("reminders")
        schedule_assessment_alerts(aid, title, new_start, new_reminders, new_end)

    return jsonify({"status": "updated"})


@app.route("/admin/delete_assessment/<int:aid>", methods=["DELETE"])
@admin_required
def delete_assessment(aid):
    conn = get_admin_conn()
    cur = conn.cursor(pymysql.cursors.DictCursor)
    cur.execute("SELECT * FROM assessments WHERE id=%s", (aid,))
    existing = cur.fetchone()
    if not existing:
        cur.close(); conn.close()
        return jsonify({"error": "Assessment not found"}), 404
    if _assessment_started(existing):
        cur.close(); conn.close()
        return jsonify({"error": "Assessment has already started"}), 400

    cur.execute("DELETE FROM assessments WHERE id=%s", (aid,))
    conn.commit()
    cur.close(); conn.close()
    return jsonify({"status": "deleted"})

@app.route("/admin/update_assessment_questions/<int:aid>", methods=["PUT"])
@admin_required
def update_assessment_questions(aid):
    data = request.json or {}
    questions = data.get("questions", [])
    if not questions:
        return jsonify({"error": "No questions provided"}), 400

    conn = get_admin_conn()
    cur = conn.cursor(pymysql.cursors.DictCursor)
    cur.execute("SELECT * FROM assessments WHERE id=%s", (aid,))
    existing = cur.fetchone()
    if not existing:
        cur.close(); conn.close()
        return jsonify({"error": "Assessment not found"}), 404
    if _assessment_started(existing):
        cur.close(); conn.close()
        return jsonify({"error": "Assessment has already started"}), 400

    changed = False
    for q in questions:
        qid = q.get("id")
        if not qid:
            continue
        question_text = str(q.get("question", "")).strip()
        if not question_text:
            continue
        mark = float(q.get("mark", 1) or 1)
        neg_mark = float(q.get("negative_mark", 0) or 0)

        cur.execute("SELECT question, mark, negative_mark, answer FROM questions WHERE id=%s", (qid,))
        old = cur.fetchone()
        if not old:
            continue

        answer_json = old["answer"]
        if isinstance(answer_json, str):
            try:
                old_ans = json.loads(answer_json)
            except Exception:
                old_ans = {}
        else:
            old_ans = answer_json or {}

        new_ans = dict(old_ans)
        q_type = q.get("type", old.get("type", "MCQ"))
        raw_answer = q.get("answer")
        if raw_answer is not None:
            if q_type in ("MCQ", "MSQ"):
                if "correct_id" in raw_answer:
                    new_ans["correct_id"] = int(raw_answer["correct_id"])
                elif "correct_ids" in raw_answer:
                    new_ans["correct_ids"] = raw_answer["correct_ids"]
                if "options" in raw_answer:
                    new_ans["options"] = raw_answer["options"]
            elif q_type in ("INT", "NUM"):
                if "value" in raw_answer:
                    try:
                        new_ans["value"] = float(raw_answer["value"])
                    except Exception:
                        pass
                elif "range" in raw_answer and len(raw_answer["range"]) == 2:
                    try:
                        new_ans["range"] = [float(raw_answer["range"][0]), float(raw_answer["range"][1])]
                    except Exception:
                        pass

        same = (
            old["question"] == question_text
            and old["mark"] == mark
            and old["negative_mark"] == neg_mark
            and json.dumps(old_ans, sort_keys=True) == json.dumps(new_ans, sort_keys=True)
        )
        if same:
            continue

        cur.execute("""
            UPDATE questions SET question=%s, mark=%s, negative_mark=%s, answer=%s
            WHERE id=%s
        """, (question_text, mark, neg_mark, json.dumps(new_ans), qid))
        changed = True

    if not changed:
        cur.close(); conn.close()
        return jsonify({"status": "no_changes", "message": "No changes detected."})

    conn.commit()
    cur.close(); conn.close()
    return jsonify({"status": "updated", "message": "Questions updated successfully."})

# ---------- Results ----------
@app.route("/admin/attempts", methods=["GET"])
@admin_required
def admin_attempts():
    user_id = request.args.get("user_id")
    conn = get_admin_conn()
    cur = conn.cursor(pymysql.cursors.DictCursor)
    query = """
        SELECT u.user_id, u.name, a.id as assessment_id, a.title, a.type, a.series_no,
               a.start_at, a.end_at, a.total_duration,
               IFNULL(sub.total_score,0) as total_score, IFNULL(sub.total_time_sec,0) as total_time_taken_sec,
               sub.submitted_at, sub.detailed_log,
               (SELECT COUNT(*) FROM assessment_questions aq WHERE aq.assessment_id=a.id) as total_questions,
               (SELECT SUM(q2.mark) FROM assessment_questions aq2 JOIN questions q2 ON aq2.question_id=q2.id WHERE aq2.assessment_id=a.id) as max_marks,
               1 + (
                   SELECT COUNT(DISTINCT sub2.total_score)
                   FROM student_submissions sub2
                   WHERE sub2.assessment_id = a.id
                     AND sub2.submitted_at IS NOT NULL
                     AND sub2.total_score > sub.total_score
                ) as rank_pos
        FROM student_submissions sub
        JOIN users u ON sub.user_id=u.user_id
        JOIN assessments a ON sub.assessment_id=a.id
    """
    params = []
    if user_id:
        query += " WHERE u.user_id=%s AND sub.submitted_at IS NOT NULL"
        params.append(user_id)
    else:
        query += " WHERE sub.submitted_at IS NOT NULL"
    query += " ORDER BY a.start_at DESC, sub.total_score DESC, sub.total_time_sec ASC, sub.user_id ASC"
    cur.execute(query, params)
    rows = cur.fetchall()
    for r in rows:
        if r.get("detailed_log"):
            log = json.loads(r["detailed_log"]) if isinstance(r["detailed_log"], str) else r["detailed_log"]
            r["attended"] = sum(1 for v in log.values() if v.get("resp"))
        else:
            r["attended"] = 0
        if r.get("submitted_at"):
            r["submitted_at"] = r["submitted_at"].isoformat()
        if r.get("start_at"):
            r["start_at"] = r["start_at"].isoformat()
        if r.get("end_at"):
            end_dt = r["end_at"]
            if hasattr(end_dt, 'isoformat'):
                r["end_at"] = end_dt.isoformat()
                dur = r.get("total_duration") or 0
                r["results_available"] = datetime.now(IST) > IST.localize(end_dt) + timedelta(minutes=dur) if isinstance(end_dt, datetime) else False
            else:
                r["results_available"] = False
        else:
            r["results_available"] = False
        r["percentage"] = round((float(r.get("total_score") or 0) / float(r.get("max_marks") or 1)) * 100, 2) if r.get("max_marks") else 0
        r.pop("detailed_log", None)
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
        SELECT q.id, q.question, q.type, q.answer as correct_answer, q.mark, q.negative_mark, q.question_image, q.option_images
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
        entry = {
            "question": q["question"],
            "type": q["type"],
            "mark": q["mark"],
            "negative_mark": q["negative_mark"],
            "correct_answer": correct,
            "student_response": q_log.get("resp", {}),
            "score": q_log.get("score", 0),
            "time_taken_sec": q_log.get("time", 0)
        }
        if q.get("question_image"):
            entry["question_image"] = q["question_image"]
        if q.get("option_images"):
            opt_imgs = q["option_images"]
            if isinstance(opt_imgs, str):
                opt_imgs = json.loads(opt_imgs)
            entry["option_images"] = opt_imgs
        result.append(entry)
    return jsonify(result)

@app.route("/admin/send_message", methods=["POST"])
@admin_required
def send_message():
    data = request.json
    title = data.get("title", "").strip()
    body = data.get("body", "").strip()
    schedule_at = data.get("schedule_at")

    if not title or not body:
        return jsonify({"error": "Title and body are required"}), 400

    conn = get_admin_conn()
    cur = conn.cursor()
    try:
        if schedule_at:
            cur.execute(
                "INSERT INTO push_queue (assessment_id, title, body, status, scheduled_at) VALUES (NULL, %s, %s, 'PENDING', %s)",
                (title, body, schedule_at)
            )
            cur.execute(
                "INSERT INTO student_messages (title, body, created_at) VALUES (%s, %s, %s)",
                (title, body, schedule_at)
            )
        else:
            cur.execute(
                "INSERT INTO push_queue (assessment_id, title, body, status) VALUES (NULL, %s, %s, 'PENDING')",
                (title, body)
            )
            cur.execute(
                "INSERT INTO student_messages (title, body) VALUES (%s, %s)",
                (title, body)
            )
        conn.commit()
        if not schedule_at:
            trigger_push_processing()
        return jsonify({"status": "Message queued successfully"})
    except Exception as e:
        app.logger.error("Send message failed")
        return jsonify({"error": "Server error"}), 500
    finally:
        cur.close()
        conn.close()

@app.route("/admin/students", methods=["GET"])
@admin_required
def admin_students():
    q = request.args.get("q", "").strip()
    conn = get_admin_conn()
    cur = conn.cursor(pymysql.cursors.DictCursor)
    try:
        if q:
            cur.execute("SELECT user_id, name, details FROM users WHERE user_id LIKE %s ORDER BY user_id ASC", (f"%{q}%",))
        else:
            cur.execute("SELECT user_id, name, details FROM users ORDER BY user_id ASC")
        rows = cur.fetchall()
        result = []
        for r in rows:
            details = json.loads(r.get("details", "{}")) if isinstance(r.get("details"), str) else (r.get("details") or {})
            result.append({
                "user_id": r["user_id"],
                "name": r["name"],
                "year": details.get("year"),
                "degree": details.get("degree"),
                "stream": details.get("stream", "")
            })
        return jsonify(result)
    finally:
        cur.close()
        conn.close()

@app.route("/admin/export_assessment/<int:aid>", methods=["GET"])
@admin_required
def export_assessment(aid):
    conn = get_admin_conn()
    cur = conn.cursor(pymysql.cursors.DictCursor)
    cur.execute("""
        SELECT u.user_id, u.name, a.title, a.type, a.series_no, a.start_at, a.end_at,
               sub.total_score, sub.total_time_sec, sub.submitted_at, sub.detailed_log,
               (SELECT COUNT(*) FROM assessment_questions aq WHERE aq.assessment_id=a.id) as total_questions,
               (SELECT SUM(q2.mark) FROM assessment_questions aq2 JOIN questions q2 ON aq2.question_id=q2.id WHERE aq2.assessment_id=a.id) as max_marks,
               1 + (
                   SELECT COUNT(DISTINCT sub2.total_score)
                   FROM student_submissions sub2
                   WHERE sub2.assessment_id = a.id
                     AND sub2.submitted_at IS NOT NULL
                     AND sub2.total_score > sub.total_score
                ) as rank_pos
        FROM student_submissions sub
        JOIN users u ON sub.user_id=u.user_id
        JOIN assessments a ON sub.assessment_id=a.id
        WHERE sub.assessment_id=%s AND sub.submitted_at IS NOT NULL
        ORDER BY sub.total_score DESC, sub.total_time_sec ASC, sub.user_id ASC
    """, (aid,))
    rows = cur.fetchall()
    cur.close(); conn.close()
    result = []
    for r in rows:
        attended = 0
        if r.get("detailed_log"):
            log = json.loads(r["detailed_log"]) if isinstance(r["detailed_log"], str) else r["detailed_log"]
            attended = sum(1 for v in log.values() if v.get("resp"))
        submitted_at = r.get("submitted_at")
        submitted_at_iso = submitted_at.isoformat() if submitted_at else None
        attempt_end_at = submitted_at_iso
        attempt_start_at = None
        if submitted_at:
            attempt_start_at = (submitted_at - timedelta(seconds=int(r.get("total_time_sec") or 0))).isoformat()
        result.append({
            "user_id": r["user_id"],
            "name": r["name"],
            "title": r.get("title"),
            "type": r.get("type"),
            "series_no": r.get("series_no"),
            "total_score": r["total_score"],
            "total_time_sec": r["total_time_sec"],
            "submitted_at": submitted_at_iso,
            "attempt_start_at": attempt_start_at,
            "attempt_end_at": attempt_end_at,
            "attended": attended,
            "total_questions": r.get("total_questions") or 0,
            "max_marks": r.get("max_marks") or 0,
            "rank": r.get("rank_pos") or 0,
            "percentage": round((float(r.get("total_score") or 0) / float(r.get("max_marks") or 1)) * 100, 2) if r.get("max_marks") else 0
        })
    return jsonify(result)

if __name__ == "__main__":
    serve(app, host="0.0.0.0", threads=8, port=5002)
