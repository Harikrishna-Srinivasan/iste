import os
import json
import pandas as pd
from datetime import datetime, timedelta
from flask import Flask, request, jsonify, send_from_directory, session, render_template
from flask_cors import CORS
from flask_session import Session
import pymysql
from dbutils.pooled_db import PooledDB
import jwt
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from apscheduler.schedulers.background import BackgroundScheduler
import pytz

app = Flask(__name__, template_folder='.')
CORS(app, supports_credentials=True) 
app.config['SECRET_KEY'] = 'SUPER_SECRET_KEY'
app.config['SESSION_TYPE'] = 'filesystem'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=2)
Session(app)

ph = PasswordHasher()
IST = pytz.timezone('Asia/Kolkata')

SECRET = "SUPER_SECRET"
ALGO = "HS256"
IST = pytz.timezone('Asia/Kolkata')

# ---------- DB ----------
# Initialize a highly concurrent pool (handles 500+ sustained, 10k peak via queuing)
pool = PooledDB(
    creator=pymysql,
    maxconnections=500,  # Max simultaneous connections
    mincached=20,        # Keep warm connections ready
    maxcached=100,
    blocking=True,       # Wait for an available connection if pool is full
    host="localhost",
    user="root",
    password="password",
    database="iste",
    autocommit=True
)

def get_conn():
    return pool.connection()

# ---------- BACKGROUND SCHEDULER ----------
def background_checker():
    # FR 4.1 & 4.2: Mobile App Alerts mechanism (simulate via terminal prints)
    with app.app_context():
        conn = get_conn()
        cur = conn.cursor(pymysql.cursors.DictCursor)
        now_str = datetime.now(IST).strftime("%Y-%m-%d %H:%M:%S")
        # Find assessments starting in the next 1 minute that haven't been alerted?
        # (For this stateless version, we print everything starting 'now')
        cur.execute("SELECT id, title, start_at, reminders FROM assessments WHERE start_at > %s", (now_str,))
        upcoming = cur.fetchall()
        for u in upcoming:
            reminders = json.loads(u['reminders']) if u.get('reminders') else []
            start_at = u['start_at']
            for rem_str in reminders:
                # Parse format like "1d 2h 30m"
                delta = timedelta()
                for part in rem_str.split():
                    if 'd' in part: delta += timedelta(days=int(part[:-1]))
                    elif 'h' in part: delta += timedelta(hours=int(part[:-1]))
                    elif 'm' in part: delta += timedelta(minutes=int(part[:-1]))
                
                rem_time = start_at - delta
                if IST.localize(rem_time) <= datetime.now(IST) <= IST.localize(rem_time + timedelta(minutes=1)):
                    print(f"!!! ALERT: Assessment '{u['title']}' starts in {rem_str} !!!")
        cur.close()
        conn.close()

scheduler = BackgroundScheduler(timezone=IST)
scheduler.add_job(func=background_checker, trigger="interval", minutes=1)
scheduler.start()

# ---------- AUTH ----------
def make_token(uid, is_admin=False):
    payload = {
        "sub": uid,
        "is_admin": is_admin,
        "exp": datetime.utcnow() + timedelta(hours=6)
    }
    return jwt.encode(payload, SECRET, algorithm=ALGO)

def verify_session(admin_only=False):
    uid = session.get("user_id")
    is_admin = session.get("is_admin", False)
    if not uid:
        raise Exception("Unauthorized")
    if admin_only and not is_admin:
        raise Exception("Forbidden")
    return {"sub": uid, "is_admin": is_admin}

@app.route("/")
def serve_index():
    if session.get("user_id"):
        return render_template('dashboard.html')
    return render_template('index.html')

@app.route("/dashboard")
def serve_dashboard():
    if not session.get("user_id"):
        return render_template('index.html')
    return render_template('dashboard.html')

@app.route("/test")
def serve_test():
    if not session.get("user_id"):
        return render_template('index.html')
    return render_template('test.html')

@app.route("/admin")
def serve_admin():
    if not session.get("is_admin"):
        return render_template('admin_login.html')
    return render_template('admin.html')

# ==========================================
# STUDENT ROUTES
# ==========================================

@app.route("/student/login", methods=["POST"])
def student_login():
    body = request.json
    conn = get_conn()
    cur = conn.cursor(pymysql.cursors.DictCursor)

    cur.execute("SELECT * FROM users WHERE user_id=%s", (body.get("user_id"),))
    user = cur.fetchone()
    cur.close()
    conn.close()

    if not user:
        return jsonify({"error": "Invalid credentials"}), 401

    try:
        ph.verify(user["password"], body.get("password"))
    except VerifyMismatchError:
        return jsonify({"error": "Invalid credentials"}), 401

    session.permanent = True # Enables the 2-hour lifetime
    session["user_id"] = user["user_id"]
    session["is_admin"] = False
    return jsonify({"status": "Success"})

@app.route("/logout")
def logout():
    session.clear()
    return jsonify({"status": "Logged out"})

@app.route("/student/active", methods=["GET"])
def active_assessment():
    try:
        verify_session()
    except:
        return jsonify({"error": "Unauthorized"}), 402

    conn = get_conn()
    cur = conn.cursor(pymysql.cursors.DictCursor)
    now = datetime.now(IST).strftime("%Y-%m-%d %H:%M:%S")
    uid = session.get('user_id')
    
    # Fetch assessments that are active AND NOT YET COMPLETED (recorded in attempt_meta)
    cur.execute("""
        SELECT a.id, a.seq_num, a.title, a.start_at, a.start_until, a.total_duration 
        FROM assessments a
        LEFT JOIN (SELECT DISTINCT assessment_id FROM attempt_meta WHERE user_id = %s) meta ON a.id = meta.assessment_id
        WHERE a.start_until >= %s AND meta.assessment_id IS NULL
        ORDER BY a.start_at ASC
    """, (uid, now))
    rows = cur.fetchall()
    cur.close()
    conn.close()

    for r in rows:
        r["start_at"] = r["start_at"].isoformat()
        if r["start_until"]:
            r["start_until"] = r["start_until"].isoformat()
        
    return jsonify(rows)

@app.route("/student/questions/<int:aid>", methods=["GET"])
def get_questions(aid):
    try:
        verify_session()
    except:
        return jsonify({"error": "Unauthorized"}), 401

    conn = get_conn()
    cur = conn.cursor(pymysql.cursors.DictCursor)
    cur.execute("""
        SELECT q.id, q.type, q.question, q.answer, q.mark, q.negative_mark
        FROM questions q
        JOIN assessment_questions aq ON q.id = aq.question_id
        WHERE aq.assessment_id = %s
    """, (aid,))
    rows = cur.fetchall()
    cur.close()
    conn.close()

    for r in rows:
        r["answer"] = json.loads(r["answer"])
    return jsonify(rows)

@app.route("/student/submit", methods=["POST"])
def submit_test():
    try:
        user = verify_session()
        if user.get("is_admin"): return jsonify({"error": "Admins cannot submit tests"}), 403
        uid = int(user["sub"])
    except (ValueError, TypeError, Exception):
        return jsonify({"error": "Unauthorized"}), 401

    body = request.json
    assessment_id = body.get("assessment_id")
    responses = body.get("responses", {})
    times = body.get("times", {})

    conn = get_conn()
    cur = conn.cursor()

    # Always create meta-record if it doesn't exist
    cur.execute("INSERT IGNORE INTO attempt_meta (user_id, assessment_id) VALUES (%s, %s)", (uid, assessment_id))
    
    # Process responses...
    data = []
    for qid, resp in responses.items():
        # FR 2.2: Omission Handling. If the status is just 'visited' but no value/selection is present, skip logging it
        if "selected_id" in resp or "selected_ids" in resp or "value" in resp:
            data.append((
                uid,
                assessment_id,
                int(qid),
                json.dumps(resp),
                int(times.get(str(qid), 0))
            ))

    if data:
        cur.executemany("""
            INSERT INTO attempts (user_id, assessment_id, question_id, student_response, time_taken_sec)
            VALUES (%s,%s,%s,%s,%s)
            ON DUPLICATE KEY UPDATE
                student_response=VALUES(student_response),
                time_taken_sec=VALUES(time_taken_sec)
        """, data)
        conn.commit()

    # Update finishing time
    cur.execute("UPDATE attempt_meta SET finished_at = CURRENT_TIMESTAMP WHERE user_id = %s AND assessment_id = %s", (uid, assessment_id))
    
    cur.close()
    conn.close()
    return jsonify({"status": "submitted"})

@app.route("/student/attempts", methods=["GET"])
def student_history():
    try:
        verify_session()
    except:
        return jsonify({"error": "Unauthorized"}), 401
    
    uid = session.get('user_id')
    conn = get_conn()
    cur = conn.cursor(pymysql.cursors.DictCursor)
    
    now = datetime.now(IST)
    
    cur.execute("""
        SELECT a.title, IFNULL(s.total_score, 0) as total_score, 
               (SELECT COUNT(*) FROM assessment_questions aq WHERE aq.assessment_id = a.id) as total_questions,
               IFNULL(s.total_time_taken_sec, 0) as total_time_taken_sec, 
               a.id as assessment_id,
               a.start_at, a.total_duration
        FROM attempt_meta meta
        JOIN assessments a ON meta.assessment_id = a.id
        LEFT JOIN attempt_summary s ON meta.assessment_id = s.assessment_id AND meta.user_id = s.user_id
        WHERE meta.user_id = %s
        ORDER BY a.start_at DESC
    """, (uid,))
    rows = cur.fetchall()
    cur.close()
    conn.close()

    for r in rows:
        # Results available only after (start_at + total_duration)
        start_at = r['start_at']
        duration_mins = r['total_duration'] or 60
        end_time = start_at + timedelta(minutes=duration_mins)
        
        r['results_available'] = now > end_time
        r['start_at'] = r['start_at'].isoformat()
        
    return jsonify(rows)

@app.route("/student/attempt_details/<int:aid>", methods=["GET"])
def student_attempt_details(aid):
    try:
        verify_session()
    except:
        return jsonify({"error": "Unauthorized"}), 401
    
    uid = session.get('user_id')
    conn = get_conn()
    cur = conn.cursor(pymysql.cursors.DictCursor)
    
    # Verify results availability
    cur.execute("SELECT start_at, total_duration FROM assessments WHERE id = %s", (aid,))
    a = cur.fetchone()
    if not a: return jsonify([]), 404
    
    now = datetime.now(IST)
    end_time = a['start_at'] + timedelta(minutes=a['total_duration'] or 60)
    if now < end_time:
        return jsonify({"error": "Evaluation Pending. Results unreleased."}), 403

    cur.execute("""
        SELECT q.question, q.type, ad.student_response, q.answer as correct_answer, 
               ad.mark, ad.negative_mark, ad.score
        FROM attempt_details ad
        JOIN questions q ON ad.question_id = q.id
        WHERE ad.user_id = %s AND ad.assessment_id = %s
    """, (uid, aid))
    rows = cur.fetchall()
    cur.close()
    conn.close()

    for r in rows:
        r['correct_answer'] = json.loads(r['correct_answer'])
        
    return jsonify(rows)

# ==========================================
# ADMIN ROUTES
# ==========================================

@app.route("/admin/login", methods=["POST"])
def admin_login():
    body = request.json
    if str(body.get("user")) == "1" and body.get("password") == "1":
        session.permanent = True
        session["user_id"] = "admin"
        session["is_admin"] = True
        return jsonify({"status": "Success"})
    return jsonify({"error": "Invalid credentials"}), 401

@app.route("/admin/upload_excel", methods=["POST"])
def upload_excel():
    try:
        verify_session(admin_only=True)
    except Exception as e:
        return jsonify({"error": str(e)}), 401

    if 'file' not in request.files:
        return jsonify({"error": "No file uploaded"}), 400

    file = request.files['file']
    try:
        df = pd.read_excel(file)
        # Normalize column names for case-insensitive access
        df.columns = [str(c).strip().lower() for c in df.columns]

        conn = get_conn()
        cur = conn.cursor()

        # Check if attempt_meta exists
        cur.execute("SHOW TABLES LIKE 'attempt_meta'")
        if not cur.fetchone():
            cur.execute("""
                CREATE TABLE attempt_meta (
                    user_id INT UNSIGNED,
                    assessment_id INT UNSIGNED,
                    started_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    finished_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                    PRIMARY KEY (user_id, assessment_id),
                    FOREIGN KEY (user_id) REFERENCES users(user_id) ON UPDATE CASCADE ON DELETE CASCADE,
                    FOREIGN KEY (assessment_id) REFERENCES assessments(id) ON UPDATE CASCADE ON DELETE CASCADE
                )
            """)
            print("DB Migration: Created attempt_meta table")

        insert_data = []
        for _, row in df.iterrows():
            # Get type with default MCQ
            q_type = str(row.get('type', 'MCQ')).upper().strip()
            if not q_type or q_type == 'NAN': q_type = 'MCQ'

            q_text = str(row.get('question', ''))

            # Find all single-letter columns for options (A, B, C...)
            options = []
            import string
            for letter in string.ascii_lowercase:
                if letter in df.columns and not pd.isna(row.get(letter)):
                    options.append(str(row[letter]))

            # Duration default 60 (check for 'duration' or 'time')
            duration = int(row.get('duration', row.get('time', 60))) if not pd.isna(row.get('duration', row.get('time', 60))) else 60
            ans_obj = {"duration_sec": duration}

            # Correct parsing
            correct_raw = str(row.get('correct', '')).strip().lower()
            
            def parse_ans_to_idx(val):
                if val.isdigit(): return int(val)
                # Map a->0, b->1...
                if len(val) == 1 and 'a' <= val <= 'z':
                    return ord(val) - ord('a')
                return None

            if q_type == 'MCQ':
                ans_obj["correct_id"] = parse_ans_to_idx(correct_raw)
                ans_obj["options"] = options
            elif q_type == 'MSQ':
                # Space or comma separated labels or indices
                import re
                parts = re.split(r'[ ,]+', correct_raw)
                ans_obj["correct_ids"] = [parse_ans_to_idx(p) for p in parts if parse_ans_to_idx(p) is not None]
                ans_obj["options"] = options
            elif q_type == 'INT' or q_type == 'NUM':
                # Range: "1, 2" or "1,2"
                if ',' in correct_raw:
                    parts = [float(x.strip()) for x in correct_raw.split(',')]
                    ans_obj["range"] = sorted(parts)
                else:
                    ans_obj["value"] = float(correct_raw)
                
                    if q_type == 'NUM' and not ans_obj.get('range'):
                        ans_obj["tolerance"] = float(row.get('tolerance', 0.1))

                insert_data.append((
                    q_type,
                    q_text,
                    json.dumps(ans_obj),
                    int(row.get('marks', 1)) if not pd.isna(row.get('marks')) else 1,
                    int(row.get('negative_marks', row.get('negative_mark', 0))) if not pd.isna(row.get('negative_marks', row.get('negative_mark', 0))) else 0
                ))

        # Filter out existing duplicates
        final_insert = []
        for d in insert_data:
            cur.execute("SELECT id FROM questions WHERE type=%s AND question=%s AND answer=%s AND mark=%s AND negative_mark=%s", d)
            if not cur.fetchone():
                final_insert.append(d)

        cur.executemany("""
            INSERT INTO questions (type, question, answer, mark, negative_mark)
            VALUES (%s, %s, %s, %s, %s)
        """, final_insert)
        
        # Get IDs of ALL questions from this upload (including those already existing if match)
        all_ids = []
        for d in insert_data:
            cur.execute("SELECT id FROM questions WHERE type=%s AND question=%s AND answer=%s AND mark=%s AND negative_mark=%s", d)
            rid = cur.fetchone()
            if rid: all_ids.append(rid[0] if isinstance(rid, list) else rid.get('id', rid[0]))

        session['last_upload_ids'] = all_ids
        conn.commit()
        cur.close()
        conn.close()
        return jsonify({"status": "success", "count": len(insert_data)})
    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({"error": str(e)}), 400

@app.route("/admin/create_assessment", methods=["POST"])
def create_assessment():
    try:
        verify_session(admin_only=True)
    except: return jsonify({"error": "Unauthorized"}), 401

    body = request.json
    start_at_str = body.get('start_at', '').strip()
    start_until_str = body.get('start_until', '').strip()
    
    # Validation: empty field from HTML might result in just ":00"
    if len(start_at_str) < 10: 
        return jsonify({"error": "Start date is required"}), 400

    try:
        start_at = datetime.strptime(start_at_str, "%Y-%m-%d %H:%M:%S")
    except ValueError:
        return jsonify({"error": "Invalid start time format"}), 400
    
    # Calculate start_until if it's missing or malformed (like just ':00')
    if len(start_until_str) < 10:
        # Default to 1 minute after start
        start_until = (start_at + timedelta(minutes=1)).strftime("%Y-%m-%d %H:%M:%S")
    else:
        start_until = start_until_str

    reminders = body.get('reminders', []) 

    conn = get_conn()
    cur = conn.cursor(pymysql.cursors.DictCursor)
    cur.execute("""
        INSERT INTO assessments (seq_num, title, start_at, start_until, total_duration, reminders)
        VALUES (%s, %s, %s, %s, %s, %s)
    """, (body.get('seq_num'), body.get('title'), start_at_str, start_until, body.get('total_duration', 30), json.dumps(reminders)))
    
    new_id = cur.lastrowid
    
    # Link only the questions from the CURRENT Excel upload being processed
    q_ids = session.get('last_upload_ids', [])
    if q_ids:
        for qid in q_ids:
            cur.execute("INSERT IGNORE INTO assessment_questions (assessment_id, question_id) VALUES (%s, %s)", (new_id, qid))
    else:
        # Fallback: link everything if no session upload found (optional safety)
        cur.execute("INSERT INTO assessment_questions (assessment_id, question_id) SELECT %s, id FROM questions", (new_id,))
    
    # Calculate total duration in Python ONLY (as requested)
    cur.execute("""
        SELECT q.answer 
        FROM questions q
        JOIN assessment_questions aq ON q.id = aq.question_id
        WHERE aq.assessment_id = %s
    """, (new_id,))
    rows = cur.fetchall()
    
    total_sec = 0
    for r in rows:
        ans = json.loads(r['answer'])
        total_sec += int(ans.get('duration_sec', 60))
    
    total_min = max(min(total_sec // 60, 60), 1) # Capped at 1 hour, floor 1 min
    
    cur.execute("UPDATE assessments SET total_duration = %s WHERE id = %s", (total_min, new_id))
    
    conn.commit()
    cur.close()
    conn.close()
    return jsonify({"status": "Assessment created Successfully"})

@app.route("/admin/questions", methods=["GET"])
def admin_questions():
    try:
        verify_session(admin_only=True)
    except: return jsonify({"error": "Unauthorized"}), 401

    conn = get_conn()
    cur = conn.cursor(pymysql.cursors.DictCursor)
    cur.execute("SELECT id, type, question, answer, mark FROM questions")
    rows = cur.fetchall()
    for r in rows:
        r["answer"] = json.loads(r["answer"])

    cur.close()
    conn.close()
    return jsonify(rows)

@app.route("/admin/attempts", methods=["GET"])
def get_attempts():
    try:
        verify_session(admin_only=True)
    except: return jsonify({"error": "Unauthorized"}), 401

    user_id = request.args.get("user_id")
    conn = get_conn()
    cur = conn.cursor(pymysql.cursors.DictCursor)

    # FR 3.3 Dashboard fetching Aggregated summary view
    query = "SELECT * FROM attempt_summary"
    params = ()
    if user_id:
        query += " WHERE user_id = %s"
        params = (user_id,)

    cur.execute(query, params)
    rows = cur.fetchall()
    cur.close()
    conn.close()

    return jsonify(rows)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
