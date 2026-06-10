<p align="center">
  <img src="sastra.png" width="100" alt="SASTRA Logo"/>
  <img src="iste.png" width="100" alt="ISTE Logo"/>
</p>

<h1 align="center">ISTE Test Portal</h1>

<p align="center">
  <strong>A simple, powerful online test platform for ISTE chapter members at SASTRA University</strong>
</p>

<p align="center">
  <a href="#for-faculty">Faculty Guide</a> •
  <a href="#for-students">Student Guide</a> •
  <a href="#for-developers">Developer Guide</a> •
  <a href="https://iste-ws2k.onrender.com" target="_blank">Live Portal</a>
</p>

---

> **What is this?**
> A website (and Android app) where faculty can create question banks, schedule tests, and view student results. Students register, take tests, and see their scores — all from their phone or computer.

---

# For Faculty

> **No technical knowledge needed.** This section walks you through everything step by step.

---

## Quick Start — 3 Easy Steps

```
Step 1 →  Log in to the Admin Dashboard
Step 2 →  Upload your questions (or add them one by one)
Step 3 →  Create a test and schedule it
```

That's it. Students will see the test on their dashboard and can start writing.

---

## Step 1: Log In

1. Open your browser and go to ISTE admin site
2. Enter the **Admin Username** and **Admin Password**, then click **Log In**
3. You will see a **CAPTCHA** (twisted letters/numbers in a picture)
4. Type the letters exactly as shown (it is case-sensitive — `A` and `a` are **NOT** the same)
5. Click **Verify Captcha**

> [!TIP]
> If the **CAPTCHA** image is not clear, click **refresh image** to get a new image

---

## Step 2: Add Questions to the Question Bank

You have **two options**:

### Option A: Upload from Excel (Recommended)

This is the fastest way to add many questions at once.

#### Download the Template

> 📥 **[Download Sample Question Template](sample_question_template.xlsx)** — a ready-made Excel file with examples you can edit and upload.

#### How the Excel File Works

Open the template in Microsoft Excel, Google Sheets, or LibreOffice Calc. You will see **2 sheets**:

| Sheet | What it is |
|-------|-----------|
| **How to Use** | Instructions (same as below) |
| **Questions** | Fill in your questions here |

#### Understanding the Columns

| Column | What to Fill | Example |
|--------|-------------|---------|
| **type** | Question type (leave blank for MCQ) | `MCQ` or leave empty |
| **question** | The question itself | `Capital of India?` |
| **A** | First option | `Mumbai` |
| **B** | Second option | `New Delhi` |
| **C** | Third option | `Chennai` |
| **D** | Fourth option | `Kolkata` |
| **correct** | The correct answer | `B` (for MCQ) |
| **marks** | Points for correct answer (default: 1) | `1` |

#### Defaults (If You Leave Cells Empty)

| Column | Default Value |
|--------|--------------|
| type | MCQ (single correct answer) |
| marks | 1 |
| negative marks | 0 (no negative marking) |
| Options | 4 options (A, B, C, D) |

> **So if you just fill in `question`, `A`, `B`, `C`, `D`, and `correct` — everything else is handled automatically!**

#### Example: Adding a Simple MCQ

```
type:        (leave blank — defaults to MCQ)
question:    What is the capital of France?
A:           London
B:           Paris
C:           Berlin
D:           Madrid
correct:     B
marks:       (leave blank — defaults to 1)
```

#### Example: Adding an MSQ (Multiple Correct)

```
type:        MSQ
question:    Which of these are programming languages?
A:           Python
B:           HTML
C:           Java
D:           CSS
correct:     A,C
marks:       2
```

> [!NOTE]
> (For MSQs) Separate multiple correct answers with commas: `A,C` or `A, B, D` (with or without space)

#### Example: Adding an Integer Question

```
type:        INT
question:    How many continents are there on Earth?
A:           (leave blank)
B:           (leave blank)
C:           (leave blank)
D:           (leave blank)
correct:     7
marks:       1
```

#### Example: Adding a Numeric (Decimal) Question

**Single value** (default tolerance ±0.1):

```
type:        NUM
question:    Value of pi (correct to 2 decimal places)
A:           (leave blank)
B:           (leave blank)
C:           (leave blank)
D:           (leave blank)
correct:     3.14
marks:       1
```

> Student is correct if their answer is between **3.04 and 3.24** (±0.1 tolerance).

**Explicit range** (use comma to set min,max):

```
type:        NUM
question:    Density of water at 4°C (g/cm³)
A:           (leave blank)
B:           (leave blank)
C:           (leave blank)
D:           (leave blank)
correct:     0.99,1.01
marks:       1
```

> Student is correct if their answer is between **0.99 and 1.01** (inclusive).

#### Uploading the File

1. Save your Excel file as `.xlsx` format
2. In the Admin Dashboard, find the **"Import Excel"** section
3. Click **"Choose File"** and select your Excel file
4. Click **"Upload"**
5. You will see a success message showing how many questions were imported

> **Duplicate Detection:** If a question already exists in the bank (same text, type, options, and marks), it will be **automatically skipped** — you don't need to worry about uploading the same file twice.

---

### Option B: Add Questions One by One

If you only have a few questions, you can add them manually:

1. In the Admin Dashboard, find the **"Manual Question Builder"** section
2. Select the question type from the dropdown:
   - **MCQ** — Single correct answer
   - **MSQ** — Multiple correct answers
   - **INT** — Integer answer
   - **NUM** — Numeric/decimal answer
3. Type your **question** in the text box
4. Fill in the **options** (for MCQ and MSQ):
   - Option A
   - Option B
   - Option C
   - Option D
5. Enter the **correct answer**:
   - MCQ: select the correct option letter (A, B, C, or D)
   - MSQ: enter comma-separated letters (e.g. `A,C,D`)
   - INT: enter the integer (e.g. `7`)
   - NUM: enter the number (e.g. `3.14`)
6. Set **Marks** (default is 1)
7. Click **"Add Question"**

---

## Step 3: Create a Test (Assessment)

Once your questions are in the bank, you can create a test:

1. Find the **"Live Event Scheduler"** section in the Admin Dashboard
2. Fill in the test details:

| Field | What to Enter | Example |
|-------|--------------|---------|
| **Type** | `WEEK` for weekly test, `DAY` for daily quiz, `MOCK` for mock exam | `WEEK` |
| **Sequence Number** | Test number (1, 2, 3...) | `1` |
| **Title** | A name students will see | `Week 1 — Data Structures Basics` |
| **Start Date & Time** | When students can start | `2026-06-15 10:00` |
| **End Date & Time** | When the test window closes | `2026-06-15 11:00` |
| **Duration (minutes)** | How long students have to finish | `30` |

3. **Select Reminders** (optional but recommended):
   - ☐ 1 day before
   - ☐ 2 hours before
   - ☐ 1 hour before
   - ☐ 15 minutes before
   - ☐ 5 minutes before

   Students will receive a **push notification** on their phone at these times.

4. **Select Questions** from the question bank:
   - Browse the question bank
   - Click on questions to add them to this test
   - Or select all questions from a specific category

5. Click **"Create Assessment"**

> **That's it!** The test is now scheduled. Students will see it on their dashboard when the test window opens.

---

## Step 4: View Student Results

### Quick View

1. Go to **"Student Performance Logs"** section
2. Enter the student's **Register ID** (e.g. `22803001`)
3. Complete the CAPTCHA
4. Click **"Search"**
5. You'll see a list of all tests the student has taken
6. Click **"View Analysis"** to see:
   - Overall score
   - Time spent
   - Question-by-question breakdown (correct / incorrect / unattempted)
   - Time spent on each question

### Export Results to Excel

1. Go to **"Export Published Assessments"** section
2. Find the test you want to export
3. Click **"Export XLSX"**
4. An Excel file will download with all student scores and details

### Download Student List

1. Go to **"All Registered Students"** section
2. Click **"Load Student List"** to view all registered students
3. Click **"Download XLSX"** to export the list as an Excel file with columns: Reg. ID, Name, Year, Degree, Stream

> **Note:** Assessments conducted before a student registered will show as **"Missing"** with a score of **0** in the student's history. This is expected — the student was not yet registered when those assessments took place.

---

## Step 5: Send Notifications to Students

You can send custom messages to all students:

1. Go to **"Send Message to Students"** section
2. Enter a **Title** (e.g. "Test Postponed")
3. Enter your **Message**
4. Choose:
   - **Send Now** — students receive it immediately
   - **Schedule** — pick a date and time for it to be sent

> Students receive these as **push notifications** on their phones (if they have the app installed) or as **browser notifications** (if using the web browser).

---

## Frequently Asked Questions (Faculty)

**Q: Can I edit a question after uploading?**
A: Not through the portal currently. You would need to re-upload the corrected Excel file — duplicates are automatically skipped.

**Q: What if I upload the same file twice?**
A: No problem — duplicate questions are detected and skipped. Only new questions are added.

**Q: Can I set negative marks?**
A: Yes. Add a `negative_marks` column in your Excel (e.g. `-1` for wrong answers). The default is 0 (no negative marking).

**Q: How do students see the test?**
A: Students log in to the portal (web or app). Active tests appear on their dashboard with a countdown timer. They click "Start Test" when the window opens.

**Q: When are results shown to students?**
A: Results appear automatically after the test window closes + the test duration has passed. For example, if a test ends at 11:00 AM and duration is 30 minutes, results show at 11:30 AM.

**Q: Can I create a test with questions from different topics?**
A: Yes! Just add all questions to the question bank first, then select the specific ones you want for each test.

**Q: What does "Missing" mean in a student's results?**
A: Assessments conducted before a student registered show as "Missing" with a score of 0. This is expected — the student wasn't in the system yet or the student didn't attend that test.

---

# For Students

## How to Register

1. Open the portal: **[iste-ws2k.onrender.com](https://iste-ws2k.onrender.com)**
2. Click **"Register"** tab
3. Enter your **Registration ID** and click **"Send OTP"**
4. Check your SASTRA email (`{your-id}@sastra.ac.in`) for the 6-digit OTP
5. Enter the OTP and click **"Verify OTP"**
6. Fill in your details:
   - **Name** — your full name
   - **Year** — select your current year (1st / 2nd / 3rd / 4th)
   - **Degree** — e.g. `B.Tech`
   - **Stream** — e.g. `CSE`
   - **Password** — choose a password (minimum 6 characters)
   - **Confirm Password** — type the same password again
7. Click **"Create Account"**

> **OTP Limit:** Each Registration ID can request a maximum of **4 OTPs per day** (across both registration and password reset). If you exceed this, wait 24 hours and try again.

> You're all set! Log in with your Register Number and Your Password.

---

## How to Take a Test

1. **Log in** with your Register ID and Password
2. On your dashboard, you'll see **Active Assessments** with countdown timers
3. When the test window opens, the **"Start Test"** button becomes clickable
4. Click **"Start Test"**

### During the Test

| Button | What it does |
|--------|-------------|
| **Save & Next** | Saves your answer and moves to the next question |
| **Mark for Review** | Flags the question so you can come back to it |
| **Clear Response** | Removes your answer for the current question |
| **Final Submit** | Submits the entire test (you'll be asked to confirm) |

### Timer

- A countdown timer runs at the top of the screen
- **When the timer reaches zero, the test auto-submits** — so make sure to save your answers before time runs out!

### Crash Recovery

If your browser crashes or you accidentally close the tab, don't worry. When you reopen the test, your previous answers are **automatically restored** from local storage.

> [!CAUTION]
> Your progress is saved **only on the device you started the test on**. If you log in from a different device, your previous answers will not be there. Also, the timer keeps running in the background even when the test tab is closed — so get back quickly!

---

## How to Use the Mobile App

1. Download the APK from the latest **release** that you can see on *https://github.com/Harikrishna-Srinivasan/iste*
2. Install it on your Android phone (you may need to enable "Install from unknown sources")
3. Open the app and log in with the same credentials
4. Allow notification alerts from ISTE so that you can receive **push notifications** for test reminders

---

## How to View Your Results

1. Log in to the portal
2. Scroll down to **"Past Attempts & Results"**
3. Click on any test to expand and see:
   - Your score
   - Time spent
   - Per-question breakdown (which ones you got right/wrong)

---

# For Developers

---

## Tech Stack

| Layer | Technology | Notes |
|-------|-----------|-------|
| Backend | Flask (Python 3.12) | Two separate apps: student + admin |
| WSGI Server | Waitress | 64 threads, production-grade |
| Database | MySQL 8 (Aiven Cloud) | Managed, with JSON column support |
| DB Driver | PyMySQL + DBUtils PooledDB | Connection pooling (50 student / 2 admin) |
| Auth | JWT + Flask Sessions | Dual auth for Capacitor WebView compatibility |
| Password Hashing | Argon2 | Memory-hard, ASIC-resistant |
| Push Notifications | FCM (`firebase-admin`) | Multicast to all registered devices |
| Scheduler | APScheduler | BackgroundScheduler for timed alerts |
| Mobile | Capacitor 8 | WebView wrapper → Android APK (`com.iste.app`) |
| Compression | flask-compress | Gzip |
| Minification | flask-minify | Auto-minifies HTML/JS/CSS |
| Excel I/O | Pandas + OpenPyXL (server) / SheetJS (client) | Import questions, export results |
| Deployment | Render | Auto-deploy from git push |

---

## Architecture

```
┌──────────────────────────────────────────────────────┐
│                    Render (Cloud)                     │
│                                                      │
│  ┌──────────────┐          ┌──────────────┐          │
│  │ student.py    │          │ admin.py      │          │
│  │ :5000         │          │ :5002         │          │
│  │ Waitress      │          │ Flask dev     │          │
│  │               │          │               │          │
│  │ Auth          │          │ Auth + CAP    │          │
│  │ Registration  │          │ Question Bank │          │
│  │ Test Taking   │          │ Scheduling    │          │
│  │ Auto-grading  │          │ FCM Push      │          │
│  │ Results       │          │ APScheduler   │          │
│  └───────┬───────┘          └───────┬───────┘          │
│          └──────────┬───────────────┘                  │
│                     │                                 │
│             ┌───────▼───────┐                         │
│             │ MySQL (Aiven)  │                         │
│             │ db: iste       │                         │
│             └───────────────┘                         │
└──────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────┐
│                  Client Devices                       │
│                                                      │
│  ┌────────────┐  ┌────────────┐  ┌────────────┐    │
│  │ Web Browser │  │ Android    │  │ Admin      │    │
│  │ (students)  │  │ (Capacitor)│  │ (browser)  │    │
│  └────────────┘  └────────────┘  └────────────┘    │
└──────────────────────────────────────────────────────┘
```

### Key Design Decisions

- **Two Flask apps, separate processes** — student app (`student.py`) runs on port 5000 with Waitress, admin app (`admin.py`) runs on port 5002 with Flask dev server. Different DB credentials for least privilege.
- **No bundler** — all HTML files have inline CSS/JS, served as Jinja2 templates from the project root. No React/Vue/Webpack.
- **Live WebView** — Capacitor loads `https://iste-ws2k.onrender.com` directly. No bundled assets. Updates are instant.
- **Dual auth** — JWT token cookie (`SameSite=Lax`, 1-day expiry) for API fetch calls + Flask session for page loads. Required because Capacitor WebView breaks `SameSite=None`.
- **No cache on API** — `Cache-Control: no-store` + `Surrogate-Control: no-store` on all JSON responses. Prevents CDN/browser caching.

---

## Project Structure

```
iste/
├── student.py              # Student Flask backend (port 5000)
│   ├── Auth (login, register, JWT, session)
│   ├── Test taking (questions, submit, auto-grade)
│   ├── Results & history
│   ├── FCM device registration
│   └── Notification polling
│
├── admin.py                # Admin Flask backend (port 5002)
│   ├── Auth (login, CAPTCHA)
│   ├── Question bank (CRUD, Excel import)
│   ├── Assessment scheduling
│   ├── FCM push notifications
│   ├── APScheduler (timed alerts)
│   └── XLSX export
│
├── index.html              # Student login / register page
├── dashboard.html          # Student dashboard (active tests + history)
├── test.html               # Live test environment (anti-cheat)
├── admin_login.html        # Admin login (canvas CAPTCHA)
├── admin.html              # Admin dashboard (all management tools)
│
├── schema.db               # MySQL schema
├── sample_question_template.xlsx   # Downloadable Excel template
├── .env                    # Environment variables (gitignored)
├── requirements.txt        # Python dependencies
├── capacitor.config.json   # Capacitor config
├── package.json            # Node.js deps for Capacitor plugins
├── android/                # Capacitor Android project
├── www/                    # Built web assets (copies for Capacitor)
├── setup_bash.sh           # Capacitor setup (Linux/Mac)
├── setup_cap.bat           # Capacitor setup (Windows)
├── iste.png
└── sastra.png
```

---

## Setup

### Prerequisites

```
Python 3.10+         →  https://python.org
MySQL 8+             →  https://aiven.io (free cloud) or local install
Node.js 18+          →  https://nodejs.org
Firebase project     →  https://console.firebase.google.com
Android Studio       →  https://developer.android.com/studio (for APK)
```

### 1. Clone and Install

```bash
git clone https://github.com/Harikrishna-Srinivasan/iste.git && cd iste
python3 -m venv venv
source venv/bin/activate # venv\bin\activate for Windows
npm install
pip3 install -r requirements.txt
```

### 2. Database Setup

```bash
# Use the ISTE database
use ISTE;

# Create MySQL `stud` users
CREATE USER 'stud'@'%' IDENTIFIED BY 'stud-password';
GRANT SELECT, INSERT, UPDATE ON iste.* TO 'stud'@'%';
FLUSH PRIVILEGES;
```

**Why `stud` as a user?**
- `stud` — used by the student app. Can only read data and submit test answers. Cannot delete anything or change other schemas.

### 3. Environment Variables

Create `.env` in the project root:

```env
# Generate secrets: python3 -c "import secrets; print(secrets.token_hex(32))"
secret_key=<64-char-hex>
jwt_secret=<64-char-hex>
admin_secret_key=<64-char-hex>
admin_jwt_secret=<64-char-hex>

# MySQL
host=mysql-xxxxx.aivencloud.com
port=18290
db=iste
student=stud
stud_pwd=<student-db-password>
admin=avnadmin
password=<admin-db-password>

# Generate admin password hash:
# python3 -c "from argon2 import PasswordHasher; print(PasswordHasher().hash('your-password'))"
admin_password=<argon2-hash>

# Firebase
firebase_json=iste-xxxxx-firebase-adminsdk-xxxxx.json
```

### 4. Run

```bash
source venv/bin/activate

# Terminal 1 — Student app
python3 student.py
# → http://localhost:5000

# Terminal 2 — Admin app
python3 admin.py
# → http://localhost:5002
```

---

## Database Schema

```sql
users                    -- student accounts
  user_id INT UNSIGNED PK    -- SASTRA registration number
  name VARCHAR(80)
  details JSON                -- {"year": int, "degree": str, "stream": str}
  password VARCHAR(255)       -- Argon2 hash

user_devices             -- FCM device tokens
  user_id FK → users
  fcm_token VARCHAR(512) UNIQUE

questions                -- question bank
  id AUTO_INCREMENT PK
  type ENUM('MCQ','MSQ','INT','NUM')
  question TEXT
  answer JSON                 -- format depends on type
  mark TINYINT
  negative_mark TINYINT

assessments              -- test definitions
  id AUTO_INCREMENT PK
  type ENUM('WEEK','DAY','MOCK')
  title VARCHAR(255)
  start_at DATETIME           -- test window opens
  end_at DATETIME             -- test window closes
  total_duration INT          -- time limit in minutes
  reminders JSON              -- ["1d","2h","1h","15m","5m"]

assessment_questions     -- many-to-many: which questions in which test
student_submissions      -- graded attempts
  detailed_log JSON           -- per-question: {score, time, response}

sent_notifications       -- tracks sent reminders (dedup)
push_queue               -- pending push notifications (PENDING → SENT)
```

### Answer JSON Formats

```jsonc
// MCQ — single correct
{"correct_id": 0, "options": ["London", "Paris", "Berlin", "Madrid"]}

// MSQ — multiple correct
{"correct_ids": [0, 2], "options": ["Python", "HTML", "Java", "CSS"]}

// INT — integer answer
{"value": 42}
// or range
{"range": [40, 44]}

// NUM — numeric answer (single value, default ±0.1 tolerance)
{"value": 3.14, "tolerance": 0.1}
// → accepts 3.04 to 3.24

// NUM — numeric answer (explicit range)
{"range": [3.1, 3.2]}
// → accepts 3.1 to 3.2 inclusive
```

### Auto-grading Logic

| Type | Correct | Incorrect | Unattempted |
|------|---------|-----------|-------------|
| MCQ | +marks | 0 | 0 |
| MSQ | +marks only if ALL correct selected (no partial) | 0 | 0 |
| INT | +marks if exact match or within range | 0 | 0 |
| NUM | +marks if within tolerance (±0.1 default) or range | 0 | 0 |

---

## Excel Import — Parser Details

The upload endpoint (`/admin/upload_excel`) parses Excel/CSV with these rules:

- **Column names are case-insensitive** — `Type`, `type`, `TYPE` all work
- **Missing `type` column or empty cells** → defaults to `MCQ`
- **Missing `marks` column or empty cells** → defaults to `1`
- **Missing `negative_marks` column** → defaults to `0`
- **Options** → any single-letter columns (`A`, `B`, `C`, `D`) are treated as options
- **`correct` column** → case-insensitive. MCQ: `A`/`B`/`C`/`D`. MSQ: `A,C,D` (comma-separated). INT: integer. NUM: single value (e.g. `3.14` → default ±0.1 tolerance) or range (e.g. `3.1,3.2` → explicit min,max).
- **Duplicate detection** → strict: question text + type + marks + negative marks + options must ALL match
- **Blank rows** → skipped
- **Unknown types** → skipped

---

## Capacitor (Android)

### How It Works

The Android app is a **WebView** that loads the production URL (`https://iste-ws2k.onrender.com`). It does NOT bundle HTML locally. Updates are instant — no rebuild needed.

### Build the APK

```bash
source venv/bin/activate
npx cap sync android
```

Then open `android/` in **Android Studio**:
1. **Build** → **Generate Signed Bundle / APK**
2. Select **APK**
3. Choose keystore (`iste.jks` at project root), set passwords
4. Output: `android/app/build/outputs/apk/release/app-release.apk`

### Android Config (`AndroidManifest.xml`)

- **Permissions:** `INTERNET`, `ACCESS_NETWORK_STATE`, `POST_NOTIFICATIONS`
- **Firebase:** `google-services.json` + messaging metadata
- **Cleartext:** allowed for local dev (`usesCleartextTraffic="true"`)
- **Package:** `com.iste.app`

### Quick Setup Scripts

```bash
# Linux/Mac
bash setup_bash.sh

# Windows
setup_cap.bat
```

---

## Deployment (Render)

```bash
# Only student.py runs on Render (port 5000)
python3 student.py
```

### CORS Whitelist

```python
CORS(app, origins=[
    "https://iste-ws2k.onrender.com",
    "http://localhost:5000",
    "http://localhost:5002",
    "capacitor://localhost",
    "http://localhost"
])
```

### Cache Headers

All JSON responses include:
```
Cache-Control: no-store, no-cache, must-revalidate
Surrogate-Control: no-store
Vary: Cookie
```

---

## API Endpoints

### Student

| Endpoint | Method | Auth | Description |
|----------|--------|------|-------------|
| `/student/login` | POST | None | Login |
| `/student/register` | POST | None | Register (requires registration_token from OTP verification) |
| `/student/send-registration-otp` | POST | None | Send OTP for registration |
| `/student/verify-registration-otp` | POST | None | Verify registration OTP, returns registration_token |
| `/student/me` | GET | JWT/Session | Current user info |
| `/student/active` | GET | JWT/Session | Active assessments |
| `/student/questions/<aid>` | GET | JWT/Session | Fetch questions |
| `/student/submit` | POST | JWT/Session | Submit answers |
| `/student/attempts` | GET | JWT/Session | Past attempts |
| `/student/attempt_details/<aid>` | GET | JWT/Session | Detailed results |
| `/student/register_device` | POST | JWT/Session | Register FCM token |
| `/get_pending_notifications` | GET | JWT/Session | Unread notifications |
| `/ack_notification` | POST | JWT/Session | Acknowledge notification |

### Admin

| Endpoint | Method | Auth | Description |
|----------|--------|------|-------------|
| `/admin/login` | POST | None | Login |
| `/admin/questions` | GET | JWT/Session | List question bank |
| `/admin/upload_excel` | POST | JWT/Session | Import from Excel |
| `/admin/add_question` | POST | JWT/Session | Add single question |
| `/admin/create_assessment` | POST | JWT/Session | Create assessment |
| `/admin/assessments` | GET | JWT/Session | List assessments |
| `/admin/attempts` | GET | JWT/Session | All submissions |
| `/admin/attempt_details/<uid>/<aid>` | GET | JWT/Session | Student analysis |
| `/admin/export_assessment/<aid>` | GET | JWT/Session | Export results |
| `/admin/send_message` | POST | JWT/Session | Queue notification |
| `/admin/students` | GET | JWT/Session | List students |

---

## License
This project is licensed under the Apache License 2.0. See the [LICENSE](LICENSE) file for detailed information.

Additional attribution details can be found in the [NOTICE](NOTICE) file.
