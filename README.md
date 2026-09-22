# AI-Quiz Generator

A Flask web app that generates quizzes from course materials using Google Gemini, lets students take them with their UiTM Google account, and gives lecturers AI-powered analysis of class performance.

Live at `https://aiquiz.pythonanywhere.com`.

## Features

**For lecturers**
- Generate questions from pasted text or an uploaded PDF
- Configure any number of question groups — each with its own type, count, Bloom's level and marks (e.g. 5 True/False at Remembering + 5 True/False at Understanding)
- Live summary of total questions, total marks and estimated sitting time, with warnings when a quiz gets long or short-answer-heavy
- Review and edit every generated question before saving
- Schedule open/close times and a time limit (Malaysia time)
- Share by link or QR code
- See attempts with matric number and real name; export to CSV
- AI analysis of class-wide misconceptions

**For students**
- Sign in with the UiTM student Google account — no name typing, no registration
- One attempt per quiz (unless the lecturer allows retakes)
- Immediate results with a question-by-question breakdown
- A personal history of every quiz taken, with past results

## Tech stack

- **Backend:** Flask 3, Flask-Login, Flask-WTF, Flask-Mail, Flask-Limiter, Flask-Session
- **Auth:** Google OAuth 2.0 via Authlib (OpenID Connect)
- **Database:** Google Firestore (`firebase-admin`)
- **AI:** Google Gemini (`gemini-2.5-flash`)
- **PDF parsing:** `pdfplumber`
- **Fuzzy matching:** `thefuzz` (rapidfuzz backend)
- **Frontend:** Jinja2 templates, vanilla JS
- **Hosting:** PythonAnywhere

## Authentication and roles

Identity comes from the email domain, not from anything the user types.

| Address | Role | How they sign in |
|---|---|---|
| `<staff-username>@uitm.edu.my` | lecturer | Google, or password (approved staff only) |
| `<matric>@student.uitm.edu.my` | student | Google only |
| anything else | rejected | — |

Two further rules:

- **Lecturer accounts are allowlisted.** A staff member signing in for the first time is refused unless their address is in `ALLOWED_LECTURER_EMAILS`. This is what stops the Gemini bill being spent by anyone who finds the URL.
- **Password sign-in is staff-only.** Students must use Google. Legacy password accounts that aren't approved staff are refused.

Every `users` document carries an explicit `role`. Documents without one fall back to `lecturer` in `load_user`, so never leave the field unset.

### Workshop guests

To let participants from another institution take a quiz, add their domain to `UITM_STUDENT_DOMAINS`, reload the web app, and remove it again afterwards:

```ini
UITM_STUDENT_DOMAINS="student.uitm.edu.my,student.uthm.edu.my"
```

Removing the domain doesn't delete their accounts or attempts — those stay visible to you in the attempts table and CSV. They simply can't sign in again.

## Local setup

### 1. Clone and install

```bash
git clone <your-repo-url>
cd aiquiz
python -m venv .venv
.venv\Scripts\Activate.ps1      # Windows;  source .venv/bin/activate on Linux
pip install -r requirements.txt
```

Use Python 3.10 or 3.11 to match PythonAnywhere. Python 3.13 works but some wheels resolve differently.

### 2. Firebase

1. Create a project at https://console.firebase.google.com
2. Enable Firestore (Native mode)
3. Project Settings → Service Accounts → Generate new private key
4. Save the JSON as `sa-final.json` in the project root (gitignored)

### 3. Google OAuth client

In the **same** Google Cloud project:

1. **Google Auth Platform → Branding** — app name `AI-Quiz Generator`, support email, homepage, privacy and terms URLs, authorised domain `pythonanywhere.com`. **Leave the logo empty** — uploading one triggers a verification review that the three non-sensitive scopes otherwise avoid.
2. **Audience → External**, then Publish.
3. **Data Access** — add exactly `openid`, `.../auth/userinfo.email`, `.../auth/userinfo.profile`. All three must show as **Non-sensitive**. Adding anything else loses the exemption from the 100-user cap and the unverified-app warning.
4. **Clients → Create client → Web application**, with these authorised redirect URIs:
   - `https://aiquiz.pythonanywhere.com/auth/google/callback`
   - `http://127.0.0.1:5000/auth/google/callback`
   - `http://localhost:5000/auth/google/callback`

URIs must match byte for byte. `localhost` and `127.0.0.1` are different strings — register both or you'll get `redirect_uri_mismatch` locally.

### 4. Email (password reset)

SMTP credentials. For Gmail, generate an App Password under Google Account → Security → 2-Step Verification → App passwords.

### 5. Environment file

Create `.env` in the project root:

```ini
FLASK_SECRET_KEY="a-long-random-string"
GOOGLE_APPLICATION_CREDENTIALS="sa-final.json"
FIREBASE_PROJECT_ID="your-firebase-project-id"
GEMINI_API_KEY="your-gemini-api-key"

# --- Email ---
MAIL_SERVER="smtp.gmail.com"
MAIL_PORT=587
MAIL_USE_TLS=True
MAIL_USERNAME="your-email@gmail.com"
MAIL_PASSWORD="your-app-password"

# --- Google OAuth ---
GOOGLE_OAUTH_CLIENT_ID="xxxx.apps.googleusercontent.com"
GOOGLE_OAUTH_CLIENT_SECRET="GOCSPX-xxxx"

# --- Identity ---
UITM_STUDENT_DOMAINS="student.uitm.edu.my"
UITM_STAFF_DOMAINS="uitm.edu.my"
ALLOWED_LECTURER_EMAILS="you@uitm.edu.my,colleague@uitm.edu.my"

# --- Quiz size limits ---
SUGGESTED_MAX_QUESTIONS=20
MAX_QUESTIONS_PER_QUIZ=50
```

Quote every value. An unquoted secret containing `#` is silently truncated at that character, producing a confusing `invalid_client` error at sign-in.

On PythonAnywhere use the absolute path: `GOOGLE_APPLICATION_CREDENTIALS="/home/<user>/aiquiz/sa-final.json"`.

### 6. Run

```bash
python app.py
```

Open `http://127.0.0.1:5000`.

## Firestore data model

```
users/{user_id}
  role           : 'lecturer' | 'student'     <- always set this explicitly
  email
  full_name      : from the Google profile
  matric_no      : students only, the email local part
  auth_provider  : 'google' | 'password'
  username       : legacy password accounts
  password_hash  : legacy password accounts
  created_at, last_login

quizzes/{quiz_id}
  title, user_id, created_at, is_active
  opens_at, closes_at, time_limit        <- UTC
  allow_retakes  : bool
  analysis_text  : cached class analysis
  /questions/{question_id}
    content, question_type, bloom_level, answer, marks, options

quiz_attempts/{attempt_id}
  quiz_id, quiz_title
  student_id, student_email, student_matric, student_name
  score, total_score, percentage, timestamp
  results_detail : [] full per-question grading, for re-rendering the result page
  /student_answers/{answer_id}
    question_id, question_content, answer_text, is_correct
```

### Required composite indexes

Create these in the Firebase console under Firestore → Indexes → Composite, or follow the link Firestore puts in the error.

| Collection | Fields |
|---|---|
| `quizzes` | `user_id` ASC, `created_at` DESC |
| `quiz_attempts` | `quiz_id` ASC, `student_id` ASC |
| `quiz_attempts` | `quiz_id` ASC, `timestamp` DESC |
| `quiz_attempts` | `student_id` ASC, `timestamp` DESC |

The last one is for the student dashboard. Without it the history page renders empty with a red error rather than crashing, which makes it easy to misdiagnose.

## Deployment to PythonAnywhere

### First time

1. Push to GitHub.
2. `git clone <your-repo-url> ~/aiquiz`
3. `mkvirtualenv --python=python3.10 my-app-env && pip install -r requirements.txt`
4. Upload `sa-final.json` via the Files tab.
5. Create `.env` with the same variables, absolute credentials path.
6. `mkdir -p ~/aiquiz/.flask_session`
7. Web tab: source `/home/<user>/aiquiz`, working dir the same, virtualenv `/home/<user>/.virtualenvs/my-app-env`, WSGI file `from app import app as application`.
8. Reload.

### Every deploy after that

```bash
# laptop
git add .
git commit -m "..."
git push origin main

# PythonAnywhere
cd ~/aiquiz
git pull
# then RELOAD from the Web tab
```

**The reload is not optional.** Files on disk do nothing until uWSGI restarts — the most common cause of "I deployed but nothing changed".

`.env` is gitignored, so it does **not** travel with a push. Any new variable must be added on both machines by hand.

Never edit code directly on PythonAnywhere. Production pulls from git; that's all. Editing there is what produces merge conflicts on the next pull — and conflict markers committed into `app.py` will take the whole site down with a `SyntaxError`.

## Key architectural decisions

### Post-redirect-get on submission

`submit_quiz` saves the attempt and redirects to `view_attempt_result`, a GET route. Refreshing the results page re-reads Firestore instead of resubmitting. This prevents duplicate attempts and duplicate Gemini grading calls. **Do not** change `submit_quiz` to render the results template directly.

### Duplicate prevention is account-based

`submit_quiz` checks for an existing attempt with the same `quiz_id` + `student_id` and redirects to it. That's absolute, not a time window, and needs no timestamp index. An earlier name-based, 10-minute version was removed — it collided when two students shared a name.

### Objective questions never call Gemini

True/False, MCQ and Fill-in-the-Blank are graded locally with `normalize_answer` plus `fuzz.ratio` at an 85% threshold. Only Short Answer goes to the API.

### Short answers are graded in one batched call

`batch_grade_short_answers` sends every short answer in a submission to Gemini in a single request, not one per question. Follow the same pattern for any new AI-graded type.

### Question configuration is a list of groups

`create_quiz` reads parallel form arrays (`q_type`, `q_count`, `q_bloom`, `q_marks`) into a list of config dicts, merging identical `(type, bloom, marks)` rows. Each group can specify its own Bloom's level, so one quiz can span several levels for the same question type.

After generation, the returned questions are reconciled against the requested breakdown and any shortfall is flashed to the lecturer. Gemini drifts when given many groups; without the check, that drift is silent.

### Analysis caching

`overall_analysis` caches its output in `analysis_text` on the quiz document. The `force_reanalyze=true` parameter bypasses the cache and costs a full Gemini call — rate-limited to 3/min, but not capped in total.

### Timezone handling

All datetimes are stored in UTC. Display conversion to `Asia/Kuala_Lumpur` happens through the `myt` Jinja filter. Input from `datetime-local` fields is parsed as naive, localised to MYT, then converted to UTC before storing.

### Server-side sessions

`generated_questions` is held in the session between generation and saving. Flask's default cookie session has a ~4KB browser limit, which a 10-question quiz can exceed — silently, producing "your session expired" on save. Flask-Session with the filesystem backend removes that limit. Don't switch back.

## Cost management

Gemini is billed to the project's Google Cloud account. Keep a budget alert set (RM10 is a reasonable floor for a single-lecturer deployment) — a spike almost always signals a bug, not gradual growth.

| Action | Cost |
|---|---|
| Generating a quiz — the entire course material goes into the prompt | Highest |
| `overall_analysis` with `force_reanalyze=true` | Highest |
| Short-answer grading — one call per submission | Scales with class size |
| True/False, MCQ, Fill-in-the-Blank grading | Free |
| Viewing or re-reading results | Free |

Controls in place:
- `MAX_QUESTIONS_PER_QUIZ` — hard limit, enforced server-side
- `SUGGESTED_MAX_QUESTIONS` — soft limit; the form warns and requires an explicit acknowledgement
- Rate limits on `create_quiz` (10/min), `overall_analysis` (3/min), `submit_quiz` (10/min)
- Long quizzes are logged with the lecturer's email and short-answer count

Generation cost is driven more by **material length** than question count. A short quiz on a 40-page chapter costs more than a long quiz on three pages.

To audit usage:

```bash
grep "Gemini API" app.log | wc -l
grep "Long quiz generated" app.log | tail -20
```

## Known limits

- **Cross-class access** — any signed-in student with the link can take any quiz, not only your class. Keep the open window tight for graded work, and check matric numbers in the export.
- **Question order** is not guaranteed stable across reads; Firestore doesn't preserve insertion order. Add an `order` field to the questions subcollection if it matters.
- **Pre-authentication attempts** have no `student_id` or `student_matric`, so they show `—` in the attempts table and never appear in any student's history. Nothing backfills them.
- **Bloom's level fidelity** depends on the prompt. Verify that questions labelled Applying actually require application — the reconciliation check counts them but cannot judge them.
- **Legacy password accounts** exist from before Google sign-in. All should carry an explicit `role`; run an audit if you're unsure.

## Troubleshooting

**"I deployed but nothing changed"**
You didn't reload from the Web tab.

**`Error 400: redirect_uri_mismatch`**
The URI Flask sent isn't registered. Click *error details* on the Google page to see the exact string. `localhost` and `127.0.0.1` are different — register both.

**`SyntaxError: invalid decimal literal` on reload**
Merge conflict markers in a file. `grep -rn '<<<<<<<\|>>>>>>>' .`

**"The query requires an index"**
Click the link in the error log, create it, wait for **Enabled**.

**Student sees the lecturer dashboard**
Their `users` document has no `role`, so it defaults to lecturer. Set it explicitly.

**Student can't sign in**
Almost always a personal Gmail. Have them open the link in a private window and choose their `@student.uitm.edu.my` account.

**Jinja `Encountered unknown tag 'endblock'`**
Unbalanced `{% block %}` / `{% endblock %}`. Check every template compiles:
```bash
python -c "from app import app; import os; [app.jinja_env.get_template(f) for f in os.listdir('templates') if f.endswith('.html')]; print('ok')"
```

**Gemini returns malformed JSON**
`parse_questions` handles trailing commas, markdown fences and wrapped dicts. If a specific quiz still fails, check `app.log` for the raw response — usually the prompt needs tightening or the material is too long.

**"CSRF token has expired"**
The page sat open too long. Refresh. Not a bug.

## Scripts

Utility scripts live in `scripts/` and are gitignored. Run them from the project root, where `.env` and `sa-final.json` are. Every script that writes should default to `DRY_RUN = True`.

Never leave migration scripts on PythonAnywhere — run them from your laptop against the same Firestore project.

## License

Add your license here.

## Disclaimer

This tool uses generative AI. Generated questions and analyses may contain errors. Always review output before using it with students.