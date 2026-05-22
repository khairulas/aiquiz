# AI-Quiz Generator

A Flask web app that generates quizzes from course materials using Google Gemini, lets students take them via a shareable link or QR code, and gives instructors AI-powered analysis of class performance.

## Features

- Generate quizzes from pasted text or uploaded PDF using Gemini
- Configure question types (True/False, MCQ, Fill-in-the-Blank, Short Answer) and Bloom's taxonomy level per type
- Edit, schedule (open/close times), and time-limit quizzes
- Share quizzes via public link or QR code (no account required for students)
- Auto-graded objective questions (local fuzzy matching, no API call)
- Batch AI-graded short answers (one Gemini call per submission, not per question)
- View individual attempts and AI-generated overall class analysis
- Password reset by email, CSRF protection, rate limiting

## Tech stack

- **Backend:** Flask 3, Flask-Login, Flask-WTF, Flask-Mail, Flask-Limiter
- **Database:** Google Firestore (via `firebase-admin`)
- **AI:** Google Gemini (`gemini-2.5-flash`)
- **PDF parsing:** `pdfplumber`
- **Fuzzy matching:** `thefuzz`
- **Frontend:** Jinja2 templates, vanilla JS
- **Hosting:** PythonAnywhere

## Local setup

### 1. Clone and install

```bash
git clone <your-repo-url>
cd aiquiz
python -m venv venv
source venv/bin/activate   # on Windows: venv\Scripts\activate
pip install -r requirements.txt
```

### 2. Firebase setup

1. Create a Firebase project at https://console.firebase.google.com
2. Enable Firestore (Native mode)
3. Go to Project Settings → Service Accounts → Generate new private key
4. Save the JSON file as `sa-final.json` in the project root (already gitignored)

### 3. Gemini API key

Get a key from https://aistudio.google.com/app/apikey

### 4. Email (for password reset)

You'll need SMTP credentials. For Gmail, generate an App Password under your Google Account → Security → 2-Step Verification → App passwords.

### 5. Environment file

Create `.env` in the project root:

```ini
FLASK_SECRET_KEY=generate-a-long-random-string-here
GOOGLE_APPLICATION_CREDENTIALS=./sa-final.json
FIREBASE_PROJECT_ID=your-firebase-project-id
GEMINI_API_KEY=your-gemini-api-key

MAIL_SERVER=smtp.gmail.com
MAIL_PORT=587
MAIL_USE_TLS=true
MAIL_USERNAME=your-email@gmail.com
MAIL_PASSWORD=your-app-password
```

### 6. Run

```bash
python app.py
```

App will be at `http://127.0.0.1:5000`.

## Firestore data model

```
users/{user_id}
  username, email, password_hash

quizzes/{quiz_id}
  title, user_id, created_at, is_active
  opens_at, closes_at, time_limit, analysis_text
  /questions/{question_id}
    content, question_type, bloom_level, answer, marks, options

quiz_attempts/{attempt_id}
  quiz_id, quiz_title, student_name, score, total_score,
  percentage, timestamp, results_detail
  /student_answers/{answer_id}
    question_id, question_content, answer_text, is_correct
```

### Required Firestore indexes

Firestore will prompt you to create these on first use (it shows a link in the error). Pre-create them in the Firebase console under Firestore → Indexes:

- `quizzes`: `user_id` ASC, `created_at` DESC
- `quiz_attempts`: `quiz_id` ASC, `timestamp` DESC
- `quiz_attempts`: `quiz_id` ASC, `timestamp` ASC (if using time-window dedup)

## Deployment to PythonAnywhere

1. **Push your code to GitHub.**

2. **On PythonAnywhere, clone the repo:**
   ```bash
   git clone <your-repo-url> ~/aiquiz
   cd ~/aiquiz
   ```

3. **Create a virtualenv:**
   ```bash
   mkvirtualenv --python=python3.10 my-app-env
   pip install -r requirements.txt
   ```

4. **Upload your `sa-final.json`** to `~/aiquiz/` via the Files tab.

5. **Create `.env`** in `~/aiquiz/` with the same variables as local, but adjust `GOOGLE_APPLICATION_CREDENTIALS` to the absolute path:
   ```ini
   GOOGLE_APPLICATION_CREDENTIALS=/home/yourusername/aiquiz/sa-final.json
   ```

6. **Configure the Web tab:**
   - Source code: `/home/yourusername/aiquiz`
   - Working directory: `/home/yourusername/aiquiz`
   - Virtualenv: `/home/yourusername/.virtualenvs/my-app-env`
   - WSGI file: edit to point to `from app import app as application`

7. **Reload** from the Web tab.

### Deployment workflow (after initial setup)

Always edit code on your laptop, never on PythonAnywhere.

```bash
# On laptop
git add .
git commit -m "your change"
git push origin main

# On PythonAnywhere bash console
cd ~/aiquiz
git pull
# Then reload the web app from the Web tab
```

## Key architectural decisions

### Post-redirect-get on quiz submission

`submit_quiz` saves the attempt and `redirect()`s to `view_attempt_result`, which is a GET route. Refreshing the results page re-reads from Firestore instead of resubmitting the form. This prevents duplicate attempts and duplicate Gemini grading calls. **Do not** change `submit_quiz` to render the results template directly.

### Batched short-answer grading

`batch_grade_short_answers` sends all short answers in one submission to Gemini in a single API call, not one call per question. This is critical for cost. If you add new question types that need AI grading, follow the same pattern.

### Objective questions never call Gemini

True/False, MCQ, and Fill-in-the-Blank are graded locally with `normalize_answer` + `fuzz.ratio` (85% threshold). Only Short Answer goes to the API.

### Analysis caching

`overall_analysis` caches the generated text on the quiz doc (`analysis_text` field). The `force_reanalyze=true` query param bypasses the cache — be careful with this, every click is a Gemini call. Rate-limited to 3/min.

### Timezone handling

All datetimes stored in Firestore are UTC. Display conversion to Malaysia Time (`Asia/Kuala_Lumpur`) happens via the `myt` Jinja filter. When parsing user input from `datetime-local` form fields, treat as naive, localize to MYT, then convert to UTC before storing.

## Cost management

This app calls a paid API (Gemini). Watch these:

- **Quiz generation** is the largest per-call cost — full course material goes into the prompt. Consider truncating very long materials.
- **Short-answer grading** scales with submissions × number of short-answer questions per quiz.
- **Overall analysis** can be re-run; the cache prevents most calls but `force_reanalyze` bypasses it.

Set a billing alert in Google Cloud Console at a comfortable cap (e.g., RM10/month).

If you see a billing spike, check `app.log` for high-frequency Gemini calls:

```bash
grep "Gemini API" app.log | wc -l
grep "Gemini API" app.log | tail -50
```

## Known limits and design choices

- **One quiz attempt per name per quiz** is not strictly enforced server-side (only via client-side button-disable + post-redirect-get). For stronger guarantees, add the time-window dedup check in `submit_quiz`.
- **Session storage uses cookies** for `generated_questions` between create and save. For quizzes with many questions this can exceed the 4KB cookie limit. Migrate to `Flask-Session` if it becomes a problem.
- **Question order** is not guaranteed stable across reads — Firestore doesn't preserve insertion order without an explicit `order` field. Add one to the `/questions/` subcollection if order matters.
- **Migration scripts** that touch Firestore should live in a separate `scripts/` folder and be gitignored or kept out of the production directory.

## Troubleshooting

**"SyntaxError: invalid decimal literal" on PythonAnywhere reload**
You probably have unresolved merge conflict markers in a file. Check with:
```bash
grep -rn '<<<<<<<\|>>>>>>>' .
```

**"The query requires an index"**
Firestore is asking for a composite index. Click the link in the error log and wait for it to build.

**"CSRF token has expired"**
The user sat on a page too long. Refresh the page to get a new token. Not a bug.

**Jinja `Encountered unknown tag 'endblock'`**
Unbalanced `{% block %}` / `{% endblock %}` in a template. Check counts match.

**Gemini returns malformed JSON**
`parse_questions` handles most cases (trailing commas, markdown fences, wrapped dicts). If a specific quiz fails to generate, check `app.log` for the raw response — usually the prompt needs tightening.

## License

Add your license here.

## Disclaimer

This tool uses generative AI. Generated questions and analyses may contain errors. Always review output before using with students.
