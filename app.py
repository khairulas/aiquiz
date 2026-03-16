import pytz
from datetime import datetime
import firebase_admin
from firebase_admin import credentials, firestore
import io
import re
#import sys
#import uuid
import json
import logging
import os
import time
#from datetime import datetime, timezone
from collections import defaultdict


# --- Standard Library Imports First ---
from flask import (
    Flask, current_app, flash, render_template,
    request, redirect, send_file, session, url_for, g
)
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.security import generate_password_hash, check_password_hash
from markupsafe import Markup

# --- Third-Party Imports ---
from dotenv import load_dotenv

from flask_login import (
    LoginManager, UserMixin, login_user, logout_user,
    login_required, current_user
)
from flask_wtf.csrf import CSRFProtect, generate_csrf
from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadTimeSignature
import google.generativeai as genai
import markdown
import pdfplumber
import qrcode
from bleach import clean
from thefuzz import fuzz
import string

def normalize_answer(ans):
    if not ans:
        return ""
    # Lowercase and strip surrounding whitespace
    ans = str(ans).lower().strip()
    # Remove any stray punctuation (like periods at the end)
    ans = ans.translate(str.maketrans('', '', string.punctuation))
    
    # Map common number words to digits
    number_map = {
        'zero': '0', 'one': '1', 'two': '2', 'three': '3', 'four': '4',
        'five': '5', 'six': '6', 'seven': '7', 'eight': '8', 'nine': '9', 'ten': '10'
    }
    
    # Return the mapped digit, or the original word if it's not in the map
    return number_map.get(ans, ans)

# ==============================================================================
# 1. APPLICATION SETUP AND CONFIGURATION
# ==============================================================================

# Load environment variables from .env file
load_dotenv()

# Initialize the Flask app
app = Flask(__name__)

# --- Timezone Configuration ---
MYT = pytz.timezone('Asia/Kuala_Lumpur')

limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"]
)

MAX_FILE_SIZE_MB = 10  # Set your limit here (e.g., 5 MB)
app.config['MAX_CONTENT_LENGTH'] = MAX_FILE_SIZE_MB * 1024 * 1024

# --- Logging Configuration in terminal
# Set up basic logging to capture INFO level messages and above.
# This is crucial for performance, usability, and security auditing.
# logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# --- Logging Configuration ---
# Set up basic logging to capture INFO level messages and above.
# This is crucial for performance, usability, and security auditing.
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    filename='app.log',  # <-- Directs output to the app.log file
    filemode='a'         # <-- 'a' for append, so logs aren't erased on restart
)


# --- Load Configurations ---
app.config['SECRET_KEY'] = os.getenv('FLASK_SECRET_KEY', 'a_default_secret_key_for_development')

# Database Configuration
# --- Firebase Admin SDK Initialization ---
# This uses the GOOGLE_APPLICATION_CREDENTIALS path from your .env
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
KEY_PATH = os.path.join(BASE_DIR, 'serviceAccountKey.json')

try:
    # 1. Try to get path from environment variable (Best for Production)
    key_path = os.getenv('GOOGLE_APPLICATION_CREDENTIALS')

    # 2. Fallback: Check local directory (Best for Local Dev if env var is missing)
    if not key_path or not os.path.exists(key_path):
        base_dir = os.path.dirname(os.path.abspath(__file__))
        local_key_path = os.path.join(base_dir, 'sa-final.json') # Or serviceAccountKey.json
        if os.path.exists(local_key_path):
            key_path = local_key_path

    if not key_path or not os.path.exists(key_path):
        raise FileNotFoundError(f"Service account key not found. Env var: {os.getenv('GOOGLE_APPLICATION_CREDENTIALS')}")

    # Initialize
    cred = credentials.Certificate(key_path)
    firebase_admin.initialize_app(cred, {
        'projectId': os.getenv('FIREBASE_PROJECT_ID'),
    })
    app.logger.info("Firebase Admin SDK initialized successfully.")

except ValueError:
    # App already initialized (common with reloader)
    app.logger.warning("Firebase app already initialized.")
except Exception as e:
    # CRITICAL: If init fails, we cannot continue.
    app.logger.error(f"Failed to initialize Firebase: {e}")
    # Don't silence the error; let it crash so we know what's wrong in the logs
    raise e

db = firestore.client()

# Email Configuration
app.config['MAIL_SERVER'] = os.getenv('MAIL_SERVER')
app.config['MAIL_PORT'] = int(os.getenv('MAIL_PORT', 587))
app.config['MAIL_USE_TLS'] = os.getenv('MAIL_USE_TLS', 'true').lower() in ['true', '1', 't']
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')
app.config['MAIL_DEFAULT_SENDER'] = os.getenv('MAIL_USERNAME')

# Gemini API Configuration
GEMINI_API_KEY = os.getenv('GEMINI_API_KEY')
if GEMINI_API_KEY:
    genai.configure(api_key=GEMINI_API_KEY)

# ==============================================================================
# 2. EXTENSION INITIALIZATION
# ==============================================================================

csrf = CSRFProtect(app)
mail = Mail(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# ==============================================================================
# 3. DATABASE MODELS
# ==============================================================================

# This class is now a simple "Plain Old Python Object"
# It's not tied to a database, we just use it to hold data
class User(UserMixin):
    def __init__(self, id, username, email, password_hash):
        self.id = id
        self.username = username
        self.email = email
        self.password_hash = password_hash

    # We can keep these helper methods!
    def set_password(self, password):
        self.password_hash = generate_password_hash(password, method='pbkdf2:sha256')

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def get_reset_token(self, expires_sec=3600):
        s = URLSafeTimedSerializer(app.config['SECRET_KEY'])
        return s.dumps(self.id, salt='password-reset-salt')

    @staticmethod
    def verify_reset_token(token):
        s = URLSafeTimedSerializer(app.config['SECRET_KEY'])
        try:
            user_id = s.loads(token, salt='password-reset-salt', max_age=3600)
        except (SignatureExpired, BadTimeSignature):
            return None
        return user_id


# ==============================================================================
# 4. FLASK-LOGIN USER LOADER
# ==============================================================================

@login_manager.user_loader
def load_user(user_id):
    try:
        doc = db.collection('users').document(user_id).get()
        if not doc.exists:
            return None

        data = doc.to_dict()
        return User(
            id=doc.id,
            username=data.get('username'),
            email=data.get('email'),
            password_hash=data.get('password_hash')
        )
    except Exception as e:
        app.logger.error(f"Error loading user {user_id}: {e}")
        return None

# ==============================================================================
# 5. HELPER FUNCTIONS
# ==============================================================================
def extract_text_from_pdf(pdf_stream):
    """Extracts text from a PDF file stream."""
    start_time = time.time()
    text = ""
    try:
        with pdfplumber.open(pdf_stream) as pdf:
            for page in pdf.pages:
                page_text = page.extract_text()
                if page_text:
                    text += page_text + "\n"
        duration = time.time() - start_time
        app.logger.info(f"PDF extraction of {len(pdf.pages)} pages took {duration:.2f}s.")
        return text
    except Exception as e:
        app.logger.error(f"Error extracting text from PDF: {e}")
        return None

def generate_questions(material, configs, total_questions):
    start_time = time.time()
    
    # REMOVED the generation_config that was causing the 400 Error
    model = genai.GenerativeModel('gemini-2.5-flash') 
    
    breakdown_str = "\n".join([f"- {c['count']} {c['type']} question(s) targeting the Bloom's level: {c['bloom']}." for c in configs])

    prompt = f"""
    Generate exactly {total_questions} quiz questions based on the provided course material.
    You MUST adhere strictly to the following breakdown of question types and complexities:
    
    {breakdown_str}

    CRITICAL: You MUST respond with only a valid JSON array of objects. Do not include any introductory text, explanations, or markdown formatting (like ```json) outside of the JSON block.

    The JSON array should contain one object for each question. Each object must have the following keys:
    - "type": (String) The exact type of question ("True/False", "MCQ", "Fill-in-the-Blank", or "Short Answer").
    - "marks": (Integer) A suggested mark, from 1 to 5, based on complexity.
    - "bloom_level": (String) The specific Bloom's level you targeted based on the requested breakdown.
    - "text": (String) The content of the question itself.
    - "options": (Array of Strings) For "MCQ" questions, an array of four option strings. DO NOT include letter labels or prefixes (like A., B., a), b)) inside the option strings. Provide ONLY the answer text. For other types, this should be an empty array [].
    - "answer": (String) The correct answer. For MCQs, this should be the full text of the correct option.

    COURSE MATERIAL:
    "{material}"
    """
    try:
        response = model.generate_content(prompt)
        duration = time.time() - start_time
        app.logger.info(f"Gemini API call for question generation took {duration:.2f}s.")
        return response.text
    except Exception as e:
        app.logger.error(f"Gemini API Error: {str(e)}")
        raise Exception(f"An error occurred while generating questions. Error: {str(e)}")

def parse_questions(questions_text):
    """Parses a JSON string from Gemini into a list of question dictionaries."""
    try:
        # 1. Search for EITHER an array [...] OR an object {...}
        json_match = re.search(r'\[.*\]|\{.*\}', questions_text, re.DOTALL)
        if not json_match:
            app.logger.error("Could not find valid JSON in the AI response.")
            return []

        clean_json_str = json_match.group(0)

        # 2. CLEANUP: Strip out trailing commas before closing brackets to prevent "Expecting property name" errors
        clean_json_str = re.sub(r',\s*([\]}])', r'\1', clean_json_str)

        # 3. Parse the JSON (strict=False ignores bad hidden characters)
        parsed_data = json.loads(clean_json_str, strict=False)

        # 4. Handle the case where Gemini wraps the array in a dictionary (e.g. {"questions": [...]})
        if isinstance(parsed_data, dict):
            # Hunt for the list inside the dictionary
            found_list = False
            for key, value in parsed_data.items():
                if isinstance(value, list):
                    parsed_data = value
                    found_list = True
                    break
            # If it's just a single question object, wrap it in a list
            if not found_list:
                parsed_data = [parsed_data]

        # 5. Safely extract the questions
        questions_for_app = []
        for q in parsed_data:
            # Skip invalid entries if Gemini hallucinated strings instead of objects
            if not isinstance(q, dict):
                continue 

            options_data = q.get('options', [])
            if not isinstance(options_data, list):
                options_data = []

            new_q = {
                'type': q.get('type', 'Unknown'),
                'marks': q.get('marks', 1),
                'bloom_level': q.get('bloom_level', 'Understanding'),
                'text': q.get('text', 'Error: AI generated blank question.'),
                'answer': q.get('answer', ''),
                'options': '\n'.join([str(opt) for opt in options_data])
            }
            questions_for_app.append(new_q)

        return questions_for_app

    except Exception as e:
        app.logger.error(f"An error occurred in parse_questions: {e}\nRaw Response:\n{questions_text}")
        return []

def send_reset_email(user):
    token = user.get_reset_token()
    msg = Message('Password Reset Request', recipients=[user.email])
    msg.html = render_template('reset_password_email.html', user=user, token=token)
    try:
        mail.send(msg)
    except Exception as e:
        app.logger.error(f"Failed to send email: {e}")
        raise

def grade_short_answer_with_gemini(correct_answer, student_answer):
    """Sends answers to Gemini for grading and parses the JSON response."""
    start_time = time.time()
    try:
        model = genai.GenerativeModel('gemini-2.5-flash')
        prompt = f"""
        You are an expert examiner grading a short-answer question.
        Determine if the student's answer is semantically and factually correct based on the answer key.
        The student's answer can be a subset of the key, as long as it is accurate.

        **Answer Key:** "{correct_answer}"
        **Student's Answer:** "{student_answer}"

        Respond ONLY in JSON format with one key: "is_correct" (boolean).
        """

        response = model.generate_content(prompt)
        duration = time.time() - start_time
        app.logger.info(f"Gemini API call for short answer grading took {duration:.2f}s.")
        cleaned_response = response.text.strip().replace('```json', '').replace('```', '')
        grade_data = json.loads(cleaned_response)
        return grade_data.get('is_correct', False)

    except Exception as e:
        app.logger.error(f"Gemini API grading error: {str(e)}")
        return False

def create_overall_analysis_prompt(summary_data):
    """Creates a prompt for Gemini to analyze a whole class's performance."""
    return f"""
    You are an expert educational analyst. Your task is to analyze the overall performance of a group of students on a quiz and provide feedback to the teacher.
    Based on the following summary data, which highlights the most frequently incorrect answers, please provide a concise analysis.

    SUMMARY DATA:
    ---
    {summary_data}
    ---

    Your analysis should include three sections in markdown format:
    1.  **## Common Misconceptions**: Based on the questions that were frequently answered incorrectly, identify the key concepts or topics the students are struggling with as a group.
    2.  **## Potential Reasons**: Suggest possible reasons for these common struggles (e.g., the topic is complex, the question was ambiguous, more foundational knowledge is needed).
    3.  **## Recommendations for the Teacher**: Offer 2-3 specific, actionable recommendations for the whole class. For example, suggest a topic to re-teach, a different way to explain a concept, or a follow-up activity.

    Keep the tone professional, helpful, and focused on group-level educational improvement.
    """
# ==============================================================================
# 6. ROUTES AND VIEW FUNCTIONS
# ==============================================================================

# --- Request/Response Logging ---
@app.before_request
def before_request_logging():
    g.start_time = time.time()

@app.after_request
def after_request_logging(response):
    if 'start_time' in g:
        duration = time.time() - g.start_time
        app.logger.info(
            f"{request.method} {request.path} - Status: {response.status_code} - Duration: {duration:.4f}s"
        )
    return response

# --- Core Application Routes ---
@app.route('/')
@login_required
def index():
    search_query = request.args.get('search', '')
    # --- NEW: Capture the view_all parameter ---
    view_all = request.args.get('view_all') == 'true'

    # --- Query Firestore for the user's quizzes and order by creation date ---
    quizzes_query = db.collection('quizzes').where('user_id', '==', current_user.id)
    quizzes_query = quizzes_query.order_by('created_at', direction=firestore.Query.DESCENDING)

    # --- UPDATED: Limit to 5 only if there is NO search query AND view_all is not true ---
    if not search_query and not view_all:
        quizzes_query = quizzes_query.limit(5)

    all_quizzes = []

    try:
        for doc in quizzes_query.stream():
            quiz_data = doc.to_dict()
            quiz_data['public_id'] = doc.id

            # Explicitly count attempts for this quiz
            try:
                attempts_query = db.collection('quiz_attempts').where('quiz_id', '==', doc.id).count()
                count_result = attempts_query.get()
                quiz_data['attempts_count'] = count_result[0][0].value
            except Exception:
                quiz_data['attempts_count'] = 0

            all_quizzes.append(quiz_data)

    except google.api_core.exceptions.FailedPrecondition as e:
        # If the index fails (which it did in the previous step), redirect to the index creation link
        if "The query requires an index" in str(e):
            flash(f"Error: The dashboard sort query requires a Firebase Index. Please create it using the link provided in the error log. {str(e)}", 'danger')
        else:
            flash(f"An error occurred while loading the dashboard: {str(e)}", 'danger')
        return redirect(url_for('index'))


    # Filter in Python (only if a search query is present)
    if search_query:
        quizzes = [
            quiz for quiz in all_quizzes
            if search_query.lower() in quiz.get('title', '').lower()
        ]
        # Firestore sorting is applied above, so we keep the result as is.
    else:
        quizzes = all_quizzes

    # We skip the Python sort (quizzes.sort(key=...)) because Firestore did the work

    csrf_token = generate_csrf()
    return render_template('dashboard.html', quizzes=quizzes, search_query=search_query, csrf_token=csrf_token)

@app.errorhandler(413)
def request_entity_too_large(e):
    app.logger.warning(f"File upload too large: {request.content_length}")
    flash(f"File too large! Please upload a PDF smaller than {MAX_FILE_SIZE_MB}MB.", 'danger')
    return redirect(url_for('create_quiz')) # Or redirect to the page where the upload happened

@app.route('/create-quiz', methods=['GET', 'POST'])
@limiter.limit("10 per minute")
@login_required
def create_quiz():
    if request.method == 'POST':
        course_material = ""
        form_data = request.form

        if 'pdf_file' in request.files:
            pdf_file = request.files['pdf_file']
            if pdf_file.filename != '':
                if not pdf_file.filename.lower().endswith('.pdf'):
                    flash("Invalid file type. Please upload a PDF.", 'danger')
                    return redirect(url_for('index'))

                course_material = extract_text_from_pdf(pdf_file.stream)

                if course_material is None:
                    flash("Could not extract text from the PDF. The file might be corrupted or image-based.", 'danger')
                    return redirect(url_for('index'))

        if not course_material:
            course_material = form_data.get('course_material')

        if not course_material.strip():
            flash("No course material provided. Please paste text or upload a PDF.", 'danger')
            return redirect(url_for('index'))

        # --- NEW LOGIC: Parse the configuration table ---
        configs = []
        total_questions = 0

        # Map checkbox names to their specific input field names
        types_map = {
            'qtype_tf': ('True/False', 'count_tf', 'bloom_tf'),
            'qtype_mcq': ('MCQ', 'count_mcq', 'bloom_mcq'),
            'qtype_fib': ('Fill-in-the-Blank', 'count_fib', 'bloom_fib'),
            'qtype_sa': ('Short Answer', 'count_sa', 'bloom_sa')
        }

        for cb_name, (display_name, count_name, bloom_name) in types_map.items():
            if form_data.get(cb_name): 
                try:
                    count = int(form_data.get(count_name, 0))
                except ValueError:
                    count = 0
                
                if count > 0:
                    bloom = form_data.get(bloom_name)
                    configs.append({'type': display_name, 'count': count, 'bloom': bloom})
                    total_questions += count

        # This is the NEW validation that replaces the old one!
        if total_questions == 0:
            flash("Please select at least one question type and ensure its count is greater than 0.", 'danger')
            return redirect(url_for('index'))

        sanitized_course_material = clean(course_material)
        try:
            # Pass the structured configs and total sum to the new function
            questions_text = generate_questions(sanitized_course_material, configs, total_questions)
        except Exception as e:
            flash(str(e), 'danger')
            return redirect(url_for('index'))

        # --- NEW: Cleaner parsing block ---
        questions_list_for_display = parse_questions(questions_text)

        if not questions_list_for_display:
            flash('The AI was unable to generate valid questions. Please try again or simplify your request.', 'danger')
            return redirect(url_for('index'))

        question_type_order = ["True/False", "MCQ", "Fill-in-the-Blank", "Short Answer"]
        sorted_questions = sorted(
            questions_list_for_display,
            key=lambda q: question_type_order.index(q.get('type', '')) if q.get('type') in question_type_order else len(question_type_order)
        )

        # --- THIS IS THE KEY CHANGE ---
        # Save the parsed, sorted list of question dicts to the session
        session['generated_questions'] = sorted_questions

        csrf_token = generate_csrf()

        return render_template(
            'results.html',
            questions_list=sorted_questions,
            # We no longer need to pass the raw text in the form
            csrf_token=csrf_token
        )

    csrf_token = generate_csrf()
    return render_template('index.html', csrf_token=csrf_token)

@app.route('/save-questions', methods=['POST'])
@login_required
def save_questions():
    # --- Retrieve the parsed questions from the session ---
    parsed_questions = session.pop('generated_questions', None)

    if not parsed_questions:
        flash("Your session expired or no questions were found. Please generate questions again.", 'danger')
        app.logger.warning(f"User '{current_user.username}' tried to save questions, but session data was missing.")
        return redirect(url_for('index'))

    quiz_title = request.form.get('quiz_title', 'Unnamed Quiz')

    try:
        # --- Create the main Quiz document ---
        new_quiz_data = {
            'title': quiz_title,
            'user_id': current_user.id,
            'created_at': firestore.SERVER_TIMESTAMP, # Use server's timestamp
            'is_active': True,
            'opens_at': None,
            'closes_at': None,
            'time_limit': None,
            'analysis_text': None
        }

        # Add the new quiz to the 'quizzes' collection
        # This returns a tuple (timestamp, DocumentReference)
        quiz_ref = db.collection('quizzes').add(new_quiz_data)[1]

        # --- Create a batch write for all the questions ---
        batch = db.batch()

        # Get the subcollection reference
        questions_collection_ref = quiz_ref.collection('questions')

        for q_data in parsed_questions:
            # Create a new document reference in the 'questions' subcollection
            new_q_ref = questions_collection_ref.document()

            # Prepare the question data
            # The 'options' field is already a newline-separated string from parse_questions
            question_doc_data = {
                'content': q_data.get('text'),
                'question_type': q_data.get('type'),
                'bloom_level': q_data.get('bloom_level'),
                'answer': q_data.get('answer'),
                'marks': q_data.get('marks'),
                'options': q_data.get('options', '')
            }
            batch.set(new_q_ref, question_doc_data)

        # Commit the batch of new questions
        batch.commit()

        app.logger.info(f"User '{current_user.username}' saved a new quiz titled '{quiz_title}'. Firestore ID: {quiz_ref.id}")
        flash('Quiz saved successfully!', 'success')
        return redirect(url_for('view_quiz', public_id=quiz_ref.id))

    except Exception as e:
        app.logger.error(f"Database error while saving quiz for user '{current_user.username}': {str(e)}")
        flash(f"An error occurred while saving your quiz. Error: {str(e)}", 'danger')
        return redirect(url_for('index'))

# --- Authentication and User Management Routes ---
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')

        if not request.form.get('agree_terms'):
            flash('You must agree to the Terms of Use and Privacy Policy to create an account.', 'danger')
            return redirect(url_for('register'))

        # Check if username exists
        users_ref = db.collection('users').where('username', '==', username).limit(1)

        # ✅ FIX 1: Convert the stream to a list before checking length
        if len(list(users_ref.stream())) > 0:
            flash('Username already exists. Please choose a different one.', 'danger')
            return redirect(url_for('register'))

        # Check if email exists
        users_ref_email = db.collection('users').where('email', '==', email).limit(1)

        # ✅ FIX 2: Convert the stream to a list before checking length
        if len(list(users_ref_email.stream())) > 0:
            flash('Email address is already registered.', 'danger')
            return redirect(url_for('register'))

        if password != confirm_password:
            flash('Passwords do not match. Please try again.', 'danger')
            return redirect(url_for('register'))

        if len(password) < 8:
            flash('Password must be at least 8 characters long.', 'danger')
            return redirect(url_for('register'))

        # Create a new user object (but not from a model)
        new_user_data = {
            'username': username,
            'email': email,
            'password_hash': generate_password_hash(password, method='pbkdf2:sha256')
        }

        # Add the new user to the 'users' collection
        # Firestore will auto-generate an ID
        doc_ref = db.collection('users').add(new_user_data)

        app.logger.info(f"New user registered: '{username}'")
        flash('Account created successfully! You are now logged in.', 'success')

        # Manually create a User object to log them in
        # doc_ref[1].id is the ID of the new document
        user_obj = User(id=doc_ref[1].id, **new_user_data)
        login_user(user_obj)
        return redirect(url_for('index'))

    csrf_token = generate_csrf()
    return render_template('register.html', csrf_token=csrf_token)

## --- Login Route ---
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        # --- Query Firestore for the user ---
        users_ref = db.collection('users').where('username', '==', username).limit(1)
        user_docs = list(users_ref.stream())

        user_obj = None

        if user_docs:
            doc = user_docs[0]
            user_data = doc.to_dict()
            # Create our User object to hold the data
            user_obj = User(
                id=doc.id,
                username=user_data.get('username'),
                email=user_data.get('email'),
                password_hash=user_data.get('password_hash')
            )

        # Check if user object was created and if password is correct
        if user_obj is None or not user_obj.check_password(password):
            app.logger.warning(f"Failed login attempt for username '{username}' from IP {request.remote_addr}.")
            flash('Invalid username or password.', 'danger')
            return redirect(url_for('login'))

        login_user(user_obj)
        app.logger.info(f"User '{username}' logged in successfully from IP {request.remote_addr}.")
        return redirect(url_for('index'))

    csrf_token = generate_csrf()
    return render_template('login.html', csrf_token=csrf_token)

@app.route('/logout')
@login_required
def logout():
    app.logger.info(f"User '{current_user.username}' logged out.")
    logout_user()
    return redirect(url_for('login'))

@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form.get('email')

        # --- Query Firestore for the user's email ---
        users_ref = db.collection('users').where('email', '==', email).limit(1)
        user_docs = list(users_ref.stream())

        if user_docs:
            doc = user_docs[0]
            user_data = doc.to_dict()
            # Create a User object to use the .get_reset_token() method
            user_obj = User(
                id=doc.id,
                username=user_data.get('username'),
                email=user_data.get('email'),
                password_hash=user_data.get('password_hash')
            )
            send_reset_email(user_obj)

        app.logger.info(f"Password reset requested for email '{email}' from IP {request.remote_addr}.")
        flash('If an account with that email exists, a password reset link has been sent.', 'success')
        return redirect(url_for('login'))

    csrf_token = generate_csrf()
    return render_template('forgot_password.html', csrf_token=csrf_token)

@app.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    user_id = User.verify_reset_token(token)

    if not user_id:
        flash('That is an invalid or expired token.', 'danger')
        return redirect(url_for('forgot_password'))

    # Get the user document reference from Firestore
    user_ref = db.collection('users').document(user_id)
    doc = user_ref.get()

    if not doc.exists:
        flash('User not found.', 'danger')
        return redirect(url_for('forgot_password'))

    if request.method == 'POST':
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')

        if password != confirm_password:
            flash('Passwords do not match.', 'danger')
            return redirect(url_for('reset_password', token=token))

        if len(password) < 8:
            flash('Password must be at least 8 characters long.', 'danger')
            return redirect(url_for('reset_password', token=token))

        # --- Update the password hash in Firestore ---
        new_password_hash = generate_password_hash(password, method='pbkdf2:sha256')
        user_ref.update({'password_hash': new_password_hash})

        app.logger.info(f"Password reset successful for user (ID: {user_id}) from IP {request.remote_addr}.")
        flash('Your password has been updated! You are now able to log in.', 'success')
        return redirect(url_for('login'))

    csrf_token = generate_csrf()
    return render_template('reset_password.html', token=token, csrf_token=csrf_token)

@app.route('/change-password', methods=['GET', 'POST'])
@login_required
def change_password():
    if request.method == 'POST':
        old_password = request.form.get('old_password')
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')

        if not current_user.check_password(old_password):
            app.logger.warning(f"User '{current_user.username}' failed password change due to incorrect old password.")
            flash('Your old password was incorrect. Please try again.', 'danger')
            return redirect(url_for('change_password'))

        if new_password != confirm_password:
            flash('The new passwords do not match.', 'danger')
            return redirect(url_for('change_password'))

        if len(new_password) < 8:
            flash('Your new password must be at least 8 characters long.', 'danger')
            return redirect(url_for('change_password'))

        # --- Update the password hash in Firestore ---
        user_ref = db.collection('users').document(current_user.id)
        new_password_hash = generate_password_hash(new_password, method='pbkdf2:sha256')
        user_ref.update({'password_hash': new_password_hash})

        app.logger.info(f"User '{current_user.username}' successfully changed their password.")
        flash('Your password has been updated successfully!', 'success')
        return redirect(url_for('index'))

    csrf_token = generate_csrf()
    return render_template('change_password.html', csrf_token=csrf_token)

# --- Quiz Interaction and Management Routes ---

@app.route('/quiz/<public_id>')
@login_required
def view_quiz(public_id):
    try:
        # --- Fetch the quiz document ---
        quiz_ref = db.collection('quizzes').document(public_id)
        quiz_doc = quiz_ref.get()

        if not quiz_doc.exists:
            app.logger.warning(f"User '{current_user.username}' tried to access non-existent quiz {public_id}")
            return "Quiz not found", 404

        quiz_data = quiz_doc.to_dict()

        # --- Check if the user is the owner ---
        if quiz_data.get('user_id') != current_user.id:
            app.logger.warning(f"User '{current_user.username}' tried to access quiz {public_id} owned by another user.")
            flash("You are not authorized to view this quiz.", 'danger')
            return redirect(url_for('index'))

        # --- Fetch the questions from the subcollection ---
        questions_ref = quiz_ref.collection('questions')
        questions = []
        for q_doc in questions_ref.stream():
            q_data = q_doc.to_dict()
            q_data['id'] = q_doc.id  # Store the document ID
            questions.append(q_data)

        question_type_order = ["True/False", "MCQ", "Fill-in-the-Blank", "Short Answer"]
        sorted_questions = sorted(
            questions,
            key=lambda q: question_type_order.index(q.get('question_type', '')) if q.get('question_type') in question_type_order else len(question_type_order)
        )

        # Add the public_id to the quiz data for the template
        quiz_data['public_id'] = public_id

        return render_template('quiz.html', quiz=quiz_data, questions=sorted_questions)

    except Exception as e:
        app.logger.error(f"Error fetching quiz {public_id}: {str(e)}")
        flash("An error occurred while trying to load your quiz.", 'danger')
        return redirect(url_for('index'))

@app.route('/quiz/<public_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_quiz(public_id):
    # --- Get the quiz document reference ---
    quiz_ref = db.collection('quizzes').document(public_id)
    quiz_doc = quiz_ref.get()

    if not quiz_doc.exists:
        return "Quiz not found", 404

    quiz_data = quiz_doc.to_dict()

    # --- Authorization check ---
    if quiz_data.get('user_id') != current_user.id:
        flash("You are not authorized to edit this quiz.", 'danger')
        return redirect(url_for('index'))

    # Add public_id for template links
    quiz_data['public_id'] = public_id

    # --- Handle POST (Save) Request ---
    if request.method == 'POST':
        try:
            # --- 1. Convert form datetimes from MYT to UTC ---
            opens_at_utc = None
            opens_at_str = request.form.get('opens_at')
            if opens_at_str:
                naive_dt = datetime.fromisoformat(opens_at_str)
                local_dt = MYT.localize(naive_dt)
                opens_at_utc = local_dt.astimezone(pytz.utc)

            closes_at_utc = None
            closes_at_str = request.form.get('closes_at')
            if closes_at_str:
                naive_dt = datetime.fromisoformat(closes_at_str)
                local_dt = MYT.localize(naive_dt)
                closes_at_utc = local_dt.astimezone(pytz.utc)

            # --- 2. Update the main quiz document ---
            quiz_ref.update({
                'title': request.form.get('quiz_title'),
                'opens_at': opens_at_utc,  # Store the UTC datetime object
                'closes_at': closes_at_utc, # Store the UTC datetime object
                'time_limit': int(request.form.get('time_limit')) if request.form.get('time_limit') else None,
                'is_active': True if (opens_at_str or closes_at_str) else quiz_data.get('is_active', True)
            })

            # --- 3. Use a batch to update all questions ---
            batch = db.batch()
            question_ids = request.form.getlist('question_id')

            for q_id in question_ids:
                q_ref = quiz_ref.collection('questions').document(q_id)
                batch.update(q_ref, {
                    'content': request.form.get(f'question_text_{q_id}'),
                    'answer': request.form.get(f'answer_{q_id}'),
                    'options': request.form.get(f'options_{q_id}', '')
                })

            batch.commit()

            app.logger.info(f"User '{current_user.username}' edited quiz '{public_id}'.")
            flash('Quiz updated successfully!', 'success')
            return redirect(url_for('view_quiz', public_id=public_id))

        except Exception as e:
            app.logger.error(f"Error updating quiz {public_id}: {str(e)}")
            flash(f'An error occurred while updating the quiz: {str(e)}', 'danger')
            return redirect(url_for('edit_quiz', public_id=public_id))

    # --- Handle GET (Load) Request ---
    try:
        questions_ref = quiz_ref.collection('questions')
        questions = []
        for q_doc in questions_ref.stream():
            q_data = q_doc.to_dict()
            q_data['id'] = q_doc.id  # This ID is crucial for the POST form
            questions.append(q_data)

        question_type_order = ["MCQ", "True/False", "Fill-in-the-Blank", "Short Answer"]
        sorted_questions = sorted(
            questions,
            key=lambda q: question_type_order.index(q.get('question_type', '')) if q.get('question_type') in question_type_order else len(question_type_order)
        )

        csrf_token = generate_csrf()
        return render_template('edit_quiz.html', quiz=quiz_data, questions=sorted_questions, csrf_token=csrf_token)

    except Exception as e:
        app.logger.error(f"Error fetching quiz for edit {public_id}: {str(e)}")
        flash("An error occurred while loading the quiz for editing.", 'danger')
        return redirect(url_for('index'))


@app.route('/quiz/<public_id>/take', methods=['GET'])
def take_quiz(public_id):
    try:
        quiz_ref = db.collection('quizzes').document(public_id)
        quiz_doc = quiz_ref.get()

        if not quiz_doc.exists:
            return "Quiz not found", 404

        quiz_data = quiz_doc.to_dict()
        quiz_data['public_id'] = public_id

        # --- Timezone-Aware Availability Check ---
        now_utc = datetime.now(pytz.utc)
        opens_at = quiz_data.get('opens_at')
        closes_at = quiz_data.get('closes_at')

        # Ensure datetimes from Firestore are timezone-aware
        if opens_at and opens_at.tzinfo is None:
            opens_at = pytz.utc.localize(opens_at)
        if closes_at and closes_at.tzinfo is None:
            closes_at = pytz.utc.localize(closes_at)

        message = None
        if not quiz_data.get('is_active', True):
            message = "This quiz has been manually closed by the instructor."
        elif opens_at and now_utc < opens_at:
            opens_at_myt = opens_at.astimezone(MYT)
            message = f"This quiz is not yet open. It will be available on {opens_at_myt.strftime('%B %d, %Y at %I:%M %p')}."
        elif closes_at and now_utc > closes_at:
            message = "This quiz has closed and is no longer accepting submissions."

        if message:
            app.logger.warning(f"Attempt to access unavailable quiz '{public_id}'. Reason: {message}")
            return render_template('quiz_unavailable.html', quiz=quiz_data, message=message), 403

        # --- Fetch Questions ---
        questions_ref = quiz_ref.collection('questions')
        questions = []
        for q_doc in questions_ref.stream():
            q_data = q_doc.to_dict()
            q_data['id'] = q_doc.id
            questions.append(q_data)

        question_type_order = ["True/False", "MCQ", "Fill-in-the-Blank", "Short Answer"]
        sorted_questions = sorted(
            questions,
            key=lambda q: question_type_order.index(q.get('question_type', '').strip()) if q.get('question_type', '').strip() in question_type_order else len(question_type_order)
        )

        # --- Pass Timer Data to Template ---
        closes_at_iso = closes_at.isoformat() if closes_at else None
        csrf_token = generate_csrf()

        return render_template(
            'take_quiz.html',
            quiz=quiz_data,
            questions=sorted_questions,
            time_limit_minutes=quiz_data.get('time_limit'),
            closes_at_iso=closes_at_iso,
            csrf_token=csrf_token
        )
    except Exception as e:
        app.logger.error(f"Error loading quiz for taking {public_id}: {str(e)}")
        flash("An error occurred while loading the quiz.", 'danger')
        return redirect(url_for('index'))

@app.route('/quiz/<public_id>/submit', methods=['POST'])
def submit_quiz(public_id):
    try:
        quiz_ref = db.collection('quizzes').document(public_id)
        quiz_doc = quiz_ref.get()

        if not quiz_doc.exists:
            return "Quiz not found", 404

        quiz_data = quiz_doc.to_dict()
        now_utc = datetime.now(pytz.utc)

        # --- Check for Late Submissions ---
        closes_at = quiz_data.get('closes_at')
        if closes_at and closes_at.tzinfo is None:
            closes_at = pytz.utc.localize(closes_at)

        if closes_at and now_utc > closes_at:
            app.logger.warning(f"Late submission attempt for quiz '{public_id}'.")
            message = "The deadline for this quiz has passed. Your submission was not accepted."
            return render_template('quiz_unavailable.html', quiz=quiz_data, message=message), 403

        # --- Fetch all questions for grading ---
        questions_ref = quiz_ref.collection('questions')
        questions_list = []
        for q_doc in questions_ref.stream():
            q_data = q_doc.to_dict()
            q_data['id'] = q_doc.id
            questions_list.append(q_data)

        # Create a quick-lookup dict by question ID
        # --- NEW: Sort the questions exactly how they appear on the quiz page ---
        question_type_order = ["True/False", "MCQ", "Fill-in-the-Blank", "Short Answer"]
        sorted_questions = sorted(
            questions_list,
            key=lambda q: question_type_order.index(q.get('question_type', '').strip()) if q.get('question_type', '').strip() in question_type_order else len(question_type_order)
        )

        score = 0
        total_score = 0
        results_for_template = []
        student_answers_for_db = []

        student_name = request.form.get('student_name', 'Anonymous')

        # --- Grade the submission ---
        # Loop through the sorted list instead of the scrambled dictionary
        for q_data in sorted_questions:
            q_id = q_data['id']  # Extract the ID from the sorted data
            
            question_marks = q_data.get('marks', 0)
            total_score += question_marks

            student_answer_text = request.form.get(f'question_{q_id}', 'Not Answered')
            correct_answer_text = q_data.get('answer', '').strip()

            is_correct = False
            if q_data['question_type'] in ['MCQ', 'True/False', 'Fill-in-the-Blank']:
                
                # 1. Normalize both answers first (handles "five" vs "5")
                norm_student = normalize_answer(student_answer_text)
                norm_correct = normalize_answer(correct_answer_text)
                
                # 2. Check for exact match (fastest)
                if norm_student == norm_correct:
                    is_correct = True
                else:
                    # 3. If not exact, check fuzzy match (handles typos like "prediciton")
                    # fuzz.ratio returns a score from 0 to 100
                    similarity_score = fuzz.ratio(norm_student, norm_correct)
                    
                    # You can tweak this threshold. 85 is usually safe for catching typos 
                    # without accepting entirely wrong words.
                    if similarity_score >= 85:
                        is_correct = True

            elif q_data['question_type'] == 'Short Answer':
                if student_answer_text != 'Not Answered':
                    is_correct = grade_short_answer_with_gemini(correct_answer_text, student_answer_text)

            if is_correct:
                score += question_marks
                marks_earned = question_marks  # <-- Make sure this line exists
            else:
                marks_earned = 0               # <-- Make sure this line exists

            # For display on the results page
            results_for_template.append({
                'question': q_data,
                'student_answer': student_answer_text,
                'correct_answer': correct_answer_text,
                'is_correct': is_correct,
                'marks_earned': marks_earned   # <-- Check the spelling here!
            })

            # For storing in the 'student_answers' subcollection
            student_answers_for_db.append({
                'question_id': q_id,
                'question_content': q_data.get('content'),
                'answer_text': student_answer_text,
                'is_correct': is_correct
            })

        percentage = round((score / total_score) * 100, 2) if total_score > 0 else 0

        # --- Save the attempt to Firestore ---

        # 1. Create the main QuizAttempt document
        new_attempt_data = {
            'quiz_id': public_id,
            'quiz_title': quiz_data.get('title'),
            'student_name': student_name,
            'score': score,
            'total_score': total_score,
            'percentage': percentage,
            'timestamp': firestore.SERVER_TIMESTAMP
        }
        attempt_ref = db.collection('quiz_attempts').add(new_attempt_data)[1]

        # 2. Batch write all student answers to a subcollection
        batch = db.batch()
        answers_collection_ref = attempt_ref.collection('student_answers')
        for answer_data in student_answers_for_db:
            new_answer_ref = answers_collection_ref.document()
            batch.set(new_answer_ref, answer_data)
        batch.commit()

        app.logger.info(f"Quiz '{public_id}' submitted by '{student_name}'. Score: {score}/{total_score}.")
        return render_template('quiz_results.html',
                               score=score,
                               total_score=total_score,
                               percentage=percentage,
                               quiz=quiz_data,
                               results=results_for_template)
    except Exception as e:
        app.logger.error(f"Error submitting quiz {public_id}: {str(e)}")
        return render_template('error.html', message=f"An error occurred while submitting your quiz. Error: {str(e)}")

@app.route('/quiz/<public_id>/attempts')
@login_required
def view_attempts(public_id):
    try:
        # --- 1. Get and Authorize the Quiz ---
        quiz_ref = db.collection('quizzes').document(public_id)
        quiz_doc = quiz_ref.get()

        if not quiz_doc.exists:
            flash('Quiz not found.', 'danger')
            return redirect(url_for('index'))

        quiz_data = quiz_doc.to_dict()

        if quiz_data.get('user_id') != current_user.id:
            flash('You are not authorized to view these attempts.', 'danger')
            return redirect(url_for('index'))

        quiz_data['public_id'] = public_id

        # --- 2. Get Filters from URL ---
        student_name_filter = request.args.get('student_name', '')
        date_filter_str = request.args.get('submission_date', '')

        # --- 3. Query Firestore for Attempts ---
        attempts_ref = db.collection('quiz_attempts').where('quiz_id', '==', public_id)

        # Base query ordering by timestamp
        attempts_query = attempts_ref.order_by('timestamp', direction=firestore.Query.DESCENDING)

        all_attempts = []
        for doc in attempts_query.stream():
            attempt_data = doc.to_dict()
            attempt_data['id'] = doc.id
            all_attempts.append(attempt_data)

        # --- 4. Apply Filters in Python ---
        filtered_attempts = all_attempts

        if student_name_filter:
            filtered_attempts = [
                a for a in filtered_attempts
                if student_name_filter.lower() in a.get('student_name', '').lower()
            ]

        if date_filter_str:
            try:
                submission_date = datetime.strptime(date_filter_str, '%Y-%m-%d').date()
                filtered_attempts = [
                    a for a in filtered_attempts
                    if a.get('timestamp') and a['timestamp'].date() == submission_date
                ]
            except ValueError:
                flash('Invalid date format. Please use YYYY-MM-DD.', 'danger')

        return render_template(
            'quiz_attempts.html',
            quiz=quiz_data,
            attempts=filtered_attempts,
            student_name_filter=student_name_filter,
            date_filter=date_filter_str
        )
    except Exception as e:
        app.logger.error(f"Error viewing attempts for quiz {public_id}: {str(e)}")
        flash('An error occurred while loading the quiz attempts.', 'danger')
        return redirect(url_for('index'))

@app.route('/quiz/<public_id>/delete', methods=['POST'])
@login_required
def delete_quiz(public_id):
    try:
        quiz_ref = db.collection('quizzes').document(public_id)
        quiz_doc = quiz_ref.get()

        if not quiz_doc.exists:
            flash('Quiz not found.', 'danger')
            return redirect(url_for('index'))

        # --- Authorization Check ---
        if quiz_doc.to_dict().get('user_id') != current_user.id:
            flash('You are not authorized to delete this quiz.', 'danger')
            return redirect(url_for('index'))

        # --- Delete the 'questions' subcollection ---
        # This must be done first.
        questions_ref = quiz_ref.collection('questions')
        for q_doc in questions_ref.stream():
            q_doc.reference.delete()

        # --- Now, delete the main quiz document ---
        quiz_ref.delete()

        app.logger.info(f"User '{current_user.username}' deleted quiz '{public_id}'.")
        flash('Quiz and all its questions deleted successfully.', 'success')
        return redirect(url_for('index'))

    except Exception as e:
        app.logger.error(f"Error deleting quiz {public_id}: {str(e)}")
        flash(f'An error occurred while deleting the quiz: {str(e)}', 'danger')
        return redirect(url_for('index'))

@app.route('/quiz/<public_id>/overall_analysis')
@limiter.limit("3 per minute")
@login_required
def overall_analysis(public_id):
    try:
        # --- 1. Get and Authorize the Quiz ---
        quiz_ref = db.collection('quizzes').document(public_id)
        quiz_doc = quiz_ref.get()

        if not quiz_doc.exists:
            flash('Quiz not found.', 'danger')
            return redirect(url_for('index'))

        quiz_data = quiz_doc.to_dict()

        if quiz_data.get('user_id') != current_user.id:
            flash('You are not authorized to view this analysis.', 'danger')
            return redirect(url_for('index'))

        quiz_data['public_id'] = public_id
        force_reanalyze = request.args.get('force_reanalyze', 'false').lower() == 'true'

        # --- 2. Check for Cached Analysis ---
        if quiz_data.get('analysis_text') and not force_reanalyze:
            app.logger.info(f"Serving cached analysis for quiz {public_id}")
            return render_template('quiz_overall_analysis.html', quiz=quiz_data, analysis_html=quiz_data['analysis_text'])

        # --- 3. Fetch All Attempts for this Quiz ---
        attempts_ref = db.collection('quiz_attempts').where('quiz_id', '==', public_id)
        attempts_docs = list(attempts_ref.stream())

        if not attempts_docs:
            return render_template('error.html', message="There are no attempts for this quiz yet, so an analysis cannot be generated.")

        # --- 4. Tally Incorrect Answers ---
        incorrect_counts = defaultdict(int)
        for attempt_doc in attempts_docs:
            # Get the answers from the subcollection of this attempt
            answers_ref = attempt_doc.reference.collection('student_answers')
            for answer_doc in answers_ref.stream():
                answer_data = answer_doc.to_dict()
                if not answer_data.get('is_correct'):
                    incorrect_counts[answer_data.get('question_id')] += 1

        if not incorrect_counts:
             analysis_html = "## Analysis\n\nAll submitted answers were correct. Great job!"
             quiz_ref.update({'analysis_text': analysis_html})
             return render_template('quiz_overall_analysis.html', quiz=quiz_data, analysis_html=analysis_html)

        # --- 5. Prepare Data for Gemini ---

        # Fetch the original question content
        questions_ref = quiz_ref.collection('questions')
        questions_dict = {doc.id: doc.to_dict() for doc in questions_ref.stream()}

        analysis_data_string = f"This quiz has been taken {len(attempts_docs)} time(s).\n\n"
        analysis_data_string += "Here is a summary of the most frequently missed questions:\n"

        sorted_incorrect = sorted(incorrect_counts.items(), key=lambda item: item[1], reverse=True)

        for question_id, count in sorted_incorrect:
            if question_id in questions_dict:
                question = questions_dict[question_id]
                analysis_data_string += f"- Question: \"{question.get('content')}\" was answered incorrectly {count} time(s).\n"
                analysis_data_string += f"  Correct Answer: \"{question.get('answer')}\"\n"

        # --- 6. Call Gemini and Save Analysis ---
        start_time = time.time()
        model = genai.GenerativeModel('gemini-2.5-flash')
        prompt = create_overall_analysis_prompt(analysis_data_string)
        response = model.generate_content(prompt)
        duration = time.time() - start_time
        app.logger.info(f"Gemini API call for overall analysis of quiz '{public_id}' took {duration:.2f}s.")

        analysis_html = response.text

        # Save the analysis to the main quiz document for caching
        quiz_ref.update({'analysis_text': analysis_html})

        return render_template('quiz_overall_analysis.html', quiz=quiz_data, analysis_html=analysis_html)

    except Exception as e:
        app.logger.error(f"Error generating overall analysis for quiz {public_id}: {str(e)}")
        return render_template('error.html', message=f"An error occurred while generating the overall analysis. Error: {str(e)}")

# --- Static Pages and Utility Routes ---

@app.route('/terms')
def terms():
    """Renders the Terms of Use page."""
    return render_template('terms.html')

@app.route('/privacy')
def privacy():
    """Renders the Privacy Policy page."""
    return render_template('privacy.html')

@app.route('/quiz/<public_id>/qr')
def quiz_qr_code(public_id):
    """Generates a QR code for the quiz link."""
    quiz_url = url_for('take_quiz', public_id=public_id, _external=True)
    img = qrcode.make(quiz_url)
    buf = io.BytesIO()
    img.save(buf)
    buf.seek(0)
    return send_file(buf, mimetype='image/png')

@app.template_filter('myt')
def to_myt_filter(utc_dt):
    """Converts a UTC datetime object to a formatted MYT string."""
    if not utc_dt:
        return ""
    # Ensure the datetime is timezone-aware before converting
    if utc_dt.tzinfo is None:
        utc_dt = pytz.utc.localize(utc_dt)
    return utc_dt.astimezone(MYT).strftime('%Y-%m-%dT%H:%M')

# ==============================================================================
# 7. ERROR HANDLERS AND OTHER APP-WIDE CONFIGURATIONS
# ==============================================================================

@app.errorhandler(404)
def page_not_found(e):
    app.logger.warning(f"404 Not Found error for path: {request.path}")
    return render_template('error.html', message="Sorry, the page you are looking for does not exist."), 404

@app.context_processor
def inject_now():
    return {'now': datetime.now().strftime('%Y-%m-%d %H:%M')}

@app.template_filter('markdown')
def markdown_filter(s):
    return Markup(markdown.markdown(s))

# ==============================================================================
# 8. MAIN EXECUTION BLOCK
# ==============================================================================

if __name__ == '__main__':
    app.run(debug=True, use_reloader=False)