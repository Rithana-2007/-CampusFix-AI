from flask import (
    Flask, render_template, request, redirect,
    url_for, session, flash
)
import os
import csv
import sqlite3
from datetime import datetime
from functools import wraps
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash


# -------------------- APP CONFIGURATION --------------------

app = Flask(__name__)

app.secret_key = os.environ.get(
    "SECRET_KEY", "campusfix-development-key-change-before-deployment"
)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

UPLOAD_FOLDER = os.path.join(BASE_DIR, "static", "uploads")
CSV_FILE = os.path.join(BASE_DIR, "complaints.csv")
DATABASE = os.path.join(BASE_DIR, "users.db")

ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "gif", "webp"}

os.makedirs(UPLOAD_FOLDER, exist_ok=True)

CSV_FIELDS = [
    "Complaint ID",
    "Student Name",
    "Student Email",
    "Location",
    "Fault Type",
    "Description",
    "Priority",
    "Department",
    "Photo",
    "Status",
]


# -------------------- DATABASE SETUP --------------------

def setup_database():
    """Create the users database and default administrator."""

    with sqlite3.connect(DATABASE) as connection:
        connection.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                email TEXT NOT NULL UNIQUE,
                password TEXT NOT NULL,
                role TEXT NOT NULL DEFAULT 'student'
            )
        """)

        admin_email = os.environ.get(
            "ADMIN_EMAIL", "admin@campusfix.local"
        ).strip().lower()

        admin_password = os.environ.get(
            "ADMIN_PASSWORD", "Admin@123"
        )

        existing_admin = connection.execute(
            "SELECT id FROM users WHERE email = ?",
            (admin_email,)
        ).fetchone()

        if not existing_admin:
            connection.execute("""
                INSERT INTO users (name, email, password, role)
                VALUES (?, ?, ?, ?)
            """, (
                "Administrator",
                admin_email,
                generate_password_hash(admin_password),
                "admin",
            ))


# -------------------- COMPLAINT CSV SETUP --------------------

def setup_complaints_csv():
    """Create the complaints CSV if it does not exist."""

    if not os.path.exists(CSV_FILE) or os.path.getsize(CSV_FILE) == 0:
        with open(CSV_FILE, "w", newline="", encoding="utf-8") as file:
            writer = csv.DictWriter(file, fieldnames=CSV_FIELDS)
            writer.writeheader()
        return

    # Preserve existing complaint data and add any missing columns.
    with open(CSV_FILE, "r", newline="", encoding="utf-8-sig") as file:
        reader = csv.DictReader(file)
        old_fields = reader.fieldnames or []
        rows = list(reader)

    if old_fields != CSV_FIELDS:
        with open(CSV_FILE, "w", newline="", encoding="utf-8") as file:
            writer = csv.DictWriter(
                file,
                fieldnames=CSV_FIELDS,
                extrasaction="ignore"
            )
            writer.writeheader()

            for row in rows:
                cleaned_row = {
                    field: row.get(field, "") or ""
                    for field in CSV_FIELDS
                }

                if not cleaned_row["Status"]:
                    cleaned_row["Status"] = "Pending"

                writer.writerow(cleaned_row)


# -------------------- LOGIN PROTECTION --------------------

def login_required(role=None):
    """Restrict routes to logged-in users and the required role."""

    def decorator(view_function):
        @wraps(view_function)
        def wrapped_view(*args, **kwargs):

            if "user_id" not in session:
                flash("Please log in to continue.", "error")
                return redirect(url_for("login"))

            if role and session.get("role") != role:
                flash("You are not authorized to access that page.", "error")
                return redirect(url_for("home"))

            return view_function(*args, **kwargs)

        return wrapped_view

    return decorator


# -------------------- FAULT CLASSIFICATION --------------------

def classify_fault(fault_type, description=""):
    """Suggest the department responsible for the complaint."""

    text = f"{fault_type} {description}".lower()

    if any(word in text for word in [
        "water", "tap", "pipe", "leak", "plumbing",
        "drain", "sewage", "toilet", "bathroom"
    ]):
        return "Plumbing Department"

    if any(word in text for word in [
        "electric", "light", "fan", "switch", "power",
        "socket", "wiring", "bulb", "current"
    ]):
        return "Electrical Department"

    if any(word in text for word in [
        "chair", "table", "desk", "bench", "door",
        "window", "furniture", "lock"
    ]):
        return "Carpentry and Maintenance Department"

    if any(word in text for word in [
        "road", "building", "wall", "floor", "roof",
        "crack", "concrete", "civil", "ceiling", "stair"
    ]):
        return "Civil Maintenance Department"

    if any(word in text for word in [
        "wifi", "wi-fi", "internet", "network",
        "computer", "projector", "printer"
    ]):
        return "IT Department"

    return "General Maintenance Department"


# -------------------- PRIORITY RECOMMENDATION --------------------

def recommend_priority(fault_type, description=""):
    """Recommend a priority using simple keyword rules."""

    text = f"{fault_type} {description}".lower()

    urgent_words = [
        "fire", "smoke", "electric shock", "sparking",
        "gas leak", "collapse", "major crack",
        "flooding", "danger", "emergency"
    ]

    medium_words = [
        "leak", "broken", "not working", "damage",
        "blocked", "crack", "overflow"
    ]

    if any(word in text for word in urgent_words):
        return "High"

    if any(word in text for word in medium_words):
        return "Medium"

    return "Low"


# -------------------- CSV HELPER FUNCTIONS --------------------

def read_complaints():
    """Read all complaints from the CSV file."""

    if not os.path.exists(CSV_FILE):
        setup_complaints_csv()

    with open(CSV_FILE, "r", newline="", encoding="utf-8-sig") as file:
        return list(csv.DictReader(file))


def write_complaints(complaints):
    """Write complaints back to the CSV file."""

    with open(CSV_FILE, "w", newline="", encoding="utf-8") as file:
        writer = csv.DictWriter(file, fieldnames=CSV_FIELDS)
        writer.writeheader()

        for complaint in complaints:
            row = {
                field: complaint.get(field, "") or ""
                for field in CSV_FIELDS
            }
            writer.writerow(row)


def allowed_file(filename):
    """Check whether the uploaded image extension is allowed."""

    return (
        "." in filename
        and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS
    )


# -------------------- HOME PAGE --------------------

@app.route("/")
def home():

    if "user_id" not in session:
        return redirect(url_for("login"))

    if session.get("role") == "admin":
        return redirect(url_for("admin"))

    return redirect(url_for("student_dashboard"))


# -------------------- STUDENT REGISTRATION --------------------

@app.route("/register", methods=["GET", "POST"])
def register():

    if request.method == "POST":
        name = request.form.get("name", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        if not name or not email or not password:
            flash("Please fill in all fields.", "error")
            return render_template("register.html")

        if len(password) < 8:
            flash("Password must contain at least 8 characters.", "error")
            return render_template("register.html")

        try:
            with sqlite3.connect(DATABASE) as connection:
                connection.execute("""
                    INSERT INTO users (name, email, password, role)
                    VALUES (?, ?, ?, ?)
                """, (
                    name,
                    email,
                    generate_password_hash(password),
                    "student",
                ))

            flash("Registration successful. Please log in.", "success")
            return redirect(url_for("login"))

        except sqlite3.IntegrityError:
            flash("An account with this email already exists.", "error")

    return render_template("register.html")


# -------------------- LOGIN --------------------

@app.route("/login", methods=["GET", "POST"])
def login():

    if "user_id" in session:
        return redirect(url_for("home"))

    if request.method == "POST":
        email = request.form.get("username", "").strip().lower()
        password = request.form.get("password", "")
        selected_role = request.form.get("role", "student")

        with sqlite3.connect(DATABASE) as connection:
            connection.row_factory = sqlite3.Row

            user = connection.execute(
                "SELECT * FROM users WHERE email = ?",
                (email,)
            ).fetchone()

        if (
            user
            and check_password_hash(user["password"], password)
            and user["role"] == selected_role
        ):
            session.clear()
            session["user_id"] = user["id"]
            session["name"] = user["name"]
            session["email"] = user["email"]
            session["role"] = user["role"]

            flash("Login successful.", "success")
            return redirect(url_for("home"))

        flash("Invalid email, password, or account type.", "error")

    return render_template("login.html")


# -------------------- STUDENT DASHBOARD --------------------

@app.route("/student")
@login_required(role="student")
def student_dashboard():

    all_complaints = read_complaints()

    student_complaints = [
        complaint
        for complaint in all_complaints
        if complaint.get("Student Email", "").strip().lower()
        == session.get("email", "").strip().lower()
    ]

    total_complaints = len(student_complaints)

    pending_count = sum(
        1 for complaint in student_complaints
        if complaint.get("Status", "").lower() == "pending"
    )

    in_progress_count = sum(
        1 for complaint in student_complaints
        if complaint.get("Status", "").lower() in [
            "in progress", "in-progress", "processing"
        ]
    )

    resolved_count = sum(
        1 for complaint in student_complaints
        if complaint.get("Status", "").lower() == "resolved"
    )

    return render_template(
        "student_dashboard.html",
        complaints=student_complaints,
        total_complaints=total_complaints,
        pending_count=pending_count,
        in_progress_count=in_progress_count,
        resolved_count=resolved_count,
    )


# -------------------- OPEN NEW COMPLAINT FORM --------------------

@app.route("/new_complaint")
@login_required(role="student")
def new_complaint():
    return render_template("index.html")


# -------------------- REPORT A COMPLAINT --------------------

@app.route("/report", methods=["POST"])
@login_required(role="student")
def report():

    location = request.form.get("location", "").strip()
    fault_type = request.form.get("fault_type", "").strip()
    description = request.form.get("description", "").strip()

    if not location or not fault_type or not description:
        flash("Please fill in the location, fault type, and description.", "error")
        return redirect(url_for("new_complaint"))

    photo = request.files.get("photo")
    photo_filename = ""

    if photo and photo.filename:
        if not allowed_file(photo.filename):
            flash(
                "Invalid photo format. Use PNG, JPG, JPEG, GIF, or WEBP.",
                "error"
            )
            return redirect(url_for("new_complaint"))

        safe_name = secure_filename(photo.filename)
        unique_name = (
            datetime.now().strftime("%Y%m%d%H%M%S%f")
            + "_"
            + safe_name
        )

        photo_path = os.path.join(UPLOAD_FOLDER, unique_name)
        photo.save(photo_path)
        photo_filename = unique_name

    complaints = read_complaints()

    complaint_id = "CF" + datetime.now().strftime("%Y%m%d%H%M%S%f")

    department = classify_fault(fault_type, description)
    priority = recommend_priority(fault_type, description)

    complaint = {
        "Complaint ID": complaint_id,
        "Student Name": session.get("name", ""),
        "Student Email": session.get("email", ""),
        "Location": location,
        "Fault Type": fault_type,
        "Description": description,
        "Priority": priority,
        "Department": department,
        "Photo": photo_filename,
        "Status": "Pending",
    }

    complaints.append(complaint)
    write_complaints(complaints)

    flash("Your complaint has been submitted successfully.", "success")

    return render_template(
        "complaint_success.html",
        complaint=complaint
    )


# -------------------- TRACK COMPLAINT --------------------

@app.route("/track", methods=["GET", "POST"])
@login_required(role="student")
def track():

    complaint = None

    if request.method == "POST":
        complaint_id = request.form.get("complaint_id", "").strip()

        for item in read_complaints():
            if (
                item.get("Complaint ID", "").strip() == complaint_id
                and item.get("Student Email", "").strip().lower()
                == session.get("email", "").strip().lower()
            ):
                complaint = item
                break

        if complaint is None:
            flash(
                "Complaint not found. Check the ID and make sure it belongs to your account.",
                "error"
            )

    return render_template("track.html", complaint=complaint)


# -------------------- ADMIN DASHBOARD --------------------

@app.route("/admin")
@login_required(role="admin")
def admin():

    complaints = read_complaints()

    total_complaints = len(complaints)

    pending_count = sum(
        1 for complaint in complaints
        if complaint.get("Status", "").lower() == "pending"
    )

    in_progress_count = sum(
        1 for complaint in complaints
        if complaint.get("Status", "").lower() in [
            "in progress", "in-progress", "processing"
        ]
    )

    resolved_count = sum(
        1 for complaint in complaints
        if complaint.get("Status", "").lower() == "resolved"
    )

    return render_template(
        "admin.html",
        complaints=complaints,
        total_complaints=total_complaints,
        pending_count=pending_count,
        in_progress_count=in_progress_count,
        resolved_count=resolved_count,
    )


# -------------------- ADMIN UPDATES COMPLAINT STATUS --------------------

@app.route("/update_status", methods=["POST"])
@login_required(role="admin")
def update_status():

    complaint_id = request.form.get("complaint_id", "").strip()
    new_status = request.form.get("status", "").strip()

    allowed_statuses = {
        "Pending",
        "In Progress",
        "Resolved",
    }

    if new_status not in allowed_statuses:
        flash("Invalid complaint status.", "error")
        return redirect(url_for("admin"))

    complaints = read_complaints()
    found = False

    for complaint in complaints:
        if complaint.get("Complaint ID", "").strip() == complaint_id:
            complaint["Status"] = new_status
            found = True
            break

    if found:
        write_complaints(complaints)
        flash("Complaint status updated successfully.", "success")
    else:
        flash("Complaint ID not found.", "error")

    return redirect(url_for("admin"))


# -------------------- LOGOUT --------------------

@app.route("/logout")
def logout():

    session.clear()
    flash("You have been logged out.", "success")

    return redirect(url_for("login"))


# -------------------- START APPLICATION --------------------

if __name__ == "__main__":
    setup_database()
    setup_complaints_csv()
    app.run(debug=True)