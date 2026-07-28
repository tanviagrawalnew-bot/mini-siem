from flask import Flask, render_template, request, redirect, send_file, url_for
import os
import logging
from werkzeug.utils import secure_filename
from werkzeug.exceptions import RequestEntityTooLarge
from search.search_logs import search_logs
from parser.parser import parse_logs
from detection.detector import detect_threats
from ioc.extractor import extract_iocs
from geo.geolocation import get_ip_geolocation

from database.db import (
    create_database,
    save_logs,
    save_alerts,
    get_dashboard_data,
    clear_database
)

from reports.report import generate_report, generate_pdf

app = Flask(__name__)

UPLOAD_FOLDER = "uploads"
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER

# ---------------- Upload Validation Config ----------------
# Max upload size: 10 MB. Flask enforces this automatically and raises
# RequestEntityTooLarge if exceeded (handled below).
app.config["MAX_CONTENT_LENGTH"] = 10 * 1024 * 1024  # 10 MB

# Allowed log file extensions for upload. Matches what the upload form
# already advertises (parser format support is unchanged in this step).
ALLOWED_UPLOAD_EXTENSIONS = {".txt", ".log", ".csv"}

os.makedirs(UPLOAD_FOLDER, exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)
logger = logging.getLogger(__name__)

create_database()

# Global variable for dashboard
geo_results = []


# ---------------- Upload Validation Helper ----------------

def validate_upload(file):
    """
    Validates an uploaded file before it is saved or processed.

    Returns:
        (is_valid, error_message)
        is_valid is True and error_message is None when validation passes.
        is_valid is False and error_message is a human-readable string
        describing the problem when validation fails.
    """

    if file is None or not file.filename:
        return False, "Please select a log file to upload."

    filename = file.filename.strip()

    if filename == "":
        return False, "Please select a log file to upload."

    _, extension = os.path.splitext(filename)
    extension = extension.lower()

    if extension not in ALLOWED_UPLOAD_EXTENSIONS:
        allowed = ", ".join(sorted(ALLOWED_UPLOAD_EXTENSIONS))
        return False, (
            f"Unsupported file type '{extension or 'unknown'}'. "
            f"Allowed file types: {allowed}"
        )

    # Check for an empty (0-byte) file without fully reading it into memory.
    file.stream.seek(0, os.SEEK_END)
    file_size = file.stream.tell()
    file.stream.seek(0)

    if file_size == 0:
        return False, "The selected file is empty. Please choose a valid log file."

    return True, None


# ---------------- Home ----------------

@app.route("/")
def home():
    return render_template("index.html")


# ---------------- Dashboard ----------------

@app.route("/dashboard")
def dashboard():

    global geo_results

    data = get_dashboard_data()

    query = request.args.get("search", "").strip()

    alerts = []

    for alert in data["recent_alerts"]:

        alerts.append({
            "timestamp": alert[0],
            "alert": alert[1],
            "severity": alert[2],
            "score": alert[3],
            "mitre_id": alert[4],
            "mitre_name": alert[5],
            "ip": alert[6] if len(alert) > 6 else "",
            "username": alert[7] if len(alert) > 7 else ""
        })

    filtered_alerts = search_logs(alerts, query)

    # ---------- Prepare Chart Data ----------

    severity_labels = [item[0] for item in data["severity_data"]]
    severity_counts = [item[1] for item in data["severity_data"]]

    mitre_labels = [item[0] for item in data["mitre_data"]]
    mitre_counts = [item[1] for item in data["mitre_data"]]

    ip_labels = [item[0] for item in data["top_ips"]]
    ip_counts = [item[1] for item in data["top_ips"]]

    user_labels = [item[0] for item in data["top_users"]]
    user_counts = [item[1] for item in data["top_users"]]

    return render_template(
        "dashboard.html",
        total_logs=data["total_logs"],
        total_alerts=data["total_alerts"],
        
        critical_alerts=data["critical_alerts"],

        security_score=data["security_score"],

        unique_ips=data["unique_ips"],
        targeted_users=data["targeted_users"],
        mitre_count=data["mitre_count"],

        recent_alerts=filtered_alerts,
        geo_results=geo_results,
        search_query=query,

        result_count=len(filtered_alerts),
        severity_labels=severity_labels,
        severity_counts=severity_counts,

        mitre_labels=mitre_labels,
        mitre_counts=mitre_counts,

        ip_labels=ip_labels,
        ip_counts=ip_counts,

        user_labels=user_labels,
        user_counts=user_counts
    )
# ---------------- Upload ----------------

@app.route("/upload", methods=["GET", "POST"])
def upload():

    global geo_results

    if request.method == "POST":

        file = request.files.get("logfile")

        # ---------------- Server-side Validation ----------------

        is_valid, error_message = validate_upload(file)

        if not is_valid:
            logger.warning("Upload rejected: %s", error_message)
            return render_template("upload.html", error=error_message)

        # ---------------- Secure Filename ----------------

        filename = secure_filename(file.filename)

        if not filename:
            logger.warning("Upload rejected: filename could not be sanitized")
            return render_template(
                "upload.html",
                error="Invalid filename. Please rename the file and try again."
            )

        filepath = os.path.join(
            app.config["UPLOAD_FOLDER"],
            filename
        )

        try:
            file.save(filepath)

            # ---------------- Parse Logs ----------------

            logs = parse_logs(filepath)

            logger.info("Parsed logs: %d", len(logs))

            # ---------------- IOC Extraction ----------------

            iocs = extract_iocs(logs)

            logger.info("IOC extraction complete: %s", {k: len(v) for k, v in iocs.items()})

            # ---------------- Geolocation ----------------

            geo_results = []

            for ip in iocs["ips"]:

                location = get_ip_geolocation(ip)

                location["ip"] = ip

                geo_results.append(location)

            logger.info("Geolocation complete for %d IP(s)", len(geo_results))

            # ---------------- Threat Detection ----------------

            alerts = detect_threats(logs)

            logger.info("Detected alerts: %d", len(alerts))

            # ---------------- Database ----------------

            save_logs(logs)
            logger.info("Logs saved successfully")

            save_alerts(alerts)
            logger.info("Alerts saved successfully")

            # ---------------- Reports ----------------

            generate_report(alerts)
            generate_pdf(alerts)

            logger.info("Upload processed successfully: %s", filename)

        except Exception:
            logger.exception("Upload processing failed for file: %s", filename)
            return render_template(
                "upload.html",
                error=(
                    "Something went wrong while processing this file. "
                    "Please check the file format and try again."
                )
            )

        return redirect(url_for("dashboard"))

    return render_template("upload.html")


# ---------------- Upload Too Large Handler ----------------

@app.errorhandler(RequestEntityTooLarge)
def handle_file_too_large(e):
    max_mb = app.config["MAX_CONTENT_LENGTH"] // (1024 * 1024)
    logger.warning("Upload rejected: file exceeds %d MB limit", max_mb)
    return render_template(
        "upload.html",
        error=f"File is too large. Maximum allowed size is {max_mb} MB."
    ), 413


# ---------------- Reports ----------------

@app.route("/reports")
def reports():
    return render_template("reports.html")


# ---------------- Download CSV ----------------

@app.route("/download-report")
def download_report():

    return send_file(
        "reports/security_report.csv",
        as_attachment=True
    )


# ---------------- Download PDF ----------------

@app.route("/download-pdf")
def download_pdf():

    return send_file(
        "reports/security_report.pdf",
        as_attachment=True
    )


# ---------------- Clear History ----------------

@app.route("/clear-history")
def clear_history():

    global geo_results

    geo_results = []

    clear_database()

    return redirect("/dashboard")


# ---------------- Run ----------------


    import os

if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=int(os.environ.get("PORT", 5000)),
        debug=False
    )