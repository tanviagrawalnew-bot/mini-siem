from flask import Flask, render_template, request, redirect,send_file
import os

from parser.parser import parse_logs
from detection.detector import detect_threats
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

os.makedirs(UPLOAD_FOLDER, exist_ok=True)

create_database()


# ---------------- Home ----------------

@app.route("/")
def home():
    return render_template("index.html")


# ---------------- Dashboard ----------------

@app.route("/dashboard")
def dashboard():

    data = get_dashboard_data()

    return render_template(
        "dashboard.html",
        total_logs=data["total_logs"],
        total_alerts=data["total_alerts"],
        critical_alerts=data["critical_alerts"],
        recent_alerts=data["recent_alerts"]
    )


# ---------------- Upload ----------------

@app.route("/upload", methods=["GET", "POST"])
def upload():

    if request.method == "POST":

        file = request.files.get("logfile")

        if file and file.filename:

            filepath = os.path.join(
                app.config["UPLOAD_FOLDER"],
                file.filename
            )

            file.save(filepath)

            logs = parse_logs(filepath)
            print("=" * 50)
            print("Parsed Logs:", len(logs))

            alerts = detect_threats(logs)
            print("Detected Alerts:", len(alerts))

            save_logs(logs)
            print("Logs saved successfully")

            save_alerts(alerts)
            print("Alerts saved successfully")

            generate_report(alerts)
            generate_pdf(alerts)


            print("=" * 50)

            return redirect("/dashboard")

    return render_template("upload.html")


# ---------------- Reports ----------------

@app.route("/reports")
def reports():

    return render_template("reports.html")

# ---------------- Download Report CSV File----------------

@app.route("/download-report")
def download_report():

    return send_file(
        "reports/security_report.csv",
        as_attachment=True
    )

# ---------------- Download Report PDF File----------------
@app.route("/download-pdf")
def download_pdf():

    return send_file(

        "reports/security_report.pdf",

        as_attachment=True

    )
# ---------------- Clear History ----------------

@app.route("/clear-history")
def clear_history():

    clear_database()

    return redirect("/dashboard")

# ---------------- Run ----------------

if __name__ == "__main__":
    app.run(debug=True)