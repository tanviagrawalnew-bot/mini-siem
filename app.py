from flask import Flask, render_template, request, redirect, send_file
import os
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

os.makedirs(UPLOAD_FOLDER, exist_ok=True)

create_database()

# Global variable for dashboard
geo_results = []


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

    filtered_alerts =  search_logs(alerts, query)
    return render_template(
        "dashboard.html",
        total_logs=data["total_logs"],
        total_alerts=data["total_alerts"],
        critical_alerts=data["critical_alerts"],
        recent_alerts=filtered_alerts,
        geo_results=geo_results,
        search_query=query,
        result_count=len(filtered_alerts)
    )
# ---------------- Upload ----------------

@app.route("/upload", methods=["GET", "POST"])
def upload():

    global geo_results

    if request.method == "POST":

        file = request.files.get("logfile")

        if file and file.filename:

            filepath = os.path.join(
                app.config["UPLOAD_FOLDER"],
                file.filename
            )

            file.save(filepath)

            # ---------------- Parse Logs ----------------

            logs = parse_logs(filepath)

            print("=" * 50)
            print("Parsed Logs:", len(logs))

            # ---------------- IOC Extraction ----------------

            iocs = extract_iocs(logs)

            print("=" * 50)
            print("IOC EXTRACTION")
            print(iocs)

            # ---------------- Geolocation ----------------

            geo_results = []

            print("\n========== GEOLOCATION ==========")

            for ip in iocs["ips"]:

                location = get_ip_geolocation(ip)

                location["ip"] = ip

                geo_results.append(location)

                print(ip, "->", location)

            # ---------------- Threat Detection ----------------

            alerts = detect_threats(logs)

            print("Detected Alerts:", len(alerts))

            # ---------------- Database ----------------

            save_logs(logs)
            print("Logs saved successfully")

            save_alerts(alerts)
            print("Alerts saved successfully")

            # ---------------- Reports ----------------

            generate_report(alerts)
            generate_pdf(alerts)

            print("=" * 50)

            return redirect("/dashboard")

    return render_template("upload.html")


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

if __name__ == "__main__":
    app.run(debug=True)