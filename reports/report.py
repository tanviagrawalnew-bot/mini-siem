import csv

# ----------------------- CSV REPORT -----------------------

def generate_report(alerts, filename="reports/security_report.csv"):

    with open(filename, "w", newline="", encoding="utf-8") as file:

        writer = csv.writer(file)

        writer.writerow([
            "Timestamp",
            "Severity",
            "Threat Score",
            "Alert",
            "IP Address",
            "Username"
        ])

        for alert in alerts:

            writer.writerow([

                alert["timestamp"],
                alert["severity"],
                alert["score"],
                alert["alert"],
                alert["ip"],
                alert["username"]

            ])

    return filename


# ----------------------- PDF REPORT -----------------------

from reportlab.platypus import SimpleDocTemplate, Table
from reportlab.lib import colors


def generate_pdf(alerts, filename="reports/security_report.pdf"):

    data = [[
        "Timestamp",
        "Severity",
        "Threat Score",
        "Alert",
        "IP",
        "Username"
    ]]

    for alert in alerts:

        data.append([

            alert["timestamp"],
            alert["severity"],
            alert["score"],
            alert["alert"],
            alert["ip"],
            alert["username"]

        ])

    pdf = SimpleDocTemplate(filename)

    table = Table(data)

    table.setStyle([

        ("GRID", (0, 0), (-1, -1), 1, colors.black),

        ("BACKGROUND", (0, 0), (-1, 0), colors.grey),

        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),

        ("ALIGN", (0, 0), (-1, -1), "CENTER")

    ])

    pdf.build([table])

    return filename