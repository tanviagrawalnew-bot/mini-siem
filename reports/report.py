import csv
from itertools import count

# ----------------------- CSV REPORT -----------------------

def generate_report(alerts, filename="reports/security_report.csv"):

    with open(filename, "w", newline="", encoding="utf-8") as file:

        writer = csv.writer(file)

        writer.writerow([
            "Timestamp",
            "Severity",
            "Threat Score",
            "MITRE ID",
            "Technique",
            "Alert",
            "IP Address",
            "Username"
        ])

        for alert in alerts:

            writer.writerow([

                alert["timestamp"],
                alert["severity"],
                alert["score"],
                alert["mitre_id"],
                alert["mitre_name"],
                alert["alert"],
                alert["ip"],
                alert["username"]

            ])

    return filename


# ----------------------- PDF REPORT -----------------------

from reportlab.platypus import (
    SimpleDocTemplate,
    Table,
    TableStyle,
    Paragraph,
    Spacer,
    PageBreak
)

from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from reportlab.lib.units import inch
from reportlab.lib.colors import HexColor

from collections import Counter
from datetime import datetime


from reportlab.pdfgen import canvas

def add_footer(canvas, doc):
    canvas.saveState()

    canvas.setFont("Helvetica", 9)

    footer_text = "Mini SIEM Security Report"

    page = f"Page {doc.page}"

    canvas.drawString(30, 20, footer_text)

    canvas.drawRightString(565, 20, page)

    canvas.restoreState()
def generate_pdf(alerts, filename="reports/security_report.pdf"):

        # -------------------- STYLES --------------------

    styles = getSampleStyleSheet()

    title_style = ParagraphStyle(
        "Title",
        parent=styles["Heading1"],
        alignment=TA_CENTER,
        fontName="Helvetica-Bold",
        fontSize=20,
        textColor=HexColor("#0B3D91"),
        spaceAfter=20
    )

    heading_style = ParagraphStyle(
        "Heading",
        parent=styles["Heading2"],
        fontName="Helvetica-Bold",
        fontSize=14,
        textColor=HexColor("#003366"),
        spaceBefore=12,
        spaceAfter=8
    )

    normal_style = styles["BodyText"]

    elements = []
        # -------------------- REPORT STATISTICS --------------------

    severity_counts = Counter(alert["severity"] for alert in alerts)

    critical = severity_counts.get("Critical", 0)
    high = severity_counts.get("High", 0)
    medium = severity_counts.get("Medium", 0)
    low = severity_counts.get("Low", 0)

    total_alerts = len(alerts)

    unique_ips = len(set(alert["ip"] for alert in alerts if alert["ip"]))

    unique_users = len(set(alert["username"] for alert in alerts if alert["username"]))

    unique_mitre = len(set(alert["mitre_name"] for alert in alerts if alert["mitre_name"]))

    highest_score = max((alert["score"] for alert in alerts), default=0)

    average_score = (
        sum(alert["score"] for alert in alerts) / total_alerts
        if total_alerts else 0
    )
        # -------------------- SECURITY SCORE --------------------

    security_score = 100

    security_score -= critical * 15
    security_score -= high * 8
    security_score -= medium * 4

    security_score = max(security_score, 0)

    if security_score >= 95:
        risk_level = "LOW"

    elif security_score >= 80:
        risk_level = "MEDIUM"

    else:
        risk_level = "HIGH"
    # -------------------- MOST ACTIVE IP --------------------

    ip_counter = Counter(
    alert["ip"]
    for alert in alerts
    if alert["ip"]
)

    most_active_ip = (
    ip_counter.most_common(1)[0][0]
    if ip_counter
    else "N/A"
)
    # -------------------- MOST TARGETED USER --------------------

    user_counter = Counter(
    alert["username"]
    for alert in alerts
    if alert["username"] and alert["username"] != "-"
)

    most_targeted_user = (
    user_counter.most_common(1)[0][0]
    if user_counter
    else "N/A"
)
    # -------------------- THREAT COUNTS --------------------

    failed_login_count = 0
    brute_force_count = 0
    root_login_count = 0
    invalid_user_count = 0

    for alert in alerts:

        alert_name = alert["alert"].lower()

        if "failed login" in alert_name:
            failed_login_count += 1

        elif "brute force" in alert_name:
            brute_force_count += 1

        elif "root login" in alert_name:
            root_login_count += 1

        elif "invalid user" in alert_name:
            invalid_user_count += 1
        
    # -------------------- MITRE TECHNIQUE COUNTS --------------------

    mitre_counter = Counter(
        (alert["mitre_id"], alert["mitre_name"])
        for alert in alerts
        if alert["mitre_id"]
)

        # -------------------- SECURITY ASSESSMENT --------------------

    if risk_level == "HIGH":

        assessment = (
            "The analysed SSH authentication logs indicate a high-risk security posture "
            "with repeated malicious authentication attempts. Immediate investigation "
            "is recommended."
        )

    elif risk_level == "MEDIUM":

        assessment = (
            "Suspicious authentication activity was detected. Continuous monitoring "
            "and preventive controls are recommended."
        )

    else:

        assessment = (
            "No significant malicious authentication behaviour was detected during analysis."
        )
        # -------------------- SECURITY RECOMMENDATIONS --------------------

    recommendations = []

    if brute_force_count > 0:
        recommendations.append(
            "Enable Multi-Factor Authentication (MFA) for privileged accounts."
        )

    if failed_login_count >= 3:
        recommendations.append(
            "Configure SSH rate limiting or account lockout to mitigate repeated login attempts."
        )

    if root_login_count > 0:
        recommendations.append(
            "Disable direct root login and use sudo for administrative access."
        )

    if invalid_user_count > 0:
        recommendations.append(
            "Investigate invalid username attempts to identify possible reconnaissance activity."
        )

    if most_active_ip != "N/A":
        recommendations.append(
            f"Review traffic originating from {most_active_ip} and block the source if malicious."
        )

    recommendations.append(
        "Continue monitoring authentication logs for abnormal login behaviour."
    )
        # -------------------- REPORT TIME --------------------

    report_time = datetime.now().strftime("%d %B %Y | %I:%M %p")   
    data = [[
        "Timestamp",
        "Severity",
        "Threat Score",
        "MITRE ID",
        "Technique",
        "Alert",
        "IP",
        "Username"
    ]]

    for alert in alerts:

        data.append([

            alert["timestamp"],
            alert["severity"],
            alert["score"],
            alert["mitre_id"],
            alert["mitre_name"],
            Paragraph(alert["alert"], normal_style),
            alert["ip"],
            alert["username"]

        ])

    pdf = SimpleDocTemplate(
    filename,
    rightMargin=30,
    leftMargin=30,
    topMargin=30,
    bottomMargin=30
)
    elements.append(
    Paragraph(
        "🛡 MINI SIEM SECURITY REPORT",
        title_style
    )
)

    elements.append(
    Paragraph(
        "Security Operations Center (SOC)",
        heading_style
    )
)

    elements.append(
    Paragraph(
        f"<b>Generated:</b> {report_time}",
        normal_style
    )
)

    elements.append(Spacer(1, 0.25 * inch))
    # -------------------- EXECUTIVE SUMMARY --------------------

    elements.append(
    Paragraph(
        "EXECUTIVE SUMMARY",
        heading_style
    )
)
    summary_data = [

    ["Total Alerts", total_alerts],

    ["Critical Alerts", critical],

    ["High Alerts", high],

    ["Medium Alerts", medium],

    ["Low Alerts", low],

    ["Security Score", f"{security_score}/100"],

    ["Overall Risk", risk_level],
    ["Log Source", "SSH Authentication Logs"],
    ["Analysis Status",
     "Investigation Required" if risk_level == "HIGH"
    else "Monitoring Recommended"]

]
    summary_table = Table(summary_data, colWidths=[220, 120])

    summary_table.setStyle(TableStyle([

    ("BACKGROUND", (0,0), (-1,-1), colors.whitesmoke),

    ("GRID", (0,0), (-1,-1), 0.5, colors.grey),

    ("FONTNAME", (0,0), (-1,-1), "Helvetica"),

    ("FONTNAME", (0,0), (0,-1), "Helvetica-Bold"),

    ("TEXTCOLOR", (0,0), (0,-1), HexColor("#003366")),

    ("BOTTOMPADDING", (0,0), (-1,-1), 8),

    ("TOPPADDING", (0,0), (-1,-1), 8),

]))
    elements.append(summary_table)

    elements.append(Spacer(1, 0.30 * inch))
    # table = Table(data)
    table = Table(
        data,
        colWidths=[
            75,   # Timestamp
            55,   # Severity
            45,   # Score
            55,   # MITRE ID
            100,  # Technique
            145,  # Alert Description
            70,   # IP Address
            65    # Username
        ]
    )
    table.setStyle(TableStyle([

        ("BACKGROUND", (0,0), (-1,0), HexColor("#003366")),
        ("TEXTCOLOR", (0,0), (-1,0), colors.white),

        ("FONTNAME", (0,0), (-1,0), "Helvetica-Bold"),
        ("FONTSIZE", (0,0), (-1,-1), 9),

        ("GRID", (0,0), (-1,-1), 0.5, colors.grey),

        ("BOTTOMPADDING", (0,0), (-1,0), 10),
        ("TOPPADDING", (0,0), (-1,-1), 6),

        ("VALIGN", (0,0), (-1,-1), "MIDDLE"),
        ("ALIGN", (0,0), (-1,-1), "CENTER"),

        ("ROWBACKGROUNDS",
            (0,1),
            (-1,-1),
            [colors.white, HexColor("#F5F7FA")])

    ]))
    for row, alert in enumerate(alerts, start=1):

        severity = alert["severity"].lower()

        if severity == "critical":
            table.setStyle(TableStyle([
                ("TEXTCOLOR", (1,row), (1,row), colors.red),
                ("FONTNAME", (1,row), (1,row), "Helvetica-Bold")
            ]))

        elif severity == "high":
            table.setStyle(TableStyle([
                ("TEXTCOLOR", (1,row), (1,row), colors.orange),
                ("FONTNAME", (1,row), (1,row), "Helvetica-Bold")
            ]))

        elif severity == "medium":
            table.setStyle(TableStyle([
                ("TEXTCOLOR", (1,row), (1,row), colors.darkgoldenrod),
                ("FONTNAME", (1,row), (1,row), "Helvetica-Bold")
            ]))

        elif severity == "low":
            table.setStyle(TableStyle([
                ("TEXTCOLOR", (1,row), (1,row), colors.green),
                ("FONTNAME", (1,row), (1,row), "Helvetica-Bold")
            ]))
    elements.append(Spacer(1, 0.25 * inch))

    elements.append(
    Paragraph(
        "IOC SUMMARY",
        heading_style
    )
)
    ioc_data = [

    ["Unique Source IPs", unique_ips],

    ["Unique Usernames", unique_users],

    ["MITRE Techniques", unique_mitre],

    ["Highest Threat Score", highest_score],

    ["Most Active IP", most_active_ip],

    ["Most Targeted User", most_targeted_user]

]
    ioc_table = Table(
    ioc_data,
    colWidths=[220,120]
)

    ioc_table.setStyle(TableStyle([

    ("BACKGROUND",(0,0),(-1,-1),colors.beige),

    ("GRID",(0,0),(-1,-1),0.5,colors.grey),

    ("FONTNAME",(0,0),(0,-1),"Helvetica-Bold"),

    ("TEXTCOLOR",(0,0),(0,-1),HexColor("#003366")),

    ("BOTTOMPADDING",(0,0),(-1,-1),8),

    ("TOPPADDING",(0,0),(-1,-1),8)

]))
    elements.append(ioc_table)

    elements.append(Spacer(1,0.30*inch))
    elements.append(
    Paragraph(
        "THREAT ANALYSIS",
        heading_style
    )
)
    threat_data = [

    [
        "Failed Login Attempts",
        failed_login_count
    ],

    [
        "Brute Force Alerts",
        brute_force_count
    ],

    [
        "Root Login Events",
        root_login_count
    ],

    [
        "Invalid User Attempts",
        invalid_user_count
    ]

]
    threat_table = Table(
    threat_data,
    colWidths=[220,120]
)

    threat_table.setStyle(TableStyle([

    ("BACKGROUND",(0,0),(-1,-1),colors.lightgrey),

    ("GRID",(0,0),(-1,-1),0.5,colors.grey),

    ("FONTNAME",(0,0),(0,-1),"Helvetica-Bold"),

    ("TEXTCOLOR",(0,0),(0,-1),HexColor("#003366")),

    ("BOTTOMPADDING",(0,0),(-1,-1),8),

    ("TOPPADDING",(0,0),(-1,-1),8)

]))
    observation = ""

    if brute_force_count > 0:

        observation += (
        "• Brute force behaviour detected against the SSH service.<br/>"
    )

    if failed_login_count > 0:

        observation += (
        "• Multiple failed authentication attempts observed.<br/>"
    )

    if root_login_count > 0:

        observation += (
        "• Root account activity requires administrative review.<br/>"
    )

    if invalid_user_count > 0:

        observation += (
        "• Invalid username attempts may indicate reconnaissance.<br/>"
    )

    if observation == "":
        observation = "• No significant authentication threats detected."
    elements.append(threat_table)

    elements.append(Spacer(1,0.15*inch))

    elements.append(
    Paragraph(
        "<b>Observations</b><br/>" + observation,
        normal_style
    )
)

    elements.append(Spacer(1,0.30*inch))
    elements.append(
        Paragraph(
            "MITRE ATT&CK SUMMARY",
            heading_style
    )
)
    mitre_data = [
        ["Technique ID", "Technique", "Occurrences"]
]

    for (mitre_id, mitre_name), count in mitre_counter.items():

        mitre_data.append([
            mitre_id,
            mitre_name,
            str(count)
    ])
        mitre_table = Table(
    mitre_data,
    colWidths=[100, 220, 90]
)

    mitre_table.setStyle(TableStyle([

        ("BACKGROUND", (0, 0), (-1, 0), HexColor("#003366")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),

        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),

        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),

        ("ALIGN", (2, 1), (2, -1), "CENTER"),

        ("BOTTOMPADDING", (0, 0), (-1, -1), 8),

        ("TOPPADDING", (0, 0), (-1, -1), 8),

]))
    if mitre_counter:

     (top_id, top_name), count = mitre_counter.most_common(1)[0]

    observation = (
        f"<b>Observation:</b><br/>"
        f"The most frequently detected MITRE ATT&CK technique is "
        f"<b>{top_id} - {top_name}</b>, observed "
        f"<b>{count}</b> time(s). This indicates the primary attack pattern identified during analysis."
    )  
    elements.append(mitre_table)

    elements.append(Spacer(1, 0.15 * inch))

    elements.append(
        Paragraph(
            observation,
            normal_style
    )
)

    elements.append(Spacer(1, 0.30 * inch))
    elements.append(
        Paragraph(
            "SECURITY ASSESSMENT",
            heading_style
    )
)
    assessment_data = [

        ["Security Score", f"{security_score}/100"],

        ["Overall Risk", risk_level],

        ["Analysis Status",
        "Investigation Required" if risk_level == "HIGH"
        else "Monitoring Recommended"]

]
    assessment_table = Table(
        assessment_data,
        colWidths=[220,120]
)

    assessment_table.setStyle(TableStyle([

        ("BACKGROUND",(0,0),(-1,-1),colors.whitesmoke),

        ("GRID",(0,0),(-1,-1),0.5,colors.grey),

        ("FONTNAME",(0,0),(0,-1),"Helvetica-Bold"),

        ("TEXTCOLOR",(0,0),(0,-1),HexColor("#003366")),

        ("BOTTOMPADDING",(0,0),(-1,-1),8),

        ("TOPPADDING",(0,0),(-1,-1),8)

    ]))
    elements.append(assessment_table)

    elements.append(Spacer(1,0.15*inch))

    elements.append(
        Paragraph(
            f"<b>Assessment:</b><br/>{assessment}",
            normal_style
        )
    )

    elements.append(Spacer(1,0.30*inch))
    # pdf.build([table])
    elements.append(
        Paragraph(
            "SECURITY RECOMMENDATIONS",
            heading_style
        )
    )

    recommendation_text = ""

    for i, rec in enumerate(recommendations, start=1):

        recommendation_text += f"{i}. {rec}<br/><br/>"

    elements.append(
        Paragraph(
            recommendation_text,
            normal_style
        )
    )

    elements.append(Spacer(1,0.30*inch))
    elements.append(
        Paragraph(
            "DETAILED ALERTS",
            heading_style
        )
    )

    elements.append(Spacer(1, 0.15 * inch))

    elements.append(table)
    # pdf.build(elements)
    pdf.build(
        elements,
        onFirstPage=add_footer,
        onLaterPages=add_footer
    )
    return filename