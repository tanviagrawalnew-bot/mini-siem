import sqlite3

DATABASE_NAME = "database/siem.db"


# ---------------- Create Database ----------------

def create_database():

    conn = sqlite3.connect(DATABASE_NAME)
    cursor = conn.cursor()

    # Logs Table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS logs (

            id INTEGER PRIMARY KEY AUTOINCREMENT,

            timestamp TEXT,
            hostname TEXT,
            service TEXT,
            pid TEXT,
            event TEXT,
            username TEXT,
            ip TEXT,
            port TEXT,
            message TEXT

        )
    """)

    # Alerts Table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS alerts (

            id INTEGER PRIMARY KEY AUTOINCREMENT,

            timestamp TEXT,
            severity TEXT,
            score INTEGER,
            mitre_id TEXT,
            mitre_name TEXT,
            alert TEXT,
            ip TEXT,
            username TEXT

        )
    """)

    conn.commit()
    conn.close()


# ---------------- Save Parsed Logs ----------------

def save_logs(logs):

    conn = sqlite3.connect(DATABASE_NAME)
    cursor = conn.cursor()

    for log in logs:

        cursor.execute("""
            INSERT INTO logs(

                timestamp,
                hostname,
                service,
                pid,
                event,
                username,
                ip,
                port,
                message

            )

            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)

        """, (

            log["timestamp"],
            log["hostname"],
            log["service"],
            log["pid"],
            log["event"],
            log["username"],
            log["ip"],
            log["port"],
            log["message"]

        ))

    conn.commit()
    conn.close()


# ---------------- Save Alerts ----------------

def save_alerts(alerts):

    conn = sqlite3.connect(DATABASE_NAME)
    cursor = conn.cursor()

    for alert in alerts:

        print(alert)

        cursor.execute("""
            INSERT INTO alerts(

                timestamp,
                severity,
                score,
                mitre_id,
                mitre_name,
                alert,
                ip,
                username

            )

            VALUES (?, ?, ?, ?, ?, ?, ?, ?)

        """, (

            alert["timestamp"],
            alert["severity"],
            alert["score"],
            alert["mitre_id"],
            alert["mitre_name"],
            alert["alert"],
            alert["ip"],
            alert["username"]

        ))

    conn.commit()
    conn.close()


# ---------------- Dashboard Data ----------------

def get_dashboard_data():

    conn = sqlite3.connect(DATABASE_NAME)
    cursor = conn.cursor()

    # Total Logs
    cursor.execute("SELECT COUNT(*) FROM logs")
    total_logs = cursor.fetchone()[0]

    # Total Alerts
    cursor.execute("SELECT COUNT(*) FROM alerts")
    total_alerts = cursor.fetchone()[0]

    # Critical Alerts
    cursor.execute("""
        SELECT COUNT(*)
        FROM alerts
        WHERE severity = 'Critical'
    """)
    critical_alerts = cursor.fetchone()[0]

    # Recent Alerts (Search Ready)
    cursor.execute("""
        SELECT

            timestamp,
            alert,
            severity,
            score,
            mitre_id,
            mitre_name,
            ip,
            username

        FROM alerts

        ORDER BY id DESC

        LIMIT 50

    """)

    recent_alerts = cursor.fetchall()

    conn.close()

    return {

        "total_logs": total_logs,
        "total_alerts": total_alerts,
        "critical_alerts": critical_alerts,
        "recent_alerts": recent_alerts

    }


# ---------------- Clear Database ----------------

def clear_database():

    conn = sqlite3.connect(DATABASE_NAME)
    cursor = conn.cursor()

    cursor.execute("DELETE FROM logs")
    cursor.execute("DELETE FROM alerts")

    conn.commit()
    conn.close()