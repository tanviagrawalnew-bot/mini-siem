from collections import Counter
from detection.scoring import get_threat_score


def detect_threats(logs):

    alerts = []
    failed_ips = Counter()

    for log in logs:

        event = log["event"]
        ip = log["ip"]
        username = log["username"]

        # ---------------- Failed Login ----------------

        if event == "Failed Login":

            alerts.append({

                "timestamp": log["timestamp"],
                "severity": "Medium",
                "score": get_threat_score("Failed Login Attempt"),
                "alert": "Failed Login Attempt",
                "ip": ip,
                "username": username

            })

            if ip:
                failed_ips[ip] += 1

        # ---------------- Invalid User ----------------

        elif event == "Invalid User":

            alerts.append({

                "timestamp": log["timestamp"],
                "severity": "Medium",
                "score": get_threat_score("Invalid User Login Attempt"),
                "alert": "Invalid User Login Attempt",
                "ip": ip,
                "username": username

            })

        # ---------------- Root Login ----------------

        elif event == "Successful Login" and username == "root":

            alerts.append({

                "timestamp": log["timestamp"],
                "severity": "High",
                "score": get_threat_score("Root Login Detected"),
                "alert": "Root Login Detected",
                "ip": ip,
                "username": username

            })

        # ---------------- Sudo Command ----------------

        elif event == "Sudo Command":

            alerts.append({

                "timestamp": log["timestamp"],
                "severity": "Low",
                "score": get_threat_score("Sudo Command Executed"),
                "alert": "Sudo Command Executed",
                "ip": ip,
                "username": username

            })

    # ---------------- Brute Force Detection ----------------

    for ip, count in failed_ips.items():

        if count >= 5:

            alerts.append({

                "timestamp": "-",
                "severity": "Critical",
                "score": get_threat_score("Possible Brute Force Attack"),
                "alert": "Possible Brute Force Attack",
                "ip": ip,
                "username": "-"

            })

    return alerts