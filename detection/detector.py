from collections import defaultdict

from detection.scoring import get_threat_score
from detection.mitre import get_mitre_mapping


def detect_threats(logs):

    alerts = []

    # Store failed login count + first timestamp for each IP
    failed_ips = defaultdict(lambda: {
        "count": 0,
        "timestamp": ""
    })

    for log in logs:

        event = log["event"]
        ip = log["ip"]
        username = log["username"]

        # ---------------- Failed Login ----------------

        if event == "Failed Login":

            mitre = get_mitre_mapping("Failed Login Attempt")

            alerts.append({

                "timestamp": log["timestamp"],
                "severity": "Medium",
                "score": get_threat_score("Failed Login Attempt"),
                "mitre_id": mitre["id"],
                "mitre_name": mitre["technique"],
                "alert": "Failed Login Attempt",
                "ip": ip,
                "username": username

            })

            if ip:
                failed_ips[ip]["count"] += 1

                # Save the first failed login timestamp
                if not failed_ips[ip]["timestamp"]:
                    failed_ips[ip]["timestamp"] = log["timestamp"]

        # ---------------- Invalid User ----------------

        elif event == "Invalid User":

            mitre = get_mitre_mapping("Invalid User Login Attempt")

            alerts.append({

                "timestamp": log["timestamp"],
                "severity": "Medium",
                "score": get_threat_score("Invalid User Login Attempt"),
                "mitre_id": mitre["id"],
                "mitre_name": mitre["technique"],
                "alert": "Invalid User Login Attempt",
                "ip": ip,
                "username": username

            })

        # ---------------- Root Login ----------------

        elif event == "Successful Login" and username == "root":

            mitre = get_mitre_mapping("Root Login Detected")

            alerts.append({

                "timestamp": log["timestamp"],
                "severity": "High",
                "score": get_threat_score("Root Login Detected"),
                "mitre_id": mitre["id"],
                "mitre_name": mitre["technique"],
                "alert": "Root Login Detected",
                "ip": ip,
                "username": username

            })

        # ---------------- Sudo Command ----------------

        elif event == "Sudo Command":

            mitre = get_mitre_mapping("Sudo Command Executed")

            alerts.append({

                "timestamp": log["timestamp"],
                "severity": "Low",
                "score": get_threat_score("Sudo Command Executed"),
                "mitre_id": mitre["id"],
                "mitre_name": mitre["technique"],
                "alert": "Sudo Command Executed",
                "ip": ip,
                "username": username

            })

    # ---------------- Brute Force Detection ----------------

    for ip, data in failed_ips.items():

        if data["count"] >= 5:

            mitre = get_mitre_mapping("Possible Brute Force Attack")

            alerts.append({

                "timestamp": data["timestamp"],
                "severity": "Critical",
                "score": get_threat_score("Possible Brute Force Attack"),
                "mitre_id": mitre["id"],
                "mitre_name": mitre["technique"],
                "alert": "Possible Brute Force Attack",
                "ip": ip,
                "username": "-"

            })

    return alerts