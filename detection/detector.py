from collections import Counter


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
                "alert": "Invalid User Login Attempt",
                "ip": ip,
                "username": username

            })

        # ---------------- Root Login ----------------

        elif event == "Successful Login" and username == "root":

            alerts.append({

                "timestamp": log["timestamp"],
                "severity": "High",
                "alert": "Root Login Detected",
                "ip": ip,
                "username": username

            })

        # ---------------- Sudo Command ----------------

        elif event == "Sudo Command":

            alerts.append({

                "timestamp": log["timestamp"],
                "severity": "Low",
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
                "alert": "Possible Brute Force Attack",
                "ip": ip,
                "username": "-"

            })

    return alerts