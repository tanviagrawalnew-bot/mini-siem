THREAT_SCORES = {
    "Failed Login Attempt": 10,
    "Invalid User Login Attempt": 20,
    "Sudo Command Executed": 15,
    "Root Login Detected": 50,
    "Possible Brute Force Attack": 100
}


def get_threat_score(alert_name):
    return THREAT_SCORES.get(alert_name, 0)