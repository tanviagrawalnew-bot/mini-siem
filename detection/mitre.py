# MITRE ATT&CK Mapping

MITRE_MAPPING = {

    "Failed Login Attempt": {
        "id": "T1110",
        "technique": "Brute Force"
    },

    "Invalid User Login Attempt": {
        "id": "T1110",
        "technique": "Brute Force"
    },

    "Possible Brute Force Attack": {
        "id": "T1110",
        "technique": "Brute Force"
    },

    "Root Login Detected": {
        "id": "T1078",
        "technique": "Valid Accounts"
    },

    "Sudo Command Executed": {
        "id": "T1548",
        "technique": "Abuse Elevation Control Mechanism"
    }

}


def get_mitre_mapping(alert_name):
    return MITRE_MAPPING.get(
        alert_name,
        {
            "id": "N/A",
            "technique": "Unknown"
        }
    )