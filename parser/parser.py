import re


def parse_logs(file_path):
    logs = []

    pattern = re.compile(
        r'^(?P<timestamp>\w+\s+\d+\s+\d+:\d+:\d+)\s+'
        r'(?P<hostname>\S+)\s+'
        r'(?P<service>\w+)\[(?P<pid>\d+)\]:\s+'
        r'(?P<message>.*)$'
    )

    with open(file_path, "r", encoding="utf-8", errors="ignore") as file:

        for line in file:

            line = line.strip()

            if not line:
                continue

            match = pattern.match(line)

            if not match:
                continue

            data = match.groupdict()

            message = data["message"]

            username = None
            ip = None
            port = None
            event = "Other"

            if "Failed password" in message:
                event = "Failed Login"

            elif "Accepted password" in message:
                event = "Successful Login"

            elif "Invalid user" in message:
                event = "Invalid User"

            elif "session opened" in message:
                event = "Session Opened"

            elif "session closed" in message:
                event = "Session Closed"

            elif "sudo" in message:
                event = "Sudo Command"

            user = re.search(r"for\s+(\w+)", message)

            if user:
                username = user.group(1)

            ip_match = re.search(
                r"from\s+(\d+\.\d+\.\d+\.\d+)",
                message
            )

            if ip_match:
                ip = ip_match.group(1)

            port_match = re.search(r"port\s+(\d+)", message)

            if port_match:
                port = port_match.group(1)

            logs.append({

                "timestamp": data["timestamp"],
                "hostname": data["hostname"],
                "service": data["service"],
                "pid": data["pid"],
                "event": event,
                "username": username,
                "ip": ip,
                "port": port,
                "message": message

            })

    return logs