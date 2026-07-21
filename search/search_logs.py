def search_logs(alerts, query=""):

    if not query:
        return alerts

    query = query.lower().strip()

    results = []

    searchable_fields = [
        "timestamp",
        "alert",
        "severity",
        "score",
        "mitre_id",
        "mitre_name",
        "ip",
        "username"
    ]

    for alert in alerts:

        matched = False

        for field in searchable_fields:

            value = alert.get(field)

            if value is None:
                continue

            if query in str(value).lower():
                matched = True
                break

        if matched:
            results.append(alert)

    return results