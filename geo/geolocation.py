# FAKE_GEO_DB = {

#     "192.168.1.10": {
#         "country": "India",
#         "city": "Delhi",
#         "isp": "Jio",
#         "risk": "High"
#     },

#     "192.168.1.15": {
#         "country": "India",
#         "city": "Mumbai",
#         "isp": "Airtel",
#         "risk": "Low"
#     },

#     "198.51.100.25": {
#         "country": "Germany",
#         "city": "Berlin",
#         "isp": "Deutsche Telekom",
#         "risk": "Medium"
#     },

#     "203.0.113.55": {
#         "country": "Russia",
#         "city": "Moscow",
#         "isp": "Rostelecom",
#         "risk": "Critical"
#     }

# }


# def get_ip_geolocation(ip):

#     return FAKE_GEO_DB.get(

#         ip,

#         {
#             "country": "Unknown",
#             "city": "Unknown",
#             "isp": "Unknown",
#             "risk": "Unknown"
#         }

#     )


import requests


def get_ip_geolocation(ip):

    url = f"http://ip-api.com/json/{ip}"

    try:

        response = requests.get(url, timeout=5)

        data = response.json()

        if data["status"] == "success":

            return {

                "country": data.get("country"),
                "country_code": data.get("countryCode"),

                "city": data.get("city"),

                "isp": data.get("isp"),

                "latitude": data.get("lat"),

                "longitude": data.get("lon")

            }

    except Exception as e:

        print("Geo API Error:", e)

    return {

        "country": "Unknown",

        "city": "Unknown",

        "isp": "Unknown",

        "latitude": "-",

        "longitude": "-",
        "country_code": ""

    }