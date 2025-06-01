import requests

def get_ip():
    response = requests.get("https://api.ipify.org?format=json").json()
    return response["ip"]

def get_ip_info():

    ip_address = get_ip()
    if not ip_address:
        ip_address = input("Enter your custom ip if there any:")
    token = '7#@$@$%#!%$#!' # add your token here
    url = f"https://ipinfo.io/{ip_address}?token={token}"
    response = requests.get(url).json()

    google_map = f"https://www.google.com/maps/place/{response.get('loc')}"
    print(response, {"location link ": google_map})

get_ip_info()
