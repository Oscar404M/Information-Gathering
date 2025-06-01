import requests
import time
from datetime import datetime
import json
from typing import Dict, Tuple
from urllib.parse import quote

# قائمة المنصات الاجتماعية مع روابطها
platforms = {
    "Instagram": "https://www.instagram.com/{username}/",
    "Twitter": "https://twitter.com/{username}",
    "Facebook": "https://www.facebook.com/{username}",
    "Snapchat": "https://www.snapchat.com/add/{username}",
    "Tiktok": "https://www.tiktok.com/@{username}",
    "Reddit": "https://www.reddit.com/user/{username}/",
    "Youtube": "https://www.youtube.com/@{username}",
    "Linkedin": "https://www.linkedin.com/in/{username}",
    "GitHub": "https://github.com/{username}",
    "Steam": "https://steamcommunity.com/id/{username}",
    "Medium": "https://medium.com/@{username}",
    "Wordpress": "https://{username}.wordpress.com/",
    "Spotify": "https://open.spotify.com/user/{username}",
    "Soundcloud": "https://soundcloud.com/{username}",
    "Telegram": "https://t.me/{username}",
    "Pinterest": "https://www.pinterest.com/{username}/"
}

# دالة للتحقق من توفر اسم المستخدم
def check_username(username: str) -> Dict[str, Tuple[str, str]]:
    results = {}
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
    }
    
    for platform, url_template in platforms.items():
        target_url = url_template.format(username=quote(username))
        try:
            response = requests.get(target_url, headers=headers, timeout=5)
            if response.status_code == 200:
                results[platform] = ("Taken", target_url)
            elif response.status_code == 404:
                results[platform] = ("Available", target_url)
            else:
                results[platform] = (f"Status Code {response.status_code}", target_url)
        except requests.RequestException as e:
            results[platform] = (f"Error: {str(e)}", target_url)
        time.sleep(0.5)  # تأخير لتجنب الحظر من المواقع
    return results

# دالة لحفظ النتائج في ملف نصي
def save_results_to_file(username: str, results: Dict[str, Tuple[str, str]]):
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    filename = f"username_check_{username}_{timestamp}.txt"
    
    with open(filename, "w", encoding="utf-8") as file:
        file.write(f"Username check results for: {username}\n")
        file.write(f"Timestamp: {timestamp}\n\n")
        for platform, (status, url) in results.items():
            file.write(f"{platform}: {status} - {url}\n")
    
    return filename

# دالة لحفظ النتائج في ملف JSON
def save_results_to_json(username: str, results: Dict[str, Tuple[str, str]]):
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    filename = f"username_check_{username}_{timestamp}.json"
    
    json_data = {
        "username": username,
        "timestamp": timestamp,
        "results": {platform: {"status": status, "url": url} for platform, (status, url) in results.items()}
    }
    
    with open(filename, "w", encoding="utf-8") as file:
        json.dump(json_data, file, ensure_ascii=False, indent=4)
    
    return filename

# الدالة الرئيسية
def main():
    username = input("Enter the username to search: ").strip()
    if not username:
        print("Please enter a valid username!")
        return
    
    print("\nChecking username availability...")
    results = check_username(username)
    
    print("\nResults:")
    for platform, (status, url) in results.items():
        print(f"{platform}: {status} - {url}")
    
    # حفظ النتائج في ملف نصي
    txt_file = save_results_to_file(username, results)
    print(f"\nResults saved to text file: {txt_file}")
    
    # حفظ النتائج في ملف JSON
    json_file = save_results_to_json(username, results)
    print(f"Results saved to JSON file: {json_file}")

if __name__ == "__main__":
    main()