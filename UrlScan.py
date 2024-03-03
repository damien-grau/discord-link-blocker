import time
import base64
import requests
import json
from dotenv import load_dotenv
import os

"""
4 requests/min
500 requests/day
"""

load_dotenv()
VT_TOKEN = os.getenv('VT_TOKEN')


async def scan_url(url):
    """
    Scan an url and prevent if it's malicious or not
    :param url: str: url
    :return: bool: True if malicious else False
    """
    base_url = "https://www.virustotal.com/api/v3/urls/"
    url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
    full_url = base_url + url_id
    print("Request to", full_url)
    headers = {
        "accept": "application/json",
        "x-apikey": VT_TOKEN
    }
    scan = json.loads(requests.get(full_url, headers=headers).text)
    try:
        scan_stats = scan["data"]["attributes"]["last_analysis_stats"]
        print(f"Last analysis stats for {url} :")
        print(scan_stats)
        return True if scan_stats['malicious'] else False
    except KeyError as keyword:
        print(f"KeyError, {keyword} not found.\nFull response of {full_url} :\n{scan}")
        return False
