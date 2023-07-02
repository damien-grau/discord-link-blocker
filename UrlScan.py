import time
import base64
import requests
import json

"""
4 requests/min
500 requests/day
"""


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
        "x-apikey": "85456b677bfab3ee4eca5a6f1f1a270dba34511ebf2dda4048f5753dac34e73e"
    }
    scan = json.loads(requests.get(full_url, headers=headers).text)
    scan_stats = scan["data"]["attributes"]["last_analysis_stats"]
    print(f"Last analysis stats for {url} :")
    print(scan_stats)
    return True if scan_stats['malicious'] else False




