import base64
import os

import aiohttp
from dotenv import load_dotenv

"""
VirusTotal API v3
Limites free tier : 4 requêtes/min, 500 requêtes/jour
Doc : https://docs.virustotal.com/reference/url-info
"""

load_dotenv()
VT_TOKEN = os.getenv('VT_TOKEN')


async def scan_url(url: str) -> bool:
    """
    Scanne une URL via l'API VirusTotal v3.
    Utilise aiohttp (non-bloquant) pour ne pas bloquer l'event loop Discord.

    :param url: L'URL à analyser
    :return: True si l'URL est considérée malveillante, False sinon
    """
    if not VT_TOKEN:
        print("[VirusTotal] ERREUR : VT_TOKEN manquant dans le fichier .env")
        return False

    url_id   = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
    full_url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
    headers  = {
        "accept":   "application/json",
        "x-apikey": VT_TOKEN
    }

    print(f"[VirusTotal] Scan de : {url}")

    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(full_url, headers=headers, timeout=aiohttp.ClientTimeout(total=10)) as response:
                if response.status == 429:
                    print("[VirusTotal] Rate limit atteint (429). URL considérée sûre par défaut.")
                    return False
                if response.status != 200:
                    print(f"[VirusTotal] Réponse inattendue : HTTP {response.status}")
                    return False
                data = await response.json()

        scan_stats = data["data"]["attributes"]["last_analysis_stats"]
        print(f"[VirusTotal] Résultats pour {url} : {scan_stats}")
        return bool(scan_stats.get("malicious", 0))

    except KeyError as e:
        print(f"[VirusTotal] KeyError : clé {e} absente. Réponse : {data}")
        return False
    except aiohttp.ClientError as e:
        print(f"[VirusTotal] Erreur réseau : {e}")
        return False
    except Exception as e:
        print(f"[VirusTotal] Erreur inattendue : {e}")
        return False


