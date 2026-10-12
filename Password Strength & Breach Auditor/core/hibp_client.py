"""
HIBP (Have I Been Pwned) k-Anonymity API Client.
Zero-knowledge breach auditing: only the first 5 characters of the SHA-1 hash
are ever sent over the wire. The full password NEVER leaves the client.
"""

import hashlib
import requests
from typing import Dict, Any, Optional

HIBP_API_URL = "https://api.pwnedpasswords.com/range/"

def audit_pwned_password(password: str, timeout: float = 6.0) -> Dict[str, Any]:
    """
    Checks if a password has appeared in known data breaches using HIBP k-Anonymity API.
    
    Returns a dictionary with:
      - 'breached': bool (True if found)
      - 'count': int (number of times seen in leaks)
      - 'sha1_full': str (full SHA-1 hash computed locally)
      - 'sha1_prefix': str (first 5 chars sent to API)
      - 'sha1_suffix': str (last 35 chars matched locally)
      - 'api_url': str (the actual endpoint queried)
      - 'total_suffixes': int (number of hash suffixes returned by API)
      - 'error': Optional[str] (error message if network failed, else None)
    """
    if not password:
        return {
            "breached": False,
            "count": 0,
            "sha1_full": "",
            "sha1_prefix": "",
            "sha1_suffix": "",
            "api_url": "",
            "total_suffixes": 0,
            "error": "Empty password"
        }

    # 1. Compute SHA-1 hash locally in memory
    sha1_full = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix = sha1_full[:5]
    suffix = sha1_full[5:]
    api_url = f"{HIBP_API_URL}{prefix}"

    headers = {
        "User-Agent": "Password-Auditor-kAnonymity-Client/1.0",
        "Add-Padding": "true"  # Requests padding against response-length analysis
    }

    try:
        response = requests.get(api_url, headers=headers, timeout=timeout)
        if response.status_code != 200:
            return {
                "breached": False,
                "count": 0,
                "sha1_full": sha1_full,
                "sha1_prefix": prefix,
                "sha1_suffix": suffix,
                "api_url": api_url,
                "total_suffixes": 0,
                "error": f"API returned HTTP {response.status_code}"
            }

        # 2. Parse returned suffixes
        lines = response.text.splitlines()
        suffix_dict = {}
        for line in lines:
            if ":" in line:
                sfx, count_str = line.strip().split(":", 1)
                try:
                    count = int(count_str)
                except ValueError:
                    count = 0
                suffix_dict[sfx.upper()] = count

        # 3. Client-side local lookup: did our suffix match?
        breach_count = suffix_dict.get(suffix, 0)
        is_breached = breach_count > 0

        return {
            "breached": is_breached,
            "count": breach_count,
            "sha1_full": sha1_full,
            "sha1_prefix": prefix,
            "sha1_suffix": suffix,
            "api_url": api_url,
            "total_suffixes": len(lines),
            "error": None
        }

    except requests.exceptions.Timeout:
        return {
            "breached": False,
            "count": 0,
            "sha1_full": sha1_full,
            "sha1_prefix": prefix,
            "sha1_suffix": suffix,
            "api_url": api_url,
            "total_suffixes": 0,
            "error": "Connection timed out while reaching HIBP API"
        }
    except requests.exceptions.RequestException as e:
        return {
            "breached": False,
            "count": 0,
            "sha1_full": sha1_full,
            "sha1_prefix": prefix,
            "sha1_suffix": suffix,
            "api_url": api_url,
            "total_suffixes": 0,
            "error": f"Network error: {str(e)}"
        }
