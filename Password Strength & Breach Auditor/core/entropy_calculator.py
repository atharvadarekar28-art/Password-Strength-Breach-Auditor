"""
Entropy & Crack Time Estimation Engine.
Calculates character pool sizes, Shannon & combinatorial entropy,
and simulates brute-force crack times across diverse attacker hardware configurations.
"""

import math
import string
from typing import Dict, Any, List

def format_time_duration(seconds: float) -> str:
    """Formats seconds into human-readable duration."""
    if seconds < 0.001:
        return "Instant (< 1 millisecond)"
    elif seconds < 1:
        return f"{seconds * 1000:.0f} milliseconds"
    elif seconds < 60:
        return f"{seconds:.2f} seconds"
    elif seconds < 3600:
        mins = seconds / 60
        return f"{mins:.1f} minutes"
    elif seconds < 86400:
        hrs = seconds / 3600
        return f"{hrs:.1f} hours"
    elif seconds < 2592000: # 30 days
        days = seconds / 86400
        return f"{days:.1f} days"
    elif seconds < 31536000: # 365 days
        months = seconds / 2592000
        return f"{months:.1f} months"
    elif seconds < 31536000 * 100:
        years = seconds / 31536000
        return f"{years:.1f} years"
    elif seconds < 31536000 * 10000:
        centuries = seconds / (31536000 * 100)
        return f"{centuries:.1f} centuries"
    elif seconds < 31536000 * 1_000_000:
        millennia = seconds / (31536000 * 1000)
        return f"{millennia:,.0f} millennia"
    else:
        years = seconds / 31536000
        exp = int(math.log10(years))
        mantissa = years / (10 ** exp)
        return f"{mantissa:.2f} × 10^{exp} years (Effectively Uncrackable)"

def analyze_entropy(password: str) -> Dict[str, Any]:
    """
    Analyzes password character composition, computes information entropy,
    and estimates crack times against various threat actors.
    """
    length = len(password)
    if length == 0:
        return {
            "length": 0,
            "pool_size": 0,
            "has_lower": False,
            "has_upper": False,
            "has_digit": False,
            "has_symbol": False,
            "has_space": False,
            "has_unicode": False,
            "entropy_bits": 0.0,
            "effective_entropy_bits": 0.0,
            "char_distribution": {},
            "combinations": 0,
            "crack_times": []
        }

    has_lower = any(c in string.ascii_lowercase for c in password)
    has_upper = any(c in string.ascii_uppercase for c in password)
    has_digit = any(c in string.digits for c in password)
    has_symbol = any(c in string.punctuation for c in password)
    has_space = any(c == ' ' for c in password)
    has_unicode = any(ord(c) > 127 for c in password)

    pool_size = 0
    if has_lower:
        pool_size += 26
    if has_upper:
        pool_size += 26
    if has_digit:
        pool_size += 10
    if has_symbol:
        pool_size += 33
    if has_space:
        pool_size += 1
    if has_unicode:
        pool_size += 128

    if pool_size == 0:
        pool_size = 1

    # Theoretical combinations: pool_size ^ length
    combinations = pool_size ** length

    # Combinatorial entropy: L * log2(R)
    entropy_bits = length * math.log2(pool_size)

    # Frequency-based Shannon entropy
    freq = {}
    for char in password:
        freq[char] = freq.get(char, 0) + 1
    shannon_h = 0.0
    for count in freq.values():
        p = count / length
        shannon_h -= p * math.log2(p)
    shannon_total = shannon_h * length

    # Effective entropy penalizing duplicate heavy repetitions
    unique_ratio = len(freq) / length
    effective_entropy = entropy_bits * (0.6 + 0.4 * unique_ratio)
    effective_entropy = round(min(entropy_bits, effective_entropy), 2)
    entropy_bits = round(entropy_bits, 2)

    # Attack hardware profiles (hashes / guesses per second)
    attack_scenarios = [
        {
            "name": "Online Throttled (100 guesses/s)",
            "description": "Web login portal with rate-limiting, CAPTCHA, or lockout delays.",
            "speed": 100,
            "speed_display": "100 / sec"
        },
        {
            "name": "Online Fast API (10,000 guesses/s)",
            "description": "Unthrottled public endpoint or distributed credential spraying.",
            "speed": 10_000,
            "speed_display": "10k / sec"
        },
        {
            "name": "Offline Standard CPU (100,000 hashes/s)",
            "description": "Standard workstation attacking salted hashes or CPU-heavy hashes.",
            "speed": 100_000,
            "speed_display": "100k / sec"
        },
        {
            "name": "Offline Modern GPU (10 Billion hashes/s)",
            "description": "Single NVIDIA RTX 4090 GPU running Hashcat against NTLM/SHA-1.",
            "speed": 10_000_000_000,
            "speed_display": "10 Billion / sec"
        },
        {
            "name": "Offline 8x GPU Rig (80 Billion hashes/s)",
            "description": "Dedicated 8-card cracking rig used by penetration testers.",
            "speed": 80_000_000_000,
            "speed_display": "80 Billion / sec"
        },
        {
            "name": "Botnet / Supercomputer (100 Trillion hashes/s)",
            "description": "Nation-state distributed cluster or massive botnet cloud infrastructure.",
            "speed": 100_000_000_000_000,
            "speed_display": "100 Trillion / sec"
        }
    ]

    crack_times = []
    # On average, an attacker searches half the keyspace: combinations / 2
    avg_attempts = combinations / 2 if combinations > 0 else 0

    for scenario in attack_scenarios:
        sec = avg_attempts / scenario["speed"]
        crack_times.append({
            "name": scenario["name"],
            "description": scenario["description"],
            "speed_display": scenario["speed_display"],
            "seconds": sec,
            "human_readable": format_time_duration(sec)
        })

    return {
        "length": length,
        "pool_size": pool_size,
        "has_lower": has_lower,
        "has_upper": has_upper,
        "has_digit": has_digit,
        "has_symbol": has_symbol,
        "has_space": has_space,
        "has_unicode": has_unicode,
        "entropy_bits": entropy_bits,
        "effective_entropy_bits": effective_entropy,
        "combinations": combinations,
        "crack_times": crack_times
    }
