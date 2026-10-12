"""
Pattern Detector Engine.
Detects common structural flaws, sequences, keyboard walks, repetitions,
leetspeak variants, common dictionary passwords, and predictable date patterns.
"""

import re
from typing import List, Dict, Any

COMMON_PASSWORDS = {
    "password", "admin", "welcome", "login", "master", "dragon", "shadow",
    "monkey", "sunshine", "princess", "football", "baseball", "trustno1",
    "letmein", "superman", "batman", "secret", "default", "root", "guest",
    "test", "testing", "qwerty", "computer", "access", "hunter", "hunter2",
    "iloveyou", "mustang", "michael", "jessica", "charlie", "jordan",
    "starwars", "orange", "yellow", "purple", "killer", "matrix", "freedom",
    "pass", "user", "server", "system", "cisco", "oracle", "database",
    "service", "support", "manager", "security", "internet", "network",
    "spring", "summer", "autumn", "winter", "january", "february", "december",
    "monday", "friday", "sunday", "hockey", "soccer", "tennis", "ninja"
}

KEYBOARD_WALKS = [
    "qwertyuiop", "asdfghjkl", "zxcvbnm",
    "poiuytrewq", "lkjhgfdsa", "mnbvcxz",
    "1234567890", "0987654321",
    "1qaz", "2wsx", "3edc", "4rfv", "5tgb", "6yhn", "7ujm", "8ik,", "9ol.",
    "zaq1", "xsw2", "cde3", "vfr4", "bgt5", "nhy6", "mju7"
]

LEET_MAP = {
    '@': 'a', '4': 'a',
    '8': 'b',
    '(': 'c', '<': 'c',
    '3': 'e',
    '#': 'h',
    '1': 'i', '!': 'i', '|': 'i',
    '0': 'o',
    '9': 'g',
    '$': 's', '5': 's',
    '7': 't', '+': 't'
}

def normalize_leetspeak(text: str) -> str:
    """Converts common leetspeak characters to standard alphabet."""
    chars = []
    for c in text.lower():
        chars.append(LEET_MAP.get(c, c))
    return "".join(chars)

def detect_patterns(password: str) -> List[Dict[str, Any]]:
    """
    Analyzes password for insecure patterns and returns list of detected flaws.
    Each item contains:
      - 'name': str
      - 'severity': 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW'
      - 'description': str
      - 'penalty': int (score deduction)
      - 'match': str
    """
    findings = []
    if not password:
        return findings

    pwd_lower = password.lower()
    pwd_norm = normalize_leetspeak(password)

    # 1. Very short length check
    if len(password) < 8:
        findings.append({
            "name": "Critically Short Length",
            "severity": "CRITICAL",
            "description": f"Password has only {len(password)} characters. Minimum recommended length is 12-16 characters.",
            "penalty": 35,
            "match": password
        })
    elif len(password) < 12:
        findings.append({
            "name": "Sub-optimal Length",
            "severity": "MEDIUM",
            "description": f"Length of {len(password)} is below the modern 12-character recommended baseline.",
            "penalty": 15,
            "match": password
        })

    # 2. Repeated character runs (e.g., 'aaa', '1111')
    repeat_matches = re.findall(r'(.)\1{2,}', password)
    if repeat_matches:
        full_repeats = [m.group() for m in re.finditer(r'(.)\1{2,}', password)]
        findings.append({
            "name": "Repeated Character Run",
            "severity": "HIGH",
            "description": f"Contains identical consecutive characters: '{', '.join(full_repeats)}'.",
            "penalty": 15,
            "match": ", ".join(full_repeats)
        })

    # 3. Sequential numeric runs (e.g., '1234', '9876')
    def has_seq_digits(s: str) -> List[str]:
        seqs = []
        for i in range(len(s) - 2):
            chunk = s[i:i+3]
            if chunk.isdigit():
                d0, d1, d2 = int(chunk[0]), int(chunk[1]), int(chunk[2])
                if (d1 == d0 + 1 and d2 == d1 + 1) or (d1 == d0 - 1 and d2 == d1 - 1):
                    # expand sequence
                    j = i + 3
                    while j < len(s) and s[j].isdigit():
                        if d1 > d0 and int(s[j]) == int(s[j-1]) + 1:
                            j += 1
                        elif d1 < d0 and int(s[j]) == int(s[j-1]) - 1:
                            j += 1
                        else:
                            break
                    seqs.append(s[i:j])
        return list(set(seqs))

    digit_seqs = has_seq_digits(password)
    if digit_seqs:
        findings.append({
            "name": "Sequential Numbers",
            "severity": "HIGH",
            "description": f"Predictable numeric sequence detected: '{', '.join(digit_seqs)}'.",
            "penalty": 15,
            "match": ", ".join(digit_seqs)
        })

    # 4. Sequential alphabetical runs (e.g., 'abc', 'xyz', 'cba')
    def has_seq_alpha(s: str) -> List[str]:
        seqs = []
        low = s.lower()
        for i in range(len(low) - 2):
            if low[i].isalpha() and low[i+1].isalpha() and low[i+2].isalpha():
                o0, o1, o2 = ord(low[i]), ord(low[i+1]), ord(low[i+2])
                if (o1 == o0 + 1 and o2 == o1 + 1) or (o1 == o0 - 1 and o2 == o1 - 1):
                    j = i + 3
                    while j < len(low) and low[j].isalpha():
                        if o1 > o0 and ord(low[j]) == ord(low[j-1]) + 1:
                            j += 1
                        elif o1 < o0 and ord(low[j]) == ord(low[j-1]) - 1:
                            j += 1
                        else:
                            break
                    seqs.append(s[i:j])
        return list(set(seqs))

    alpha_seqs = has_seq_alpha(password)
    if alpha_seqs:
        findings.append({
            "name": "Sequential Alphabetical Run",
            "severity": "MEDIUM",
            "description": f"Consecutive alphabetical sequence detected: '{', '.join(alpha_seqs)}'.",
            "penalty": 12,
            "match": ", ".join(alpha_seqs)
        })

    # 5. Keyboard walks (e.g. 'qwerty', 'asdfgh', '1qaz')
    found_walks = []
    for walk in KEYBOARD_WALKS:
        for length in range(4, len(walk) + 1):
            sub = walk[:length]
            if sub in pwd_lower:
                found_walks.append(sub)
    if found_walks:
        # take longest
        found_walks.sort(key=len, reverse=True)
        findings.append({
            "name": "Keyboard Walk Pattern",
            "severity": "HIGH",
            "description": f"Common keyboard physical path detected: '{found_walks[0]}'. Easily cracked by specialized rule-based masks.",
            "penalty": 20,
            "match": found_walks[0]
        })

    # 6. Common dictionary / breached words
    matched_words = []
    for word in COMMON_PASSWORDS:
        if len(word) >= 4 and word in pwd_lower:
            matched_words.append(word)
    if matched_words:
        matched_words.sort(key=len, reverse=True)
        findings.append({
            "name": "Common Dictionary Word",
            "severity": "CRITICAL",
            "description": f"Contains frequently targeted word: '{matched_words[0]}'. Attackers prioritize dictionary permutations.",
            "penalty": 25,
            "match": matched_words[0]
        })

    # 7. Leetspeak substitution of common words
    if not matched_words:
        leet_matches = []
        for word in COMMON_PASSWORDS:
            if len(word) >= 4 and word in pwd_norm and word not in pwd_lower:
                leet_matches.append(word)
        if leet_matches:
            leet_matches.sort(key=len, reverse=True)
            findings.append({
                "name": "Predictable Leetspeak Substitution",
                "severity": "HIGH",
                "description": f"Appears to be disguised common word '{leet_matches[0]}' using basic character substitution (e.g. @->a, 0->o, 1->i, $->s).",
                "penalty": 18,
                "match": leet_matches[0]
            })

    # 8. Date or Year pattern (e.g. 1950 - 2035)
    year_match = re.search(r'\b(19\d{2}|20[0-3]\d)\b', password)
    if year_match:
        findings.append({
            "name": "Four-Digit Year Pattern",
            "severity": "MEDIUM",
            "description": f"Appears to contain a calendar birth/event year '{year_match.group(0)}'.",
            "penalty": 10,
            "match": year_match.group(0)
        })

    # 9. Predictable capitalization & suffix layout (e.g., 'Word123!')
    if re.match(r'^[A-Z][a-z]+[0-9]+[!@#$%^&*()_+\-=\[\]{};:\'",.<>?/`~]$', password):
        findings.append({
            "name": "Template Structural Pattern (Capital + Word + Digits + Symbol)",
            "severity": "HIGH",
            "description": "Follows the most heavily targeted human template: Capital letter at start, followed by lowercase word, then digits and symbol at the very end.",
            "penalty": 18,
            "match": "Standard Human Template"
        })
    elif re.match(r'^[a-z]+$', password):
        findings.append({
            "name": "Single Character Class (All Lowercase)",
            "severity": "HIGH",
            "description": "Entire password consists only of lowercase letters without variation.",
            "penalty": 20,
            "match": "All Lowercase"
        })
    elif re.match(r'^[0-9]+$', password):
        findings.append({
            "name": "PIN / All Numeric",
            "severity": "CRITICAL",
            "description": "Password consists entirely of digits with negligible keyspace.",
            "penalty": 35,
            "match": "All Digits"
        })

    return findings
