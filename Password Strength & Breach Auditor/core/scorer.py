"""
Password Security Scoring & Recommendation Engine.
Synthesizes length, entropy, structural patterns, and breach status
into an overall 0-100 score with detailed actionable recommendations.
"""

from typing import Dict, Any, List

def calculate_score(
    password: str,
    entropy_info: Dict[str, Any],
    patterns: List[Dict[str, Any]],
    breach_info: Dict[str, Any]
) -> Dict[str, Any]:
    """
    Computes overall security score and produces recommendations.
    """
    if not password:
        return {
            "score": 0,
            "status_label": "NO PASSWORD ENTERED",
            "status_code": "EMPTY",
            "status_color": "#94a3b8",
            "is_compromised": False,
            "summary_text": "Enter a password above to evaluate strength and breach status.",
            "recommendations": [
                "Enter a password or click '🎲 Generate Strong Password' to test a cryptographically secure credential."
            ]
        }

    is_compromised = breach_info.get("breached", False)
    breach_count = breach_info.get("count", 0)

    # Base score components
    # 1. Length scoring (up to 35 points)
    length = len(password)
    if length < 8:
        length_score = 4
    elif length < 10:
        length_score = 12
    elif length < 12:
        length_score = 18
    elif length < 16:
        length_score = 26
    elif length < 20:
        length_score = 31
    else:
        length_score = 35

    # 2. Diversity scoring (up to 25 points)
    diversity_score = 0
    if entropy_info.get("has_lower"):
        diversity_score += 5
    if entropy_info.get("has_upper"):
        diversity_score += 5
    if entropy_info.get("has_digit"):
        diversity_score += 6
    if entropy_info.get("has_symbol"):
        diversity_score += 7
    if entropy_info.get("has_space") or entropy_info.get("has_unicode"):
        diversity_score += 2

    # 3. Entropy scoring (up to 30 points)
    eff_entropy = entropy_info.get("effective_entropy_bits", 0.0)
    if eff_entropy < 25:
        entropy_score = 4
    elif eff_entropy < 40:
        entropy_score = 10
    elif eff_entropy < 55:
        entropy_score = 16
    elif eff_entropy < 70:
        entropy_score = 22
    elif eff_entropy < 85:
        entropy_score = 27
    else:
        entropy_score = 30

    # 4. Bonus for long passphrases (>= 20 chars with > 3 words or high entropy)
    bonus = 0
    if length >= 20 and eff_entropy >= 60:
        bonus = 10

    # 5. Pattern penalties
    total_penalty = sum(p.get("penalty", 0) for p in patterns)
    total_penalty = min(50, total_penalty)

    raw_score = length_score + diversity_score + entropy_score + bonus - total_penalty
    raw_score = max(5, min(100, raw_score))

    # If compromised in HIBP public leaks, security score drops to 0!
    if is_compromised:
        final_score = 0
        status_label = "COMPROMISED (Found in breaches!)"
        status_code = "COMPROMISED"
        status_color = "#ef4444"
        summary_text = f"BREACH DETECTED: Seen in {breach_count:,} public data leaks!"
    else:
        final_score = raw_score
        if final_score < 30:
            status_label = "VERY WEAK"
            status_code = "VERY_WEAK"
            status_color = "#ef4444"
            summary_text = "Highly vulnerable to basic brute-force and dictionary attacks."
        elif final_score < 55:
            status_label = "WEAK"
            status_code = "WEAK"
            status_color = "#f97316"
            summary_text = "Below security standards. Vulnerable to fast GPU cracking."
        elif final_score < 75:
            status_label = "MODERATE"
            status_code = "MODERATE"
            status_color = "#eab308"
            summary_text = "Acceptable for non-critical accounts, but could be strengthened."
        elif final_score < 90:
            status_label = "STRONG"
            status_code = "STRONG"
            status_color = "#10b981"
            summary_text = "High resistance against offline cracking and credential attacks."
        else:
            status_label = "VERY STRONG (Bulletproof)"
            status_code = "EXCELLENT"
            status_color = "#059669"
            summary_text = "Maximum security rating! Exceptional keyspace and entropy."

    # Generate targeted actionable recommendations
    recommendations = []

    if is_compromised:
        recommendations.append(
            f"🚨 CRITICAL ACTION REQUIRED: This exact password was found in {breach_count:,} public data leaks. "
            "Never use this password for any account. Automated credential-stuffing bots test these databases immediately."
        )

    if length < 12:
        recommendations.append(
            f"• Increase password length: Current length is {length}. Aim for at least 14 to 16 characters. "
            "Every added character multiplies attacker search space exponentially."
        )

    missing_classes = []
    if not entropy_info.get("has_upper"):
        missing_classes.append("uppercase letters (A-Z)")
    if not entropy_info.get("has_lower"):
        missing_classes.append("lowercase letters (a-z)")
    if not entropy_info.get("has_digit"):
        missing_classes.append("numbers (0-9)")
    if not entropy_info.get("has_symbol"):
        missing_classes.append("symbols (!@#$%^&*...)")

    if missing_classes:
        recommendations.append(
            f"• Add missing character varieties: Incorporate {', '.join(missing_classes)} to expand character pool."
        )

    for p in patterns:
        if p["name"] == "Keyboard Walk Pattern":
            recommendations.append("• Avoid keyboard walks (e.g. 'qwerty', 'asdfgh'): Attackers use specialized spatial dictionaries.")
        elif p["name"] == "Sequential Numbers":
            recommendations.append("• Eliminate sequential numbers (e.g. '1234'): These are trivially tested in brute-force masks.")
        elif p["name"] == "Sequential Alphabetical Run":
            recommendations.append("• Avoid alphabetical sequences (e.g. 'abc'): Replace with non-contiguous random letters.")
        elif p["name"] == "Repeated Character Run":
            recommendations.append("• Remove repeated characters (e.g. 'aaa'): Repetition does not increase cryptographic keyspace.")
        elif p["name"] == "Common Dictionary Word":
            recommendations.append("• Eliminate common dictionary words: Attackers utilize targeted wordlists like RockYou containing millions of phrases.")
        elif p["name"] == "Predictable Leetspeak Substitution":
            recommendations.append("• Do not rely on simple character substitutions like '@' for 'a' or '0' for 'o': Cracking tools automatically apply these rule mutations.")
        elif p["name"] == "Four-Digit Year Pattern":
            recommendations.append("• Avoid incorporating calendar years (e.g. birth years or current year): Birth years are the first candidate tested by social engineering scripts.")

    if not recommendations or (len(recommendations) == 1 and not is_compromised):
        recommendations.append(
            "• Use a reputable open-source or commercial Password Manager (e.g., Bitwarden, KeePassXC, 1Password) so you never need to remember complex credentials."
        )
        recommendations.append(
            "• Enable Multi-Factor Authentication (MFA / 2FA) using hardware keys (YubiKey) or TOTP authenticator apps wherever supported."
        )

    return {
        "score": final_score,
        "status_label": status_label,
        "status_code": status_code,
        "status_color": status_color,
        "is_compromised": is_compromised,
        "breach_count": breach_count,
        "summary_text": summary_text,
        "recommendations": recommendations
    }
