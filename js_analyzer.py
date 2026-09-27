
import re
from typing import List


THREAT_PATTERNS = [
    {
        "name": "Code Obfuscation (eval/unescape)",
        "pattern": r"\beval\s*\(|\bunescape\s*\(|String\.fromCharCode\s*\(",
        "severity": "HIGH",
        "description": "Code is hidden/obfuscated to avoid detection"
    },
    {
        "name": "Base64 Decoding",
        "pattern": r"\batob\s*\(|btoa\s*\(",
        "severity": "MEDIUM",
        "description": "Base64 encoding used — possible payload hiding"
    },
    {
        "name": "Credential / Form Hijacking",
        "pattern": r"\.value|password|getElementById\(['\"]pass|\.submit\s*\(",
        "severity": "HIGH",
        "description": "Script accesses form fields — possible data theft"
    },
    {
        "name": "Suspicious External Request",
        "pattern": r"fetch\s*\(|XMLHttpRequest|axios\.|\.post\s*\(|\.get\s*\(",
        "severity": "MEDIUM",
        "description": "Data sent to external server"
    },
    {
        "name": "Forced Redirect",
        "pattern": r"window\.location\s*=|location\.href\s*=|location\.replace\s*\(",
        "severity": "MEDIUM",
        "description": "Page forcefully redirects the user"
    },
    {
        "name": "Anti-Debugging / DevTools Block",
        "pattern": r"\bdebugger\b|disable.*right.*click|contextmenu",
        "severity": "HIGH",
        "description": "Script tries to block inspection — evasion technique"
    },
    {
        "name": "Crypto Mining",
        "pattern": r"CoinHive|coinhive|cryptonight|minero|miner\.start",
        "severity": "CRITICAL",
        "description": "Crypto mining script detected"
    },
    {
        "name": "Keylogger Pattern",
        "pattern": r"onkeypress|onkeydown|addEventListener\(['\"]key",
        "severity": "HIGH",
        "description": "Script listens to keyboard input — possible keylogger"
    },
]

def analyze_js(scripts: List[str]) -> dict:
    """
    Analyzes a list of JavaScript code strings for malicious patterns.
    Returns a dict with: findings, risk_level, summary
    """
    if not scripts:
        return {
            "findings": [],
            "risk_level": "NONE",
            "summary": "No JavaScript found on this page."
        }


    combined_js = "\n".join(scripts)

    findings = []
    for threat in THREAT_PATTERNS:
        matches = re.findall(threat["pattern"], combined_js, re.IGNORECASE)
        if matches:
            findings.append({
                "name": threat["name"],
                "severity": threat["severity"],
                "description": threat["description"],
                "occurrences": len(matches),
            })


    severities = [f["severity"] for f in findings]
    if "CRITICAL" in severities:
        risk_level = "CRITICAL"
    elif "HIGH" in severities:
        risk_level = "HIGH"
    elif "MEDIUM" in severities:
        risk_level = "MEDIUM"
    else:
        risk_level = "LOW"

    summary = f"Found {len(findings)} threat pattern(s) in {len(scripts)} JS script(s)."

    return {
        "findings": findings,
        "risk_level": risk_level,
        "summary": summary,
    }
    
if __name__ == "__main__":

    fake_scripts = [
        "eval(unescape('%61%6C%65%72%74'))",
        "window.location = 'http://evil.com'",
        "document.getElementById('password').value",
    ]
    result = analyze_js(fake_scripts)
    print("Risk Level:", result["risk_level"])
    print("Summary:", result["summary"])
    for f in result["findings"]:
        print(f"  [{f['severity']}] {f['name']} — {f['occurrences']} occurrence(s)")
        
        