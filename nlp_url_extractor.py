
import re
from urllib.parse import urlparse
from PIL import Image

try:
    import pytesseract
except ImportError:
    pytesseract = None

def extract_text_from_image(image_path):
    """Extract text from an image using OCR"""
    try:
        image = Image.open(image_path)
        if pytesseract:
            text = pytesseract.image_to_string(image)
            return text.strip()
        return "pytesseract library is not installed."
    except Exception as e:
        return f"Error extracting text: {str(e)}"

def analyze_url_features(url):
    """URL Analysis ("URL Features") and Detection of Suspicious Threat Indicators"""
    if not url:
        return {"url": "", "is_suspicious": False, "reasons": []}
        
    reasons = []
    parsed = urlparse(url if url.startswith(('http://', 'https://')) else f'http://{url}')
    domain = parsed.netloc or parsed.path.split('/')[0]
    
    # 1. Check for direct IP address usage instead of domain name
    ip_pattern = r'^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$'
    if re.match(ip_pattern, domain):
        reasons.append("URL uses direct IP address instead of domain name")
        
    # Check Url Length
    if len(url) > 75:
        reasons.append("URL length is unusually long (> 75 chars)")
        
    # 3.Check for '@' symbol in URL (Credential Spoofing Risk)
    if "@" in url:
        reasons.append("URL contains '@' symbol (credential spoofing risk)")
        
    # 4. Check for excessive subdomains (more than 3 dots)
    if domain.count('.') > 3:
        reasons.append("Excessive subdomains detected")
        
    # 5. Check for suspicious keywords
    keywords = ["login", "verify", "update", "account", "secure", "banking", "signin", "paypal", "bank"]
    found = [kw for kw in keywords if kw in url.lower()]
    if found:
        reasons.append(f"Contains sensitive target keywords: {', '.join(found)}")
        
    return {
        "url": url,
        "domain": domain,
        "is_suspicious": len(reasons) > 0,
        "reasons": reasons
    }