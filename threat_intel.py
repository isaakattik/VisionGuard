
import re
import logging

try:
    from config import GEMINI_API_KEY, NVIDIA_API_KEY
except ImportError:
    import config
    NVIDIA_API_KEY = getattr(config, "NVIDIA_API_KEY", "")
    GEMINI_API_KEY = getattr(config, "GEMINI_API_KEY", NVIDIA_API_KEY)
from openai import APITimeoutError, OpenAI

logger = logging.getLogger(__name__)


def build_prompt(visual_data: dict, text_data: str, url_data: dict, js_data: dict) -> str:
    """
    Builds a structured SOC analysis prompt from 3 analysis layers:
    1. CNN visual prediction
    2. OCR extracted text
    3. JavaScript threat findings
    """

    # Summarize JS findings clearly for the model
    if js_data.get("findings"):
        js_summary = f"Risk Level: {js_data['risk_level']}\n"
        for f in js_data["findings"]:
            js_summary += f"  - [{f['severity']}] {f['name']}: {f['description']} ({f['occurrences']} occurrence(s))\n"
    else:
        js_summary = "No suspicious JavaScript patterns detected."

    prompt = f"""
You are an expert Cybersecurity SOC Analyst. Analyze the following three-layer scan of a suspicious website:

-----------------------------------
LAYER 1 — VISUAL AI MODEL (CNN)
-----------------------------------
Classification: {visual_data.get('classification', 'N/A')}
Confidence Score: {visual_data.get('confidence_score', 0):.2%}

-----------------------------------
LAYER 2 — OCR EXTRACTED TEXT
-----------------------------------
{text_data[:1500] if text_data else "No text extracted."}

-----------------------------------
LAYER 3 — JAVASCRIPT THREAT ANALYSIS
-----------------------------------
{js_summary}

-----------------------------------
URL INFO
-----------------------------------
URL: {url_data.get('url', 'N/A')}
Domain: {url_data.get('domain', 'N/A')}
URL Suspicious: {url_data.get('is_suspicious', False)}
URL Reasons: {', '.join(url_data.get('reasons', [])) or 'None'}
-----------------------------------

Based on ALL three layers above, provide a structured SOC Incident Report with EXACTLY this format:

## Final Verdict
**Classification:** [SCAM / LEGIT / UNCERTAIN]
**Overall Confidence:** [0-100]%

## Threat Level
[CRITICAL / HIGH / MEDIUM / LOW / NONE]

## Analysis Summary
[2-4 sentences combining evidence from all 3 layers]

## Key Indicators
- [list the strongest red flags found]

## Recommended Actions
- [clear remediation steps]
"""
    return prompt.strip()


def _extract_classification(report_text: str) -> str:
    """Extracts the final classification label from the LLM report."""
    # Search for the verdict line specifically (handles optional brackets like [SCAM])
    match = re.search(r'\*\*Classification:\*\*\s*\[?\s*(SCAM|LEGIT|UNCERTAIN)\s*\]?', report_text, re.IGNORECASE)
    if match:
        return match.group(1).upper()
    # Fallback: scan full text
    text_upper = report_text.upper()
    if "SCAM" in text_upper:
        return "SCAM"
    elif "LEGIT" in text_upper:
        return "LEGIT"
    return "UNCERTAIN"


def _extract_confidence(report_text: str) -> float:
    """Extracts the overall confidence percentage from the LLM report."""
    # Matches both integer and decimal percentages e.g. 91% or 91.00%
    match = re.search(r'Overall Confidence[:\*\s]+(\d+(?:\.\d+)?)%', report_text, re.IGNORECASE)
    if match:
        return float(match.group(1)) / 100.0
    return 0.0


def generate_soc_report(
    visual_data: dict,
    text_data: str,
    url_data: dict,
    js_data: dict,
    api_key: str = None,
) -> dict:
    """
    Calls Google AI Studio / Gemini LLM with 3-layer input and returns a structured report dict:
    {
        "report": str,               # Full markdown SOC report
        "final_classification": str, # SCAM / LEGIT / UNCERTAIN
        "overall_confidence": float, # 0.0 - 1.0
    }
    """
    resolved_api_key = (api_key or GEMINI_API_KEY or NVIDIA_API_KEY or "").strip()
    if not resolved_api_key:
        return {
            "report": "[WARNING] API Key is not configured. Add your Google AI Studio key in the sidebar or .env file.",
            "final_classification": "UNKNOWN",
            "overall_confidence": 0.0,
        }

    prompt = build_prompt(visual_data, text_data, url_data, js_data)

    # Automatically select provider endpoint and model based on API key prefix
    is_groq = resolved_api_key.startswith("gsk_")
    is_nvidia = resolved_api_key.startswith("nvapi-")

    # if is_groq:
    base_url = "https://api.groq.com/openai/v1"
    model_name = "openai/gpt-oss-20b"
    # elif is_nvidia:
    #     base_url = "https://integrate.api.nvidia.com/v1"
    #     model_name = "meta/llama-3.2-11b-vision-instruct"
    # else:
    #     base_url = "https://generativelanguage.googleapis.com/v1beta/openai/"
    #     model_name = "gemini-1.5-flash"

    try:
        client = OpenAI(
            api_key=resolved_api_key,
            base_url=base_url,
            timeout=60.0,
        )
        response = client.chat.completions.create(
            model=model_name,
            messages=[
                {
                    "role": "system",
                    "content": "You are a cybersecurity SOC analyst. Be precise, structured, and always follow the exact report format requested.",
                },
                {"role": "user", "content": prompt},
            ],
            max_tokens=2048,
            temperature=0.1,
        )

        if not response.choices or not response.choices[0].message.content:
            logger.warning("AI model returned an empty response")
            return {
                "report": "The AI model returned an empty response. Please try again.",
                "final_classification": "UNKNOWN",
                "overall_confidence": 0.0,
            }

        raw_report = response.choices[0].message.content.strip()

        return {
            "report": raw_report,
            "final_classification": _extract_classification(raw_report),
            "overall_confidence": _extract_confidence(raw_report),
        }

    except APITimeoutError:
        logger.exception("AI model request timed out")
        return {
            "report": "[TIMEOUT] Request timed out. Please try again.",
            "final_classification": "UNKNOWN",
            "overall_confidence": 0.0,
        }
    except Exception as e:
        logger.exception(f"AI report generation failed: {e}")
        return {
            "report": f"[ERROR] Unable to generate the SOC report: {str(e)}",
            "final_classification": "UNKNOWN",
            "overall_confidence": 0.0,
        }


if __name__ == "__main__":
    # Local test — no API call, just prints the built prompt
    fake_visual = {"classification": "Scam", "confidence_score": 0.91}
    fake_text = "URGENT! Your account has been suspended. Verify now! Enter your password below."
    fake_url = {
        "url": "http://paypa1-secure.xyz/login",
        "domain": "paypa1-secure.xyz",
        "is_suspicious": True,
        "reasons": ["Contains sensitive keywords: login, paypal", "URL uses direct IP-like domain"],
    }
    fake_js = {
        "findings": [
            {"name": "Code Obfuscation (eval/unescape)", "severity": "HIGH", "description": "Obfuscated code", "occurrences": 2},
            {"name": "Credential / Form Hijacking", "severity": "HIGH", "description": "Accesses password fields", "occurrences": 1},
        ],
        "risk_level": "HIGH",
        "summary": "2 threat patterns found in 3 JS scripts.",
    }

    prompt = build_prompt(fake_visual, fake_text, fake_url, fake_js)
    print("[OK] Prompt built successfully:\n")
    print(prompt)