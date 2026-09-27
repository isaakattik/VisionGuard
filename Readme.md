
# 🛡️ PhishGuard & Threat Intel Agent

![Python](https://img.shields.io/badge/Python-3.10%2B-blue)
![TensorFlow](https://img.shields.io/badge/TensorFlow-2.x-orange)
![Playwright](https://img.shields.io/badge/Playwright-Sandbox-green)
![NVIDIA NIM](https://img.shields.io/badge/NVIDIA%20NIM-Llama%203.1%2070B-76B900)
![Streamlit](https://img.shields.io/badge/Streamlit-UI-red)

An automated **Zero-Trust AI Cybersecurity Agent** designed for real-time visual phishing detection and threat intelligence synthesis. PhishGuard isolates users from malicious payloads using a sandboxed browser, extracts multimodal page features, and generates executive SOC Incident Reports via NVIDIA NIM API.

---

## 🔑 Key Features

* **Zero-Trust Sandbox Scraping**: Leverages headless `Playwright` Chromium with disabled auto-downloads to safely visit suspect URLs and capture screenshots without user risk.
* **Multimodal Tri-Pillar Fusion**:
  1. **Visual Inference**: `ConvNeXtSmall` deep learning model fine-tuned for visual brand impersonation detection.
  2. **DOM & Code Analysis**: Extracts OCR text, embedded HTML content, and inline JavaScript scripts.
  3. **URL Heuristics**: Analyzes domain structure, typosquatting risks, direct IP usage, and sensitive target keywords.
* **Calibrated Decision Thresholds**: Features a defined decision logic ($<0.40$ Legit, $>0.75$ Scam, $0.40-0.75$ Uncertain/Deep Analysis).
* **Automated SOC Incident Reports**: Integrates **NVIDIA NIM API** (`Meta Llama 3.1 70B Instruct`) to generate structured threat reports with technical evidence and actionable remediation steps.
* **Enterprise Modular Architecture**: Codebase structured for seamless future expansion into `FastAPI` endpoints, Email Gateways, and `SIEM` systems.

---

## 🏗️ System Architecture

```text
[ Suspected URL ]
       │
       ▼
 ┌───────────────────────────┐
 │ Playwright Sandbox Engine │ ── (Isolated Capture & DOM Scraping)
 └─────────────┬─────────────┘
               │
      ┌────────┴────────────────────────┬────────────────────────┐
      ▼                                 ▼                        ▼
┌──────────────┐              ┌──────────────────┐    ┌────────────────────┐
│ Visual Model │              │  DOM & JS Engine │    │   URL Heuristics   │
│ConvNeXtSmall │              │  OCR & Scripts   │    │ Domain / Keywords  │
└──────┬───────┘              └────────┬─────────┘    └─────────┬──────────┘
       │                               │                        │
       └───────────────────────┬───────┴────────────────────────┘
                               ▼
               ┌───────────────────────────────┐
               │     groq API Fusion     │
               │   (openai/gpt-oss-20b)  │
               └───────────────┬───────────────┘
                               ▼
               ┌───────────────────────────────┐
               │  Executive SOC Incident Report│
               └───────────────────────────────┘
