
import importlib
import streamlit as st

GEMINI_API_KEY="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"


from url_sandbox import capture_url
from js_analyzer import analyze_js
from nlp_url_extractor import extract_text_from_image, analyze_url_features
from visual_inference import load_cnn_model, predict_visual_threat
import threat_intel
importlib.reload(threat_intel)
from threat_intel import generate_soc_report

# ─── Page Config ────────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="VisionGuard",
    page_icon="🛡️",
    layout="wide",
)

# ─── Header ─────────────────────────────────────────────────────────────────────
st.title("🛡️ VisionGuard")
st.caption("AI-Powered Phishing & Scam Detection Platform — Safe URL Detonation Engine")
st.divider()

# ─── Sidebar: API Key ────────────────────────────────────────────────────────────
with st.sidebar:
    st.header("⚙️ Configuration")
    default_key = GEMINI_API_KEY
    api_key_input = st.text_input(
        "Google AI Studio / Gemini API Key",
        value=default_key,
        type="password",
        help="Loaded automatically from .env if present. You can also paste another key here.",
    ).strip()
    if api_key_input:
        st.success("API Key loaded and active")
    else:
        st.warning("Enter your Google AI Studio API key to enable SOC report generation.")

    st.divider()
    st.markdown("**How it works:**")
    st.markdown("""
1. Paste a suspicious URL
2. A headless sandbox visits it safely
3. Screenshot is captured automatically
4. CNN + OCR + JS analysis runs
5. AI generates a full SOC report
""")
    st.info("⚠️ You never open the link yourself — the sandbox does it safely.")

# ─── Load CNN Model ──────────────────────────────────────────────────────────────
@st.cache_resource(show_spinner="Loading CNN model...")
def load_models():
    return load_cnn_model()

model = load_models()

# ─── Main Input ──────────────────────────────────────────────────────────────────
url_input = st.text_input(
    "🔗 Paste a suspicious URL to analyze:",
    placeholder="e.g. http://paypal-secure-login.xyz",
)

analyze_btn = st.button("🚀 Detonate & Analyze", type="primary", use_container_width=True)

# ─── Analysis Pipeline ───────────────────────────────────────────────────────────
if analyze_btn:
    if not url_input.strip():
        st.error("Please enter a URL first.")
        st.stop()

    # ── Step 1: Safe Sandbox Capture ─────────────────────────────────────────────
    with st.status("🔍 Step 1 — Opening URL in safe sandbox...", expanded=True) as status:
        sandbox_result = capture_url(url_input.strip())

        if sandbox_result["error"]:
            status.update(label="❌ Sandbox failed", state="error")
            st.error(f"Sandbox error: {sandbox_result['error']}")
            st.stop()

        st.write(f"✅ Page loaded: **{sandbox_result['page_title'] or 'No title'}**")
        st.write(f"✅ Screenshot captured")
        st.write(f"✅ JavaScript scripts extracted: **{len(sandbox_result['js_scripts'])}** script(s)")
        status.update(label="✅ Step 1 — Sandbox capture complete", state="complete")

    # ── Step 2: Visual CNN Analysis ───────────────────────────────────────────────
    with st.status("🧠 Step 2 — Running CNN visual analysis...", expanded=False) as status:
        visual_threat = predict_visual_threat(model, sandbox_result["screenshot_path"])
        st.write(f"Classification: **{visual_threat['classification']}** | Confidence: **{visual_threat['confidence_score']:.2%}**")
        status.update(label="✅ Step 2 — CNN analysis complete", state="complete")

    # ── Step 3: OCR Text Extraction ───────────────────────────────────────────────
    with st.status("📝 Step 3 — Extracting text via OCR...", expanded=False) as status:
        ocr_text = extract_text_from_image(sandbox_result["screenshot_path"])
        word_count = len(ocr_text.split()) if ocr_text else 0
        st.write(f"Extracted **{word_count}** words from the page screenshot.")
        status.update(label="✅ Step 3 — OCR extraction complete", state="complete")

    # ── Step 4: JavaScript Analysis ───────────────────────────────────────────────
    with st.status("⚙️ Step 4 — Analyzing JavaScript scripts...", expanded=False) as status:
        js_analysis = analyze_js(sandbox_result["js_scripts"])
        st.write(f"JS Risk Level: **{js_analysis['risk_level']}** | Threats found: **{len(js_analysis['findings'])}**")
        status.update(label="✅ Step 4 — JavaScript analysis complete", state="complete")

    # ── Step 5: URL Heuristic Analysis ───────────────────────────────────────────
    url_analysis = analyze_url_features(url_input.strip())

    # ── Step 6: AI SOC Report Generation ─────────────────────────────────────────
    with st.status("🤖 Step 5 — Generating AI SOC report...", expanded=False) as status:
        soc_result = generate_soc_report(
            visual_data=visual_threat,
            text_data=ocr_text,
            url_data=url_analysis,
            js_data=js_analysis,
            api_key=api_key_input,
        )
        status.update(label="✅ Step 5 — SOC report generated", state="complete")

    # ─── Results Dashboard ────────────────────────────────────────────────────────
    st.divider()
    st.subheader("📊 Analysis Results")

    # Final Verdict Banner
    classification = soc_result["final_classification"]
    confidence = soc_result["overall_confidence"]

    if classification == "SCAM":
        st.error(f"🚨 VERDICT: **{classification}** — Confidence: {confidence:.0%}")
    elif classification == "LEGIT":
        st.success(f"✅ VERDICT: **{classification}** — Confidence: {confidence:.0%}")
    else:
        st.warning(f"⚠️ VERDICT: **{classification}** — Confidence: {confidence:.0%}")

    st.divider()

    # ── 3-Column Results ──────────────────────────────────────────────────────────
    col1, col2, col3 = st.columns(3)

    with col1:
        st.subheader("🧠 CNN Visual Model")
        cnn_class = visual_threat["classification"]
        cnn_conf = visual_threat["confidence_score"]
        if cnn_class == "Scam":
            st.error(f"**{cnn_class}**")
        elif cnn_class == "Legit":
            st.success(f"**{cnn_class}**")
        else:
            st.warning(f"**{cnn_class}**")
        st.progress(cnn_conf, text=f"Confidence: {cnn_conf:.2%}")

    with col2:
        st.subheader("⚙️ JavaScript Analysis")
        js_risk = js_analysis["risk_level"]
        if js_risk in ("CRITICAL", "HIGH"):
            st.error(f"Risk: **{js_risk}**")
        elif js_risk == "MEDIUM":
            st.warning(f"Risk: **{js_risk}**")
        else:
            st.success(f"Risk: **{js_risk}**")
        if js_analysis["findings"]:
            for f in js_analysis["findings"]:
                st.caption(f"[{f['severity']}] {f['name']} ({f['occurrences']}x)")
        else:
            st.caption("No threats detected in scripts.")

    with col3:
        st.subheader("🔗 URL Analysis")
        if url_analysis["is_suspicious"]:
            st.error("**Suspicious URL**")
        else:
            st.success("**URL looks clean**")
        st.caption(f"Domain: `{url_analysis.get('domain', 'N/A')}`")
        if url_analysis["reasons"]:
            for r in url_analysis["reasons"]:
                st.caption(f"• {r}")

    st.divider()

    # ── Screenshot ────────────────────────────────────────────────────────────────
    st.subheader("🖼️ Captured Screenshot")
    st.caption("Automatically captured by the safe sandbox — you never visited this page.")
    st.image(
        sandbox_result["screenshot_path"],
        caption=f"Page: {sandbox_result['page_title'] or url_input} (1080×1920 Desktop View)",
        use_container_width=True,
    )

    # ── OCR Text ─────────────────────────────────────────────────────────────────
    with st.expander("📝 OCR Extracted Text"):
        st.text_area("Full OCR Output", ocr_text or "No text extracted.", height=200, label_visibility="collapsed")

    # ── JS Scripts ────────────────────────────────────────────────────────────────
    if sandbox_result["js_scripts"]:
        with st.expander(f"💻 Extracted JavaScript Scripts ({len(sandbox_result['js_scripts'])} found)"):
            for i, script in enumerate(sandbox_result["js_scripts"][:5], 1):  # show max 5
                st.caption(f"Script #{i}")
                st.code(script[:500] + ("..." if len(script) > 500 else ""), language="javascript")

    # ── SOC Report ────────────────────────────────────────────────────────────────
    st.divider()
    st.subheader("📋 Google AI Studio (Gemini) — AI SOC Incident Report")
    st.markdown(soc_result["report"])