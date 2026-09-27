import os
import re
from playwright.sync_api import sync_playwright, TimeoutError as PlaywrightTimeout

SCREENSHOT_PATH = os.path.join(os.path.dirname(__file__), "auto_screenshot.png")
TIMEOUT_MS = 15000

def capture_url(url: str) -> dict:
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    result = {
        "url": url,
        "screenshot_path": None,
        "js_scripts": [],
        "page_title": "",
        "error": None,
    }

    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(
                headless=True,
                args=["--no-sandbox", "--disable-dev-shm-usage", "--disable-gpu"]
            )
            context = browser.new_context(
                accept_downloads=False,
                java_script_enabled=True,
                viewport={"width": 1920, "height": 1000},
                device_scale_factor=1,
            )
            page = context.new_page()
            page.set_viewport_size({"width": 1920, "height": 1000})
            page.route("**/*.{mp4,avi,mov,exe,zip,rar,dmg}", lambda route: route.abort())
            page.goto(url, timeout=TIMEOUT_MS, wait_until="domcontentloaded")
            page.wait_for_timeout(2000)
            page.screenshot(path=SCREENSHOT_PATH, full_page=False)
            result["screenshot_path"] = SCREENSHOT_PATH
            result["page_title"] = page.title()
            scripts = page.eval_on_selector_all(
                "script",
                "elements => elements.map(el => el.innerText || el.src || '')"
            )
            result["js_scripts"] = [s for s in scripts if s.strip()]
            browser.close()

    except PlaywrightTimeout:
        result["error"] = f"Timeout: the page did not load within {TIMEOUT_MS // 1000} seconds."
    except Exception as e:
        result["error"] = f"Sandbox error: {str(e)}"

    return result

if __name__ == "__main__":
    test_url = "https://example.com"
    data = capture_url(test_url)
    print("Title:", data["page_title"])
    print("Screenshot saved:", data["screenshot_path"])
    print("JS scripts found:", len(data["js_scripts"]))
    if data["error"]:
        print("Error:", data["error"])