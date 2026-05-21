#!/usr/bin/env python3
"""
open_redirect_tester.py
========================

This script improves upon simple HTTP‐based open redirect checks by using a
headless browser to evaluate whether an application performs client‑side
redirection after page load. Many modern web applications implement
navigation logic in JavaScript rather than returning HTTP 3xx responses, so
relying solely on the `requests` library can miss DOM‑based open redirects.

Key features:

* Generates a series of test URLs using common redirection parameter names
  and multiple payload variations (including scheme‑relative and double
  encoded forms) to probe for different server‑ and client‑side checks.
* Uses Playwright to launch a headless Chromium browser for each test URL.
  After navigation it inspects the final `window.location.href` and any
  additional pages opened via `window.open` for the presence of the
  attacker‑controlled host.
* Performs a basic reflected open redirect check by looking for the
  payload string in the returned HTML when the HTTP status is 200.
* Accepts an optional authentication header (e.g. cookie) for logged‑in
  tests, and a flag to URL‑encode payloads.

Example usage:

    python3 open_redirect_tester.py -u https://example.com/login --payload https://evil.com --encode --auth "Cookie: session=abcd"

Before running this script make sure Playwright is installed and the
Chromium browser is available:

    pip install playwright
    playwright install chromium

Note: This script does not implement brute forcing of credentials. To test
post‑login redirects you must supply a valid session token via the
`--auth` option.
"""

import argparse
import asyncio
import random
import re
import sys
import time
from typing import List, Optional

import requests
from urllib.parse import quote_plus, urljoin

try:
    from playwright.async_api import async_playwright, Browser
except ImportError:
    async_playwright = None  # type: ignore


# A small pool of modern User‑Agent strings to randomise HTTP requests. This
# helps to avoid basic WAF restrictions based on static UAs.
USER_AGENTS: List[str] = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:124.0) Gecko/20100101 Firefox/124.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1",
]


# Common query parameter names that applications use to pass a next URL or
# return location. The script will iterate over each of these when
# constructing test URLs.
COMMON_PARAMS: List[str] = [
    "redirect", "redirect_uri", "redirect_url", "return", "returnUrl",
    "return_url", "next", "nextUrl", "next_url", "url", "target",
    "continue", "callback", "callback_url", "goto", "dest", "destination",
]

# Patterns considered suspicious in inline JavaScript. These are used as a
# heuristic for server‑side DOM analysis (when performing simple HTML
# requests) to detect potential open redirect sinks, as recommended by
# OWASP's testing guide【958456773754357†L68-L82】. Although true validation
# requires a browser, searching for these patterns in returned HTML can
# flag code that may be vulnerable.
DOM_VULNERABLE_PATTERNS: List[str] = [
    r"window\.location\s*\.href", r"window\.location\s*\.assign",
    r"window\.location\s*\.replace", r"window\.open\s*\(",
    r"location\s*=", r"location\.href", r"location\.assign",
    r"location\.replace", r"document\.location", r"URLSearchParams",
]


def random_user_agent() -> str:
    """Return a random User‑Agent string from the pool."""
    return random.choice(USER_AGENTS)


def get_delay(waf_level: str) -> int:
    """Return a random delay to help bypass simple WAF rate limits."""
    if waf_level == "medium":
        return random.randint(5, 7)
    if waf_level == "advanced":
        return random.randint(8, 12)
    return random.randint(2, 4)


def build_payload_variations(base: str) -> List[str]:
    """Generate a list of payload variations commonly used to bypass
    naive URL filters. Examples are based on the HackTricks list and
    OWASP guidance【193377348981531†L56-L76】."""
    host = re.sub(r"^https?://", "", base).rstrip("/")
    variations = [
        base,  # canonical fully qualified
        f"//{host}",  # scheme‑relative
        f"http://{host}",  # downgrade to HTTP
        f"https://{host}/%2F",  # slash encoded
        f"https://{host}/?x=1",
        f"https://{host}%2f",  # encoded slash with case variation
        f"https://{host}%252f",  # double encoded slash
        f"https://{host}%2F..",  # directory traversal style
        f"https://{host}#@",  # fragment confusion
        f"https://{host}@example.com",  # userinfo confusion
        f"https://example.com@{host}/",  # userinfo reversed
    ]
    return list(dict.fromkeys(variations))  # deduplicate preserving order


def perform_basic_reflected_test(
    url: str,
    param: str,
    payload: str,
    encode: bool,
    headers: dict,
) -> Optional[str]:
    """Perform a simple HTTP request to check for server‑side redirection
    (3xx) and basic reflection in the response body. Returns a PoC string
    if a vulnerability is found, otherwise None.

    This function does not follow redirects (allow_redirects=False) so the
    Location header can be inspected. If the application returns a 3xx
    pointing directly to the attacker host, or if the payload appears in
    the response HTML, it reports a vulnerability.
    """
    if not url.startswith("http"):
        return None
    encoded_payload = quote_plus(payload) if encode else payload
    test_url = f"{url.rstrip('/')}/?{param}={encoded_payload}"
    try:
        resp = requests.get(test_url, headers=headers, timeout=10, allow_redirects=False)
    except Exception:
        return None

    # Check for direct HTTP redirect: confirmed only if destination host matches attacker host
    if resp.status_code in {301, 302, 303, 307, 308}:
        location = resp.headers.get("Location") or resp.headers.get("location")
        if location and host_in_payload(location, payload):
            return (
                f"Confirmed HTTP open redirect: {test_url} returned status {resp.status_code} with Location header {location}"
            )

    # Check for reflected payload in body (may indicate a reflected redirect or XSS)
    if payload in resp.text:
        start = max(resp.text.find(payload) - 60, 0)
        end = min(resp.text.find(payload) + len(payload) + 60, len(resp.text))
        snippet = resp.text[start:end]
        return (
            f"Suspicious: payload string reflected in response body at {test_url}. Snippet: ...{snippet}..."
        )

    # Heuristic: look for client‑side redirect sinks in HTML (DOM patterns). Flag as suspicious only.
    for pattern in DOM_VULNERABLE_PATTERNS:
        if re.search(pattern, resp.text, re.IGNORECASE):
            return (
                f"Suspicious: potential client‑side redirect sink found in HTML for {test_url} matching pattern '{pattern}'"
            )
    return None


def host_in_payload(url: str, payload: str) -> bool:
    """Return True if the attacker host from payload appears in the given URL."""
    try:
        attacker = re.sub(r"^https?://", "", payload).split("/", 1)[0]
        destination = re.sub(r"^https?://", "", url).split("/", 1)[0]
        return attacker.lower() in destination.lower()
    except Exception:
        return False


async def check_redirect_with_browser(
    base_url: str,
    param: str,
    payload: str,
    encode: bool,
    headers: dict,
    delay: int,
) -> Optional[str]:
    """Navigate to a mutated URL in a headless browser and detect client‑side
    redirection. The function returns a descriptive string only if the
    navigation ends on an external attacker‑controlled host or if a new
    page (opened via window.open) points to that host. This helps avoid
    false positives where the attacker URL appears in the query string of
    the final URL but the host remains the same as the application.

    We also record cases where the payload is reflected in the DOM after
    page load to highlight potential sinks, but we label those as
    suspicious rather than confirmed vulnerabilities.
    """
    # Skip if Playwright is unavailable
    if async_playwright is None:
        return None

    # Construct the test URL with the parameter and optional encoding
    encoded_payload = quote_plus(payload) if encode else payload
    test_url = f"{base_url.rstrip('/')}/?{param}={encoded_payload}"

    # Extract attacker host (e.g. evil.com) for comparison
    attacker_host = re.sub(r"^https?://", "", payload).split("/", 1)[0].lower()

    # Extract base (target) host from the provided base_url
    try:
        from urllib.parse import urlparse
        base_parsed = urlparse(base_url)
        base_host = (base_parsed.hostname or "").lower()
    except Exception:
        base_host = ""

    async with async_playwright() as p:
        browser: Browser = await p.chromium.launch(headless=True)
        context = await browser.new_context(extra_http_headers=headers)
        vuln_info: Optional[str] = None

        # Callback for pages opened via window.open(). If the page
        # navigates to the attacker host we flag a confirmed vulnerability.
        async def on_page(page):
            nonlocal vuln_info
            try:
                await page.wait_for_load_state("domcontentloaded", timeout=10000)
                url = page.url
                # Parse the host of the new page
                parsed = urlparse(url)
                new_host = (parsed.hostname or "").lower()
                if new_host and new_host != base_host and new_host.endswith(attacker_host):
                    vuln_info = (
                        f"Client‑side open redirect via window.open detected: "
                        f"visiting {test_url} opened new page {url} (host {new_host})"
                    )
            except Exception:
                # Ignore errors during page load
                pass

        context.on("page", on_page)
        page = await context.new_page()
        try:
            await page.goto(test_url, wait_until="networkidle", timeout=15000)
            current_url = page.url
            parsed_current = urlparse(current_url)
            current_host = (parsed_current.hostname or "").lower()
            # Confirmed vulnerability only if final host is attacker_host (or subdomain) and different from base_host
            if current_host and current_host != base_host and current_host.endswith(attacker_host):
                vuln_info = (
                    f"Client‑side open redirect detected: visiting {test_url} redirected "
                    f"browser to {current_url} (host {current_host})"
                )
            else:
                # Check for reflected payload in final HTML content
                content = await page.content()
                if payload in content and vuln_info is None:
                    vuln_info = (
                        f"Suspicious: payload string reflected in DOM after page load for {test_url}. "
                        f"The host remained {current_host}; investigate potential DOM sinks."
                    )
        except Exception:
            # Ignore navigation errors and timeouts
            pass
        finally:
            await context.close()
            await browser.close()
        # Random delay to avoid triggering rate limits
        await asyncio.sleep(delay)
        return vuln_info


async def run_tests_async(
    url: str,
    payload: str,
    encode: bool,
    headers: dict,
    waf_level: str,
    max_concurrency: Optional[int] = None,
) -> List[str]:
    """Orchestrate tests across all parameter names and payload variations.
    Returns a list of vulnerability descriptions found.
    """
    findings: List[str] = []
    delay = get_delay(waf_level)

    # Generate all test cases and schedule browser tests with optional concurrency control
    tasks = []

    # Prepare a semaphore if concurrency is limited. A None value means unlimited.
    sem: Optional[asyncio.Semaphore] = None
    if max_concurrency is not None and max_concurrency > 0:
        sem = asyncio.Semaphore(max_concurrency)

    async def schedule_browser_test(param: str, variation: str) -> Optional[str]:
        """
        Wrapper coroutine that optionally limits the number of concurrent
        browser tests using a semaphore.
        """
        # Acquire semaphore if defined
        if sem is not None:
            async with sem:
                return await check_redirect_with_browser(url, param, variation, encode, headers, delay)
        else:
            # No semaphore: run directly
            return await check_redirect_with_browser(url, param, variation, encode, headers, delay)

    for param in COMMON_PARAMS:
        for variation in build_payload_variations(payload):
            # Perform a basic reflected test via HTTP for quick detection
            poc = perform_basic_reflected_test(url, param, variation, encode, headers)
            if poc:
                findings.append(poc)
            # Then schedule a browser‑based test for more subtle client‑side behaviour
            tasks.append(schedule_browser_test(param, variation))

    # Execute browser tests concurrently with optional concurrency control
    browser_results = await asyncio.gather(*tasks, return_exceptions=True)
    for result in browser_results:
        if isinstance(result, str) and result:
            findings.append(result)
    return findings


def parse_auth_header(auth: Optional[str]) -> dict:
    """Parse a simple authentication header (e.g. "Cookie: session=abc")."""
    headers = {"User-Agent": random_user_agent()}
    if auth:
        if ":" not in auth:
            print("[!] Invalid auth header format. Use 'HeaderName: value'", file=sys.stderr)
        else:
            key, value = auth.split(":", 1)
            headers[key.strip()] = value.strip()
    return headers


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Comprehensive Open Redirect tester using requests and Playwright."
    )
    parser.add_argument(
        "-u", "--url", required=True, help="Base URL to test (e.g. https://target.com/login)"
    )
    parser.add_argument(
        "-p", "--payload", default="https://example.org", help="Malicious payload URL"
    )
    parser.add_argument(
        "--encode", action="store_true", help="URL‑encode the payload value"
    )
    parser.add_argument(
        "--auth",
        help="Additional authentication header, e.g. 'Cookie: session=abcd' for logged‑in tests",
    )
    parser.add_argument(
        "--waf",
        choices=["basic", "medium", "advanced"],
        default="basic",
        help="Simulate WAF protection by adding random delay between tests",
    )
    parser.add_argument(
        "--concurrency",
        type=int,
        default=None,
        help=(
            "Maximum number of concurrent browser tests. Lower this value if "
            "system resources are constrained or to avoid spawning too many Playwright "
            "instances at once. Default is unlimited."
        ),
    )
    # Backwards compatibility: allow --max-concurrency as an alias
    parser.add_argument(
        "--max-concurrency",
        dest="concurrency",
        type=int,
        help=argparse.SUPPRESS,
    )
    args = parser.parse_args()

    headers = parse_auth_header(args.auth)

    # Ensure Playwright is installed
    if async_playwright is None:
        print(
            "[!] Playwright is not installed. Install it with 'pip install playwright' and run 'playwright install chromium'.",
            file=sys.stderr,
        )
        sys.exit(1)

    # Run asynchronous tests
    findings = asyncio.run(
        run_tests_async(
            args.url,
            args.payload,
            args.encode,
            headers,
            args.waf,
            max_concurrency=args.concurrency,
        )
    )

    if findings:
        confirmed = [f for f in findings if f.lower().startswith("confirmed") or "client‑side open redirect detected" in f.lower()]
        suspicious = [f for f in findings if f.lower().startswith("suspicious") or "potential" in f.lower()]
        print("\n=== Results ===")
        if confirmed:
            print("\n-- Confirmed vulnerabilities --")
            for f in confirmed:
                print(f"* {f}")
        if suspicious:
            print("\n-- Suspicious findings (investigate further) --")
            for f in suspicious:
                print(f"* {f}")
        # Print any remaining findings not classified above
        remaining = [f for f in findings if f not in confirmed and f not in suspicious]
        if remaining:
            print("\n-- Other findings --")
            for f in remaining:
                print(f"* {f}")
    else:
        print("\nNo open redirect behaviour detected with the given test cases.")


if __name__ == "__main__":
    main()
