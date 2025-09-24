
import requests
import argparse
import random
import time
import concurrent.futures
import re
from urllib.parse import quote_plus

# Cores para saída
RED = '\033[91m'
ENDC = '\033[0m'

# User-Agents aleatórios
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:122.0) Gecko/20100101 Firefox/122.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1"
]

COMMON_PARAMS = ['redirect', 'redirect_to', 'url', 'next', 'return', 'dest', 'direct']
DOM_VULNERABLE_PATTERNS = [
    r"location\s*=", r"location\.host", r"location\.hostname", r"location\.href", 
    r"location\.assign\s*\(", r"open\s*\(", r"XMLHttpRequest\.open\s*\(", r"jQuery\.ajax\s*\("
]

tested_urls = set()
vulnerabilities = {"reflected": [], "stored": [], "dom": []}

def random_user_agent():
    return random.choice(USER_AGENTS)

def get_delay(waf_level):
    if waf_level == "medium":
        return random.randint(5, 7)
    elif waf_level == "advanced":
        return random.randint(8, 12)
    else:
        return random.randint(2, 4)

def test_open_redirect_reflected(url, payload, encode, headers, waf_level):
    for param in COMMON_PARAMS:
        separator = '&' if '?' in url else '?'
        modified_url = f"{url}{separator}{param}={quote_plus(payload) if encode else payload}"
        try:
            response = requests.get(modified_url, headers=headers, timeout=5, allow_redirects=False)

            if response.status_code in [301, 302, 303, 307, 308]:
                poc = f"URL vulnerável: {modified_url}\nA aplicação redireciona para um destino externo sem validação."
                vulnerabilities["reflected"].append((modified_url, poc))
                print(f"{RED}[VULNERÁVEL - OPEN REDIRECT REFLETIDO]{ENDC} {modified_url}\nPoC:\n{poc}")

            elif payload in response.text:
                start_index = response.text.find(payload) - 40
                end_index = response.text.find(payload) + len(payload) + 40
                reflected_snippet = response.text[max(0, start_index):min(len(response.text), end_index)]
                poc = f"URL vulnerável: {modified_url}\nO payload foi refletido na resposta HTML:\n...{reflected_snippet}..."
                vulnerabilities["reflected"].append((modified_url, poc))
                print(f"{RED}[VULNERÁVEL - OPEN REDIRECT REFLETIDO (NO HTML)]{ENDC} {modified_url}\nPoC:\n{poc}")

            time.sleep(get_delay(waf_level))
        except requests.exceptions.RequestException:
            continue

def test_open_redirect_stored(url, headers, payload, waf_level):
    try:
        response = requests.get(url, headers=headers, timeout=5)
        if response.status_code == 200:
            post_data = {'comment': payload}
            requests.post(url, headers=headers, data=post_data, timeout=5)
            time.sleep(get_delay(waf_level))
            response_check = requests.get(url, headers=headers, timeout=5)
            if payload in response_check.text:
                poc = f"URL vulnerável: {url}\nO payload foi armazenado e refletido na resposta."
                vulnerabilities["stored"].append((url, poc))
                print(f"{RED}[VULNERÁVEL - OPEN REDIRECT ARMAZENADO]{ENDC} {url}\nPoC:\n{poc}")
    except requests.exceptions.RequestException:
        return

def test_dom_based_redirect(url, headers, waf_level):
    try:
        response = requests.get(url, headers=headers, timeout=5, allow_redirects=True)
        if response.status_code in [301, 302, 303, 307, 308]:
            poc = f"URL vulnerável: {url}\nA aplicação está redirecionando diretamente via HTTP."
            vulnerabilities["dom"].append((url, poc))
            print(f"{RED}[POTENCIALMENTE VULNERÁVEL - DOM BASED]{ENDC} {url}\nPoC:\n{poc}")
            return

        for pattern in DOM_VULNERABLE_PATTERNS:
            if re.search(pattern, response.text):
                poc = f"URL vulnerável: {url}\nCódigo suspeito encontrado: {pattern}"
                vulnerabilities["dom"].append((url, poc))
                print(f"{RED}[POTENCIALMENTE VULNERÁVEL - DOM BASED]{ENDC} {url}\nPoC:\n{poc}")
                return

        time.sleep(get_delay(waf_level))
    except requests.exceptions.RequestException:
        return

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Scanner de Open Redirect (Refletido, Armazenado e DOM-Based).')
    parser.add_argument('-u', '--url', required=True, help='URL a ser testada.')
    parser.add_argument('-p', '--payload', default='https://myserver.com', help='Payload do Open Redirect.')
    parser.add_argument('--encode', action='store_true', help='Aplica URL encoding no payload.')
    parser.add_argument('--auth', help='Cabeçalho de autenticação (ex: "Cookie: session=abc").')
    parser.add_argument('--waf', choices=['basic', 'medium', 'advanced'], default='basic',
                        help='Nível de proteção do WAF (basic: 2-4s, medium: 5-7s, advanced: 8-12s).')

    args = parser.parse_args()
    headers = {'User-Agent': random_user_agent()}
    if args.auth:
        key, value = args.auth.split(':', 1)
        headers[key.strip()] = value.strip()

    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
        executor.submit(test_open_redirect_reflected, args.url, args.payload, args.encode, headers, args.waf)
        executor.submit(test_open_redirect_stored, args.url, headers, args.payload, args.waf)
        executor.submit(test_dom_based_redirect, args.url, headers, args.waf)

    print("\n🔍 **Relatório de Vulnerabilidades Encontradas:**\n")
    for category, issues in vulnerabilities.items():
        if issues:
            print(f"{RED}🔴 {category.upper()}{ENDC}")
            for url, poc in issues:
                print(f"[{category.upper()}] {url}\n{poc}")
    print("\n✅ Teste concluído.")

