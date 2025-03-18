import requests
import argparse
import random
import time
import concurrent.futures
from urllib.parse import urlparse, urljoin, parse_qs, quote_plus
from bs4 import BeautifulSoup
import re

# Cores
RED = '\033[91m'
ENDC = '\033[0m'

# User-Agents Aleatórios
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:122.0) Gecko/20100101 Firefox/122.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1"
]

COMMON_PARAMS = ['redirect', 'redirect_to', 'url', 'next', 'return', 'dest', 'direct']
MAX_CRAWL_PAGES = 50  # Limite de páginas no crawler
tested_urls = set()

def random_user_agent():
    return random.choice(USER_AGENTS)

def random_delay():
    return random.uniform(1, 3)  # Reduzido o delay

def crawl_site(base_url, headers):
    """Crawleia o site para encontrar possíveis paths internos, sem brute force."""
    visited = set()
    queue = [base_url]
    paths = set()

    while queue and len(visited) < MAX_CRAWL_PAGES:
        url = queue.pop(0)
        if url in visited:
            continue
        visited.add(url)

        try:
            response = requests.get(url, headers=headers, timeout=5)
            soup = BeautifulSoup(response.text, 'html.parser')

            for link in soup.find_all(['a', 'script', 'link', 'img'], href=True):
                href = link.get('href') or link.get('src')
                if href and not href.startswith(('http', '#', 'mailto:', 'javascript:')):
                    full_url = urljoin(base_url, href)
                    parsed = urlparse(full_url)
                    if base_url in full_url and parsed.path not in paths:
                        paths.add(parsed.path)
                        queue.append(full_url)
        except requests.exceptions.RequestException:
            continue

    return paths

def test_open_redirect(url, payload, encode, headers):
    """Testa Open Redirect refletido."""
    if url in tested_urls:
        return
    tested_urls.add(url)

    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
        futures = []
        for param in COMMON_PARAMS:
            modified_url = f"{url}/?{param}={quote_plus(payload) if encode else payload}"
            futures.append(executor.submit(requests.get, modified_url, headers=headers, timeout=5))

        for future in concurrent.futures.as_completed(futures):
            try:
                response = future.result()
                if payload in response.text:
                    print(f"{RED}[VULNERÁVEL] {modified_url}{ENDC}")
            except requests.exceptions.RequestException:
                continue

def test_dom_based_redirect(url, headers):
    """Testa Open Redirect baseado em DOM."""
    if url in tested_urls:
        return
    tested_urls.add(url)

    try:
        response = requests.get(url, headers=headers, timeout=5)
        for pattern in ["location.href", "window.location", "document.location"]:
            if pattern in response.text:
                print(f"{RED}[POTENCIALMENTE VULNERÁVEL - DOM BASED] {url}{ENDC}")
    except requests.exceptions.RequestException:
        return

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Scanner rápido de Open Redirect.')
    parser.add_argument('-u', '--url', required=True, help='URL base a ser testada.')
    parser.add_argument('-p', '--payload', default='https://myserver.com', help='Payload do Open Redirect.')
    parser.add_argument('--encode', action='store_true', help='Aplica URL encoding no payload.')
    parser.add_argument('--auth', help='Cabeçalho de autenticação (ex: "Cookie: session=abc")')

    args = parser.parse_args()
    headers = {'User-Agent': random_user_agent()}
    
    if args.auth:
        key, value = args.auth.split(':', 1)
        headers[key.strip()] = value.strip()

    print(f"\n🔍 Buscando paths no site {args.url}...\n")
    paths = crawl_site(args.url, headers)
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
        for path in paths:
            full_url = urljoin(args.url, path)
            executor.submit(test_open_redirect, full_url, args.payload, args.encode, headers)
            executor.submit(test_dom_based_redirect, full_url, headers)

    print("\n✅ Teste concluído.")
