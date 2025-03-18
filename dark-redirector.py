import requests
import argparse
import random
import time
from urllib.parse import urlparse, urljoin, parse_qs, quote_plus
from bs4 import BeautifulSoup
import re

# Cores para impressão no terminal
RED = '\033[91m'
ENDC = '\033[0m'

# Lista de User-Agents aleatórios
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:122.0) Gecko/20100101 Firefox/122.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1"
]

COMMON_PARAMS = ['redirect', 'redirect_to', 'url', 'next', 'return', 'dest', 'direct']

DOM_VULNERABLE_PATTERNS = [
    r"location\s*=", r"location\.host", r"location\.hostname", r"location\.href", 
    r"location\.pathname", r"location\.search", r"location\.protocol", 
    r"location\.assign\s*\(", r"location\.replace\s*\(", r"open\s*\(",
    r"element\.srcdoc", r"XMLHttpRequest\.open\s*\(", r"XMLHttpRequest\.send\s*\(",
    r"jQuery\.ajax\s*\(", r"\$\.ajax\s*\(",
]

# Lista para armazenar vulnerabilidades encontradas
vulnerabilities = {
    "reflected": [],
    "stored": [],
    "dom": []
}

def random_user_agent():
    return random.choice(USER_AGENTS)

def random_delay():
    return random.randint(5, 10)

def generate_poc(url, param, payload):
    """Gera uma prova de conceito (PoC) demonstrando a vulnerabilidade."""
    return f"URL vulnerável: {url}/?{param}={payload}\nO navegador será redirecionado sem validação, permitindo phishing ou sequestro de sessão."

def generate_dom_poc(url, pattern):
    """Gera uma PoC para vulnerabilidades baseadas em DOM."""
    return f"URL vulnerável: {url}\nO código contém um padrão inseguro: {pattern}\nUm atacante pode manipular parâmetros no DOM e redirecionar usuários."

def crawl_site(base_url, headers):
    """Crawleia o site para encontrar possíveis paths internos, sem brute force."""
    visited = set()
    paths = set()
    queue = [base_url]

    while queue:
        url = queue.pop(0)
        if url in visited:
            continue
        visited.add(url)

        try:
            response = requests.get(url, headers=headers, timeout=10)
            soup = BeautifulSoup(response.text, 'html.parser')

            # Coleta links internos
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
    """Testa Open Redirect refletido em parâmetros comuns."""
    for param in COMMON_PARAMS:
        modified_url = f"{url}/?{param}={quote_plus(payload) if encode else payload}"
        try:
            response = requests.get(modified_url, headers=headers, timeout=10)
            if payload in response.text:
                poc = generate_poc(url, param, payload)
                vulnerabilities["reflected"].append((modified_url, poc))
                print(f"{RED}[VULNERÁVEL] {modified_url}\nPoC:\n{poc}{ENDC}")
            time.sleep(random_delay())
        except requests.exceptions.RequestException:
            continue

def test_stored_open_redirect(url, headers, payload):
    """Testa Open Redirect armazenado enviando um payload e verificando se é refletido futuramente."""
    try:
        response = requests.get(url, headers=headers, timeout=10)
        soup = BeautifulSoup(response.text, 'html.parser')
        forms = soup.find_all('form')
        for form in forms:
            post_url = urljoin(url, form.get('action', ''))
            post_data = {inp.get('name'): payload for inp in form.find_all('input') if inp.get('name')}
            response_post = requests.post(post_url, headers=headers, data=post_data, timeout=10)
            time.sleep(random_delay())
            response_check = requests.get(url, headers=headers, timeout=10)
            if payload in response_check.text:
                vulnerabilities["stored"].append((url, "Payload armazenado e refletido na resposta."))
                print(f"{RED}[VULNERÁVEL - OPEN REDIRECT ARMAZENADO] {url}{ENDC}")
    except requests.exceptions.RequestException:
        return

def test_dom_based_redirect(url, headers):
    """Testa Open Redirect baseado em DOM procurando padrões no JavaScript da página."""
    try:
        response = requests.get(url, headers=headers, timeout=10)
        for pattern in DOM_VULNERABLE_PATTERNS:
            match = re.search(pattern, response.text)
            if match:
                poc = generate_dom_poc(url, match.group())
                vulnerabilities["dom"].append((url, poc))
                print(f"{RED}[POTENCIALMENTE VULNERÁVEL - DOM BASED] {url}\nPoC:\n{poc}{ENDC}")
    except requests.exceptions.RequestException:
        return

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Scanner de Open Redirect.')
    parser.add_argument('-u', '--url', required=True, help='URL base da aplicação a ser testada (deve terminar com /)')
    parser.add_argument('-p', '--payload', default='https://myserver.com', help='Payload para testar open redirect')
    parser.add_argument('--encode', action='store_true', help='Encode o payload para URL encoding')
    parser.add_argument('--auth', help='Cabeçalho de autenticação para sistemas autenticados (ex: "Cookie: session=abc", "Authorization: Bearer xyz")')

    args = parser.parse_args()

    headers = {'User-Agent': random_user_agent()}
    if args.auth:
        key, value = args.auth.split(':', 1)
        headers[key.strip()] = value.strip()

    print(f"\n🔍 Iniciando busca de paths no site {args.url}...\n")
    paths = crawl_site(args.url, headers)
    
    for path in paths:
        full_url = urljoin(args.url, path)
        test_open_redirect(full_url, args.payload, args.encode, headers)
        test_dom_based_redirect(full_url, headers)
        test_stored_open_redirect(full_url, headers, args.payload)

    print("\n✅ Teste concluído.")


