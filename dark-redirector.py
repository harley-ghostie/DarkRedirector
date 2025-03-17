import requests
import argparse
import random
import time
from urllib.parse import urlparse, urljoin, parse_qs, urlencode, urlunparse, quote_plus
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

def random_user_agent():
    return random.choice(USER_AGENTS)

def random_delay():
    return random.randint(5, 10)

def extract_possible_params(url, headers):
    """Busca por possíveis parâmetros dentro do corpo da resposta HTML."""
    try:
        response = requests.get(url, headers=headers, timeout=10)
        soup = BeautifulSoup(response.text, 'html.parser')
        found_params = set()
        
        for form in soup.find_all('form'):
            for input_tag in form.find_all('input'):
                if input_tag.has_attr('name'):
                    found_params.add(input_tag['name'])
        
        for a_tag in soup.find_all('a', href=True):
            parsed_href = urlparse(a_tag['href'])
            for param in parse_qs(parsed_href.query).keys():
                found_params.add(param)
        
        return found_params
    except requests.exceptions.RequestException:
        return set()

def test_dom_based_redirect(url, headers):
    """Testa possíveis vulnerabilidades de Open Redirect baseadas em DOM."""
    try:
        response = requests.get(url, headers=headers, timeout=10)
        dom_vulnerable_patterns = [
            r"window\.location\s*=", 
            r"document\.location\s*=", 
            r"window\.location\.href\s*=", 
            r"document\.location\.href\s*=", 
            r"window\.navigate\s*\(",
            r"location\.assign\s*\(",
            r"location\.replace\s*\(",
            r"eval\s*\(",
        ]
        for pattern in dom_vulnerable_patterns:
            if re.search(pattern, response.text):
                print(f"{RED}[POTENCIALMENTE VULNERÁVEL - DOM BASED] {url}{ENDC}")
                return True
        print(f"[DOM SEGURO] {url}")
    except requests.exceptions.RequestException as e:
        print(f"[ERRO DOM] {url} - {str(e)}")
    return False

def test_open_redirect(url, payload, encode, headers):
    vulnerable = False
    possible_params = extract_possible_params(url, headers)
    all_params = COMMON_PARAMS + list(possible_params)

    for param in all_params:
        modified_url = f"{url}/?{param}={quote_plus(payload) if encode else payload}"
        try:
            response = requests.get(modified_url, headers=headers, timeout=10)
            if payload in response.text:
                reflected_part = response.text[response.text.find(payload)-40:response.text.find(payload)+len(payload)+40]
                print(f"{RED}[VULNERÁVEL] {modified_url}\nRefletido na resposta: ...{reflected_part}...{ENDC}")
                vulnerable = True
            else:
                print(f"[SEGURO] {modified_url}")
            time.sleep(random_delay())
        except requests.exceptions.RequestException as e:
            print(f"[ERRO] {modified_url} - {str(e)}")

    return vulnerable

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

    print(f"\nIniciando teste em: {args.url}\n")

    vulneravel = test_open_redirect(args.url, args.payload, args.encode, headers)
    dom_vulneravel = test_dom_based_redirect(args.url, headers)

    if vulneravel or dom_vulneravel:
        print(f"\n{RED}Teste concluído: Vulnerabilidade encontrada!{ENDC}\n")
    else:
        print("\nTeste concluído: Nenhuma vulnerabilidade encontrada.\n")

