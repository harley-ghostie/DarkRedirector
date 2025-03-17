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

def generate_poc(url, param, payload):
    """Gera uma prova de conceito (PoC) demonstrando a vulnerabilidade."""
    poc = f"URL vulnerável: {url}/?{param}={payload}\n"
    poc += "Se acessarmos essa URL, o navegador será redirecionado para o payload fornecido, o que pode permitir ataques como phishing ou roubo de credenciais."
    return poc

def test_open_redirect(url, payload, encode, headers):
    vulnerable = False
    for param in COMMON_PARAMS:
        modified_url = f"{url}/?{param}={quote_plus(payload) if encode else payload}"
        try:
            response = requests.get(modified_url, headers=headers, timeout=10)
            if payload in response.text:
                poc = generate_poc(url, param, payload)
                print(f"{RED}[VULNERÁVEL] {modified_url}\nPoC:\n{poc}{ENDC}")
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

    if vulneravel:
        print(f"\n{RED}Teste concluído: Vulnerabilidade encontrada!{ENDC}\n")
    else:
        print("\nTeste concluído: Nenhuma vulnerabilidade encontrada.\n")

