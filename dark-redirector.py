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

DOM_VULNERABLE_PATTERNS = [
    r"location\s*=", 
    r"location\.host", 
    r"location\.hostname", 
    r"location\.href", 
    r"location\.pathname", 
    r"location\.search", 
    r"location\.protocol", 
    r"location\.assign\s*\(",
    r"location\.replace\s*\(",
    r"open\s*\(",
    r"element\.srcdoc", 
    r"XMLHttpRequest\.open\s*\(",
    r"XMLHttpRequest\.send\s*\(",
    r"jQuery\.ajax\s*\(",
    r"\$\.ajax\s*\(",
]

def random_user_agent():
    return random.choice(USER_AGENTS)

def random_delay():
    return random.randint(5, 10)

def generate_poc(url, param, payload):
    """Gera uma prova de conceito (PoC) demonstrando a vulnerabilidade."""
    poc = f"URL vulnerável: {url}/?{param}={payload}\n"
    poc += "Se acessarmos essa URL, o navegador será redirecionado para o payload fornecido, permitindo possíveis ataques como phishing ou roubo de credenciais."
    return poc

def generate_dom_poc(url, pattern):
    """Gera uma PoC para vulnerabilidades baseadas em DOM."""
    poc = f"URL vulnerável: {url}\n"
    poc += f"O código contém o padrão potencialmente inseguro: {pattern}\n"
    poc += "Se um atacante manipular parâmetros no DOM, poderá redirecionar usuários sem validação adequada."
    return poc

def find_input_fields(url, headers):
    """Encontra formulários que podem armazenar dados do usuário."""
    try:
        response = requests.get(url, headers=headers, timeout=10)
        soup = BeautifulSoup(response.text, 'html.parser')
        forms = soup.find_all('form')
        input_fields = []
        for form in forms:
            inputs = form.find_all('input')
            for inp in inputs:
                if inp.has_attr('name'):
                    input_fields.append(inp['name'])
        return input_fields
    except requests.exceptions.RequestException:
        return []

def test_stored_open_redirect(url, headers, payload):
    """Testa Open Redirect armazenado enviando um payload e verificando se é refletido futuramente."""
    input_fields = find_input_fields(url, headers)
    if not input_fields:
        print("[INFO] Nenhum campo de entrada encontrado para teste de Open Redirect armazenado.")
        return False

    vulnerable = False
    for field in input_fields:
        post_data = {field: payload}
        try:
            response = requests.post(url, headers=headers, data=post_data, timeout=10)
            time.sleep(random_delay())  # Aguardar tempo para garantir que o dado seja armazenado

            response_check = requests.get(url, headers=headers, timeout=10)
            if payload in response_check.text:
                print(f"{RED}[VULNERÁVEL - OPEN REDIRECT ARMAZENADO] {url}\nO payload foi encontrado salvo na resposta.{ENDC}")
                vulnerable = True
            else:
                print(f"[SEGURO - OPEN REDIRECT ARMAZENADO] {url}")
        except requests.exceptions.RequestException as e:
            print(f"[ERRO] {url} - {str(e)}")
    return vulnerable

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

def test_dom_based_redirect(url, headers):
    """Testa possíveis vulnerabilidades de Open Redirect baseadas em DOM."""
    try:
        response = requests.get(url, headers=headers, timeout=10)
        for pattern in DOM_VULNERABLE_PATTERNS:
            match = re.search(pattern, response.text)
            if match:
                poc = generate_dom_poc(url, match.group())
                print(f"{RED}[POTENCIALMENTE VULNERÁVEL - DOM BASED] {url}\nPoC:\n{poc}{ENDC}")
                return True
        print(f"[DOM SEGURO] {url}")
    except requests.exceptions.RequestException as e:
        print(f"[ERRO DOM] {url} - {str(e)}")
    return False

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
    stored_vulneravel = test_stored_open_redirect(args.url, headers, args.payload)

    if vulneravel or dom_vulneravel or stored_vulneravel:
        print(f"\n{RED}Teste concluído: Vulnerabilidade encontrada!{ENDC}\n")
    else:
        print("\nTeste concluído: Nenhuma vulnerabilidade encontrada.\n")



