import requests
import argparse
import random
import time
from urllib.parse import urlparse, urljoin, parse_qs, urlencode, urlunparse, quote_plus
from bs4 import BeautifulSoup

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

def get_links(url, headers):
    try:
        response = requests.get(url, headers=headers, timeout=10)
        soup = BeautifulSoup(response.text, 'html.parser')
        links = set()
        for link in soup.find_all('a', href=True):
            full_link = urljoin(url, link['href'])
            links.add(full_link)
        return links
    except requests.exceptions.RequestException:
        return set()

def test_open_redirect(url, payload, encode, headers):
    urls_to_test = get_links(url, headers)
    urls_to_test.add(url)
    vulnerable = False

    for target_url in urls_to_test:
        parsed_url = urlparse(target_url)
        query_params = parse_qs(parsed_url.query)

        for param in COMMON_PARAMS:
            original_params = query_params.copy()
            original_payload = quote_plus(payload) if encode else payload
            original_params[param] = original_payload
            encoded_params = urlencode(original_params, doseq=True)

            modified_url = urlunparse((parsed_url.scheme, parsed_url.netloc, parsed_url.path, '', encoded_params, ''))

            try:
                response = requests.get(modified_url, headers=headers, timeout=10)

                if payload in response.text:
                    print(f"{RED}[VULNERÁVEL]{ENDC} {modified_url}")
                    vulnerable = True
                else:
                    print(f"[SEGURO] {modified_url}")

                time.sleep(random_delay())

            except requests.exceptions.RequestException as e:
                print(f"[ERRO] {modified_url} - {str(e)}")

    return vulnerable

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Scanner de Open Redirect.')
    parser.add_argument('-u', '--url', required=True, help='URL base da aplicação a ser testada')
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
