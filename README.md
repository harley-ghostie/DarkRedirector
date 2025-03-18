<p align="left"><img src="http://img.shields.io/static/v1?label=STATUS&message=EM%20DESENVOLVIMENTO&color=GREEN&style=for-the-badge"/></p>

# Open Redirec Scan

O script é uma ferramenta automatizada que realiza testes de segurança para identificar vulnerabilidades de **Open Redirect** em aplicações web ou APIs. Ele busca automaticamente URLs internas e parâmetros comuns relacionados a redirecionamento, injeta um payload personalizado e verifica a reflexão desse payload nas respostas HTML. Para evitar detecção por sistemas de proteção (como WAF), utiliza User-Agents aleatórios e aplica atrasos aleatórios entre as requisições. Além disso, suporta autenticação personalizada para testes em ambientes restritos.

<b>Dependências:</b><br>
    
    pip install beautifulsoup4


<b>Funcionalidades Principais</b><br>

- Testes automatizados:** Procura automaticamente por parâmetros comuns relacionados a redirecionamento (`redirect`, `url`, `redirect_to`, `next`, etc.).<br>
- Payload configurável:** Payload padrão configurado para verificar reflexões no corpo da resposta.<br>
- User-Agent aleatório:** Utiliza User-Agents variados de navegadores populares para evitar detecção por WAF.<br>
- Delay aleatório:** Tempo de espera aleatório (entre 5 e 10 segundos) entre requisições, minimizando risco de bloqueios.<br>
- Suporte a autenticação:** Possibilidade de definir cabeçalhos personalizados para autenticação (`Cookie`, `Authorization Bearer`, tokens, etc.).<br>
- Codificação opcional:** Flag opcional para codificar payload em URL encoding.<br>

<b>Exemplo de Uso</b><br>

    python dark-redirector.py -u "https://example.com?redirect=teste" [--encode] [--auth "Cookie: session=abc123"]
    
    python dark-redirector.py -u "https://exemplo.com" --auth "Authorization: Bearer tokenxyz"


<b>Opções de Flags</b><br>

<b>-u, --url:</b> (Obrigatório) Define a URL a ser testada.<br>

<b>-p, --payload:</b>  (Opcional) Define o payload para testes (padrão: https://myserver.com).<br>

<b>--encode:</b>  (Opcional) Ativa a codificação URL do payload.<br>

<b>--auth: </b> (Opcional) Define o cabeçalho de autenticação (ex.: "Cookie: session=abc123").<br>
<b>--waf: Caso não inserido a flag ele irá automaticamente no tempo de 2 a 4 segundos</b><br>
    medium → Delay de 5 a 7 segundos<br>
    advanced → Delay de 8 a 12 segundos<br>

Resultados vulneráveis são destacados claramente em vermelho no terminal.

