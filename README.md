# open-redirect-scanner

Este script em Python realiza testes automatizados para identificar vulnerabilidades de Open Redirect em aplicações web e APIs.

<b>Funcionalidades Principais</b><br>

- Testes automatizados:** Procura automaticamente por parâmetros comuns relacionados a redirecionamento (`redirect`, `url`, `redirect_to`, `next`, etc.).<br>
- Payload configurável:** Payload padrão configurado para verificar reflexões no corpo da resposta.<br>
- User-Agent aleatório:** Utiliza User-Agents variados de navegadores populares para evitar detecção por WAF.<br>
- Delay aleatório:** Tempo de espera aleatório (entre 5 e 10 segundos) entre requisições, minimizando risco de bloqueios.<br>
- Suporte a autenticação:** Possibilidade de definir cabeçalhos personalizados para autenticação (`Cookie`, `Authorization Bearer`, tokens, etc.).<br>
- Codificação opcional:** Flag opcional para codificar payload em URL encoding.<br>

<b>Exemplo de Uso</b><br>

    python open_redirect_scanner.py -u "https://example.com?redirect=teste" [--encode] [--auth "Cookie: session=abc123"]
    
    python script.py -u "https://exemplo.com" --auth "Authorization: Bearer tokenxyz"


<b>Opções de Flags</b><br>

<b>-u, --url:</b> (Obrigatório) Define a URL a ser testada.<br>

<b>-p, --payload:</b>  (Opcional) Define o payload para testes (padrão: https://myserver.com).<br>

<b>--encode:</b>  (Opcional) Ativa a codificação URL do payload.<br>

<b>--auth: </b> (Opcional) Define o cabeçalho de autenticação (ex.: "Cookie: session=abc123").<br>

Resultados vulneráveis são destacados claramente em vermelho no terminal.

