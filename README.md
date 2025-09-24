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
- Crawling automático: Explora links internos (a, script, link, img) para encontrar possíveis paths vulneráveis.<br>
- Gera PoCs (Provas de Conceito): Exibe URLs exploráveis e o motivo da vulnerabilidade.<br>

  <b>Testes de Open Redirect:</b><br>

  <b>Refletido:</b> Testa parâmetros comuns (?redirect=, ?url=, etc.).<br>
  <b>Armazenado:</b> Envia um payload e verifica se é refletido posteriormente.<br>
  <b>Baseado em DOM:</b> Busca scripts inseguros no JavaScript da página.<br>
    
     
<b>Exemplo de Uso</b><br>

<b>✅ Comando básico:
    
    python dark-redirector.py -u "https://www.alvo.com.br"

<b>🔧 Comando com payload customizado:</b><br>

    python dark-redirector.py -u "https://www.alvo.com.br" -p "https://evil.com"

<b>🔐 Comando com autenticação (ex: Cookie ou Bearer):</b><br>

    python dark-redirector.py -u "https://www.alvo.com.br" --auth "Cookie: session=abc123"

<b>🔄 Comando com payload encode (URL encoding):</b><br>

    python dark-redirector.py -u "https://www.alvo.com.br" --encode

<b>🛡️ Comando com simulação de WAF avançado (delays maiores):</b><br>

    python dark-redirector.py -u "https://www.alvo.com.br" --waf advanced

<b>📦 Exemplo completo com tudo:</b><br>

    python dark-redirector.py -u "https://www.alvo.com.br/pagina?token=xyz" \
      -p "https://evil.com" \
      --encode \
      --auth "Authorization: Bearer abc.def.ghi" \
      --waf medium
<br>


    

Resultados vulneráveis são destacados claramente em vermelho no terminal.

