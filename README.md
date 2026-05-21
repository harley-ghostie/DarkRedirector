<p align="left"><img src="http://img.shields.io/static/v1?label=STATUS&message=EM%20DESENVOLVIMENTO&color=GREEN&style=for-the-badge"/></p>

# Open Redirect

## Visão geral

**Open Redirect** é uma vulnerabilidade em que uma aplicação web permite que entradas controladas pelo usuário determinem para onde o navegador será redirecionado. Quando a aplicação não valida corretamente essas entradas, o usuário pode ser conduzido para um site externo controlado por um atacante, cenário comum em ataques de phishing, abuso de domínio confiável e encadeamento com fluxos sensíveis, como login, SSO e OAuth.

Este projeto contém um script para auxiliar na validação de **Open Redirect refletido** e **DOM-based Open Redirect**, combinando testes HTTP com validação em navegador via Playwright.

A proposta do script é reduzir falsos positivos. Ele não considera vulnerável apenas porque o payload aparece na URL ou foi refletido no HTML. A confirmação ocorre somente quando a aplicação realmente redireciona para o domínio externo informado no payload.

## Objetivo

O objetivo do script é automatizar a validação de possíveis Open Redirects em aplicações web, cobrindo cenários em que o redirecionamento ocorre:

* por resposta HTTP, usando status `301`, `302`, `303`, `307` ou `308` com header `Location` externo;
* por JavaScript no lado cliente, usando sinks como `window.open`, `location.assign` ou `location.replace`;
* por parâmetros comuns de redirecionamento, como `next`, `redirect`, `returnUrl`, `url`, `target`, `dest`, entre outros.

## Como funciona

O script gera URLs de teste a partir de uma URL base e injeta payloads externos em parâmetros comuns de redirecionamento.

Exemplo:

```text
https://alvo.com/login?next=https://evil.com/
```

Em seguida, ele executa duas frentes de validação:

1. **Validação HTTP**
   Realiza requisições sem seguir redirecionamentos automaticamente, permitindo verificar se a resposta retorna um header `Location` apontando para domínio externo.

2. **Validação em navegador**
   Usa Playwright/Chromium para abrir a URL e observar o destino final da navegação. Isso é necessário porque muitos redirecionamentos modernos ocorrem via JavaScript e não aparecem apenas na resposta HTTP.

## Critério de classificação

O script diferencia achado confirmado de comportamento apenas suspeito.

### Confirmed

É classificado como confirmado somente quando:

* o header `Location` aponta para o domínio externo definido no payload;
* o navegador termina a navegação no domínio externo;
* uma nova aba ou janela aberta via JavaScript aponta para o domínio externo.

### Suspicious

É classificado como suspeito quando:

* o payload aparece refletido no HTML;
* são encontrados indícios de sinks DOM, como `window.open`, `location.assign`, `location.replace`, `location.href` ou `URLSearchParams`;
* o payload aparece na query string, mas a aplicação permanece no domínio legítimo.

Esse comportamento exige análise manual, porque pode ser apenas ruído.

### Not reproduced

É considerado não reproduzido quando:

* não existe header `Location` externo;
* a navegação permanece no domínio legítimo;
* nenhuma aba externa é aberta;
* nenhum sink DOM recebe o domínio externo.

## Instalação

Instale as dependências:

```bash
pip install requests playwright
playwright install chromium
```

## Uso básico

```bash
python3 dark-redirector.py -u "https://alvo.com/login" -p "https://evil.com" --encode
```

## Uso com cookie ou autenticação

Para testar fluxos pós-login, informe um header de autenticação ou cookie válido:

```bash
python3 dark-redirector.py \
  -u "https://alvo.com/login" \
  -p "https://evil.com" \
  --encode \
  --auth "Cookie: session=abcdef123456"
```

## Controle de concorrência

Para evitar consumo excessivo de CPU/memória, use o parâmetro `--concurrency` ou `--max-concurrency`.

Exemplo:

```bash
python3 dark-redirector.py \
  -u "https://alvo.com/login" \
  -p "https://evil.com" \
  --encode \
  --concurrency 3
```

Também é possível usar:

```bash
python3 dark-redirector.py \
  -u "https://alvo.com/login" \
  -p "https://evil.com" \
  --encode \
  --max-concurrency 3
```

Valor recomendado:

```text
3 a 5 para máquinas comuns.
1 a 2 para ambientes mais limitados.
```

## Parâmetros testados

O script testa automaticamente parâmetros comuns associados a redirecionamento, incluindo:

```text
redirect
redirect_uri
redirect_url
return
returnUrl
return_url
next
nextUrl
next_url
url
target
continue
callback
callback_url
goto
dest
destination
```

## Payloads utilizados

O script gera variações do payload para aumentar a cobertura de validação, incluindo formatos como:

```text
https://evil.com
//evil.com
http://evil.com
https://evil.com/%2F
https://evil.com/?x=1
https://evil.com%2f
https://evil.com%252f
https://example.com@evil.com/
```

Essas variações ajudam a identificar validações frágeis, parsing inconsistente e bypasses comuns.

## Exemplo de saída esperada

Quando não houver redirecionamento externo:

```text
No open redirect behaviour detected with the given test cases.
```

Quando houver comportamento suspeito, mas não confirmado:

```text
=== Suspicious findings ===
* Potential client-side redirect sink found in HTML...
```

Quando houver Open Redirect confirmado:

```text
=== Confirmed vulnerabilities ===
* Confirmed HTTP open redirect...
* Confirmed client-side open redirect...
```

## Validação manual no DevTools

Além da automação, é recomendado realizar validação manual em cenários de DOM Open Redirect, principalmente quando a aplicação exige autenticação ou interação do usuário.

Cole o snippet abaixo no console do DevTools da aplicação alvo:

```javascript
(() => {
  const markerHost = "evil.com";
  const params = [
    "next", "redirect", "redirect_uri", "redirect_url", "return", "returnUrl",
    "return_url", "url", "target", "goto", "dest", "destination", "continue",
    "callback", "callback_url"
  ];

  const baseUrl = new URL(location.href);

  const results = params.map(p => ({
    param: p,
    url: new URL(baseUrl.href),
    triggered: false
  }));

  results.forEach(r => {
    r.url.searchParams.set(r.param, `https://${markerHost}/`);
  });

  const originalOpen = window.open;
  const originalAssign = window.location.assign.bind(window.location);
  const originalReplace = window.location.replace.bind(window.location);

  function markTriggered() {
    const current = results.find(r => r.inTest);
    if (current) current.triggered = true;
  }

  window.open = function (...args) {
    if (String(args[0]).includes(markerHost)) {
      markTriggered();
    }
    return originalOpen.apply(this, args);
  };

  window.location.assign = function (url) {
    if (String(url).includes(markerHost)) {
      markTriggered();
    }
    return originalAssign(url);
  };

  window.location.replace = function (url) {
    if (String(url).includes(markerHost)) {
      markTriggered();
    }
    return originalReplace(url);
  };

  console.log("[INFO] Hooks instalados para validação de DOM Open Redirect.");

  window.runDomTest = async function (param) {
    const item = results.find(r => r.param === param);

    if (!item) {
      console.warn("Parâmetro não encontrado:", param);
      return;
    }

    results.forEach(r => delete r.inTest);
    item.inTest = true;

    console.log(`[TESTE] Parâmetro: ${param}`);
    console.log(`[URL] Abra em nova aba: ${item.url.toString()}`);
    console.log("[AÇÃO] Interaja com a aplicação e depois volte para esta aba.");
    console.log("[AÇÃO] Em seguida execute: window.finishTest()");
  };

  window.finishTest = function () {
    const current = results.find(r => r.inTest);

    if (!current) {
      console.warn("Nenhum teste em andamento.");
      return;
    }

    console.log("[INFO] Teste finalizado.");
    console.log("Parâmetro:", current.param);
    console.log("Navegou para externo?", current.triggered ? "SIM" : "NÃO");

    delete current.inTest;
  };

  window.showDomResults = function () {
    const table = results.map(r => ({
      parametro: r.param,
      url_testada: r.url.toString(),
      navegou_para_externo: r.triggered ? "SIM" : "NÃO",
      resultado: r.triggered ? "POSSÍVEL VULNERÁVEL" : "NÃO REPRODUZIDO"
    }));

    console.table(table);

    const detected = results.filter(r => r.triggered);

    console.log("========== CONCLUSÃO ==========");

    if (detected.length > 0) {
      console.error("[ALERTA] Pelo menos um parâmetro acionou navegação para domínio externo.");
      console.table(detected.map(r => ({
        parametro: r.param,
        url_testada: r.url.toString()
      })));
    } else {
      console.log("[OK] Nenhuma navegação DOM para domínio externo foi detectada.");
      console.log("[OK] Nenhum sink monitorado recebeu evil.com.");
      console.log("[CONCLUSÃO] DOM Open Redirect não reproduzido no cenário validado.");
    }
  };

  console.log("[PASSO A PASSO]");
  console.log("1. Execute: window.runDomTest('next')");
  console.log("2. Abra a URL gerada em nova aba.");
  console.log("3. Interaja com a aplicação, incluindo login se necessário.");
  console.log("4. Volte para esta aba e execute: window.finishTest()");
  console.log("5. Ao final, execute: window.showDomResults()");
})();
```

## Como usar o comando do DevTools

Depois de colar o snippet no console, execute:

```javascript
window.runDomTest("next")
```

O console exibirá uma URL contendo o payload externo. Abra essa URL em nova aba, interaja com a aplicação e, se necessário, faça login com usuário válido e autorizado.

Depois volte para a aba original e execute:

```javascript
window.finishTest()
```

Repita o processo para outros parâmetros:

```javascript
window.runDomTest("redirect")
window.runDomTest("returnUrl")
window.runDomTest("url")
window.runDomTest("target")
```

Ao final, gere a tabela de evidência:

```javascript
window.showDomResults()
```

## Interpretação do resultado no DevTools

Se a tabela mostrar:

```text
navegou_para_externo: NÃO
resultado: NÃO REPRODUZIDO
```

Significa que o parâmetro foi testado, mas a aplicação não chamou os sinks monitorados com o domínio externo.

Se a tabela mostrar:

```text
navegou_para_externo: SIM
resultado: POSSÍVEL VULNERÁVEL
```

Significa que a aplicação tentou usar o domínio externo em um sink DOM monitorado. Nesse caso, é necessário confirmar se houve navegação real para o domínio externo.

## Observações importantes

O teste manual via DevTools é útil para validar fluxos que dependem de interação do usuário, como login, botão de continuar, retorno de autenticação ou navegação pós-clique.

O comando do DevTools não substitui a validação completa. Ele deve ser usado como apoio para gerar evidência, principalmente quando o scanner indicar comportamento suspeito.

Se a aplicação permanecer no domínio legítimo, sem header `Location` externo, sem abertura de janela externa e sem chamada aos sinks DOM com o payload, o comportamento deve ser tratado como **não reproduzido**.


## Referências

* OWASP Web Security Testing Guide - Testing for Client-side URL Redirect
* PortSwigger Web Security Academy - DOM-based Open Redirection
* MITRE CWE-601 - URL Redirection to Untrusted Site
* PayloadsAllTheThings - Open Redirect

