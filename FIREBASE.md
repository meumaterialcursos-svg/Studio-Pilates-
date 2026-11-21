# Firebase — configuração (projeto `louise-891b3`)

A sincronização é **opcional**: sem login, o app funciona 100% neste aparelho (como antes). Com login, os dados são copiados para o Firestore e ficam iguais em todos os aparelhos.

## 1. Ativar o login
1. Console Firebase → **Authentication** → **Sign-in method** → ative **E-mail/senha**.
2. **Authentication → Users → Add user**: cadastre o e-mail e a senha da proprietária.
3. Em **Authentication → Settings**, desative a criação de novas contas (auto-cadastro). Assim só quem você cadastrou entra. O nome do menu pode variar.
4. Em **Authentication → Settings → Authorized domains**, adicione o domínio onde o app roda (ex.: `usuario.github.io` ou seu domínio próprio).

## 2. Criar o banco
**Firestore Database → Criar banco de dados** → modo **produção** → região `southamerica-east1` (São Paulo).

## 3. Publicar as regras (obrigatório)
Sem as regras, o banco não protege os dados. Escolha um caminho:
- Console → Firestore → **Regras** → cole o conteúdo de `firestore.rules` → **Publicar**; ou
- Terminal: `npm i -g firebase-tools`, `firebase login`, `firebase use louise-891b3`, `firebase deploy --only firestore`.

## 4. Publicar o site (opcional, se não usar GitHub Pages)
`firebase deploy --only hosting` (usa `firebase.json`, que já inclui os cabeçalhos de segurança).

## 5. Usar no app
Configurações → **Nuvem (Firebase)** → e-mail e senha → **Entrar**. O primeiro aparelho envia os dados; os demais baixam.

## Como funciona
- Caminho: `users/{uid}/sync/meta` (versão) e `users/{uid}/sync/d{versão}_{n}` (dados em blocos de até 350 mil caracteres).
- Envio automático ~2,5 s após cada alteração. A gravação é uma transação: se outro aparelho gravou antes, nada é sobrescrito.
- **Conflito** (os dois lados mudaram): o app não decide sozinho. Mostra um aviso e você escolhe **Baixar da nuvem** ou **Enviar deste aparelho**.
- Antes de aplicar dados da nuvem, uma cópia local fica em `localStorage` → chave `sp_pre_sync`.
- A senha do app (tela de entrada) **não** é enviada à nuvem.

## Segurança
- A `apiKey` do app web é pública por design. A proteção real é o login + `firestore.rules` (cada usuária só lê e grava `users/{seu uid}`).
- Recomendado: no Google Cloud Console → Credenciais, restrinja a chave de API aos seus domínios (referenciadores HTTP).
- O Analytics está desligado (`ENABLE_ANALYTICS = false` em `firebase-config.js`) por causa dos dados de alunos (LGPD).
- O CSP usa `'unsafe-inline'` porque o app é um arquivo único com scripts embutidos. Melhoria futura: separar os scripts e usar hashes.
