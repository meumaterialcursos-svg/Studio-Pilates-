# Studio Pilates LOUISE KARLA — Sistema de gestão

App web (PWA) em arquivo único, com dados locais e sincronização opcional via Firebase.

## Arquivos
| Arquivo | Função |
|---|---|
| `index.html` | O app completo |
| `firebase-config.js` | Configuração do projeto Firebase e versão do SDK |
| `firebase-sync.js` | Login e sincronização (carrega o SDK do CDN oficial) |
| `sync-core.js` | Regras puras de sincronização (testáveis) |
| `firestore.rules`, `firestore.indexes.json`, `firebase.json` | Banco e hospedagem Firebase |
| `_headers` | Cabeçalhos de segurança (Cloudflare Pages / Netlify) |
| `manifest.webmanifest`, `sw.js`, `icon*.png`, `icon.svg`, `apple-touch-icon.png` | Instalação como app e uso offline |
| `FIREBASE.md` | Passo a passo do Firebase |

## Publicar no GitHub Pages
1. Envie todos os arquivos para a raiz do repositório.
2. **Settings → Pages → Deploy from a branch → `main` / root**.
3. Abra `https://USUARIO.github.io/REPOSITORIO/` e adicione esse domínio em Authorized domains no Firebase.

O GitHub Pages ignora `_headers` e `firebase.json`. Para ter os cabeçalhos de segurança, publique também no Firebase Hosting ou Cloudflare Pages.

## Atualizar
Substitua `index.html` e envie de novo. O service worker busca a versão mais nova quando há internet.

## Dados
Ficam no `localStorage` do navegador. Faça backup em **Configurações → Dados e backup**; o login na nuvem é um complemento, não substitui o backup.
