# Studio Pilates LOUISE KARLA — Sistema de Gestão (PWA + Firebase)

App de gestão (alunos, agenda, financeiro) **local-first**: funciona offline e, opcionalmente, sincroniza em tempo real com o Firebase. Instalável no celular (PWA).

## Estrutura
| Arquivo | Função |
|---|---|
| `index.html` · `style.css` · `app.js` | Interface, estilos e lógica do app |
| `firebase-config.js` | Configuração web do projeto Firebase |
| `firebase-sync.js` | Auth + Firestore + ícone de status da nuvem |
| `sync-core.js` | Lógica pura de sincronização (snapshot/diff) |
| `sw.js` · `manifest.webmanifest` | Service worker e manifesto PWA |
| `icon.svg` · `icon-192.png` · `icon-512.png` · `icon-maskable-512.png` · `apple-touch-icon.png` | Ícones |
| `firebase.json` · `.firebaserc` · `firestore.rules` · `firestore.indexes.json` | Firebase CLI (Hosting + Firestore) |
| `_headers` | Cabeçalhos de segurança (Netlify/Cloudflare Pages; o GitHub Pages ignora) |
| `FIREBASE.md` | Configuração do Console e modelo de dados |

## Publicar
**GitHub Pages:** envie todos os arquivos da raiz → Settings → Pages → `main` / `(root)`.
**Firebase Hosting:** `firebase deploy` (usa `.firebaserc` e `firebase.json`).
Não abra o `index.html` com duplo clique (`file://`): módulos ES e service worker exigem `http(s)`.

Configure o Firebase seguindo o `FIREBASE.md`.
