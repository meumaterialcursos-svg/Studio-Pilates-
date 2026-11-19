# Studio Pilates LOUISE KARLA — integração Firebase

Arquivos: `index.html` (app) · `firebase-sync.js` (Firebase: App, Analytics, Auth, Firestore) · `firestore.rules` · `.nojekyll`

## Como funciona
- O app continua **local-first**: `localStorage` é a fonte primária e tudo funciona offline.
- Com e-mail preenchido no login, o app entra no Firebase Auth e espelha os dados no Firestore (`studios/{uid}/...`), com diff por item e atualização em tempo real entre aparelhos.
- Sem e-mail no login, o app funciona exatamente como antes (sem nuvem).
- **Fotos e documentos (PDF/imagem) continuam só neste aparelho** (localStorage/IndexedDB). Não vão para a nuvem.

## Configuração (uma vez só) — Console Firebase, projeto `louise-891b3`
1. **Authentication → Sign-in method**: ative **E-mail/senha**. Em **Users → Add user**, crie o usuário da proprietária. Use a **mesma senha do app** (mín. 6 caracteres).
2. **Firestore Database → Criar banco** (modo produção, região `southamerica-east1`). Aba **Regras**: cole o conteúdo de `firestore.rules` e **Publicar**.
3. **Authentication → Settings → Authorized domains**: adicione `SEU-USUARIO.github.io`.
4. (Recomendado) Após criar o usuário, em **Authentication → Settings → User actions**, desative **Enable create (sign-up)**.
5. (Recomendado) Google Cloud Console → APIs e serviços → Credenciais → restrinja a chave de API por **referenciador HTTP** (`SEU-USUARIO.github.io/*`).

## Publicação no GitHub Pages
Envie os arquivos da raiz do ZIP para o repositório → Settings → Pages → Deploy from branch (`main`, `/root`).
Não abra `index.html` com duplo clique (`file://`): módulos ES e Firebase exigem `http(s)`.

## Observações
- Ao trocar a senha no app, a senha da nuvem é atualizada junto (se pedir login recente, saia, entre e repita).
- Sair do app também encerra a sessão na nuvem.
- Versão do SDK fixada em `13.1.0` (CDN `gstatic.com/firebasejs`). Para atualizar, altere o número nos 4 imports de `firebase-sync.js`.
