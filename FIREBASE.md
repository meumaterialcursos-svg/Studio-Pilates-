# Firebase — configuração (projeto `louise-891b3`)

## Console (uma vez só)
1. **Authentication → Sign-in method:** ative **E-mail/senha**. **Users → Add user:** crie o usuário da proprietária, com a **mesma senha do app** (mín. 6).
2. **Firestore Database → Criar banco** (produção, `southamerica-east1`). Em **Regras**, cole `firestore.rules` e publique (ou `firebase deploy --only firestore`).
3. **Authentication → Settings → Authorized domains:** adicione `SEU-USUARIO.github.io`.
4. Recomendado: desative **Enable create (sign-up)** em Authentication → Settings → User actions e restrinja a chave de API por referenciador HTTP no Google Cloud Console.

## Como sincroniza
- `localStorage` é a fonte primária; o Firestore é o espelho. Sem e-mail no login, o app roda só local.
- Dados em `studios/{uid}/{colecao}/{id}` (alunos, aulas, financeiro, reposições, espera, equipamentos, planos) e `studios/{uid}/meta/state` (configurações). Cada item é um documento `{ d: json, t: timestamp }`; só o que mudou é enviado.
- Conflito: vale o último a gravar, por item. Fotos e documentos (PDF/imagem) ficam só no aparelho.
- Regras: cada usuário acessa apenas o próprio `studios/{uid}`.

## Ícone de nuvem (cabeçalho, ao lado de "Sair")
Cinza com risco = desligada · âmbar pulsando = conectando · **verde com ponto pulsante = tempo real** · azul pulsando = enviando · anel verde = chegou atualização de outro aparelho · âmbar com risco = sem internet · vermelho = erro. Toque para ver a hora da última sincronização.

## SDK
Versão `13.1.0` via CDN `gstatic.com/firebasejs`, nos 4 imports de `firebase-sync.js`.
