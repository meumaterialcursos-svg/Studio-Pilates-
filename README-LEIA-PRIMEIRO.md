# Studio Pilates — pacote Firebase

Este pacote prepara a infraestrutura Firebase e preserva o HTML enviado como `public/index.html`.

## O que foi identificado no HTML original

- O aplicativo não tinha integração Firebase.
- Os dados operacionais principais são salvos em `localStorage`, na chave `studio_pilates_louise_karla_v2`, com backup local e cofre de alunos.
- Documentos de alunos ficam no IndexedDB local (`sp_docs`).
- Portanto, apenas publicar o HTML no Hosting **não** ativa sincronização na nuvem.

## Arquivos incluídos

- `firebase.json`: configuração de Hosting, Realtime Database e Storage.
- `.firebaserc`: projeto Firebase (substituir o ID).
- `database.rules.json`: regras privadas por UID.
- `storage.rules`: regras para documentos PDF/imagens dos alunos, limite de 15 MB.
- `public/index.html`: seu sistema original.
- `public/firebase-config.example.js`: modelo de configuração do app Web.
- `public/js/firebase-bridge.js`: ponte para autenticação, leitura, gravação e upload/download.
- `package.json`: Firebase CLI.

## 1. Criar e configurar o projeto

1. Acesse https://console.firebase.google.com/ e crie um projeto.
2. Adicione um aplicativo Web e copie a configuração exibida.
3. Ative **Authentication > Sign-in method > Anonymous** para o modo inicial deste pacote.
4. Crie/ative **Realtime Database** e **Storage** no Console.
5. Em Authentication, habilite o provedor anônimo.
6. Copie `public/firebase-config.example.js` para `public/firebase-config.js` e preencha os valores reais.
7. Edite `.firebaserc` e substitua `COLOQUE-SEU-PROJECT-ID` pelo ID real do projeto.

## 2. Publicar

Instale Node.js LTS e execute na pasta descompactada:

```bash
npm install
npx firebase login
npx firebase use --add
npx firebase deploy
```

O comando `firebase use --add` deve apontar para o projeto criado no Console.

## 3. Ativar sincronização no aplicativo

A ponte está pronta, mas o HTML original ainda usa armazenamento local. Para não alterar silenciosamente o comportamento e não arriscar os dados atuais, a sincronização não foi ativada automaticamente.

Antes do `</head>` em `public/index.html`, adicione:

```html
<script src="firebase-config.js"></script>
<script src="js/firebase-bridge.js"></script>
```

No bloco principal do JavaScript, depois que `db` for carregado e o usuário estiver autenticado no login interno, faça a carga inicial uma única vez:

```javascript
(async () => {
  try {
    const cloud = await FirebaseStudio.pull();
    if (cloud && Array.isArray(cloud.students) && Array.isArray(cloud.classes)) {
      // Decida conscientemente se a nuvem deve substituir os dados locais.
      // Faça exportação/backup local antes de habilitar esta etapa.
    } else {
      await FirebaseStudio.push(db); // primeiro envio: dados locais para a nuvem
    }
  } catch (e) {
    console.error("Firebase não conectado:", e);
  }
})();
```

Na função `save()` existente, depois das três gravações locais bem-sucedidas, adicione:

```javascript
if (window.FirebaseStudio?.configured) FirebaseStudio.queue(db);
```

Isso mantém o salvamento local e agenda a cópia para a nuvem. A primeira sincronização deve ser testada com uma cópia de segurança dos dados.

## 4. Limitação importante de autenticação

O login e a senha já existentes no HTML são um mecanismo local próprio; eles **não** autenticam o usuário no Firebase. Esta configuração usa login anônimo para isolar dados por UID. Isso funciona para um navegador/dispositivo, mas não garante que celular e computador acessem a mesma conta.

Para sincronização real entre vários dispositivos, o próximo passo correto é integrar Firebase Authentication com e-mail/senha (ou outro provedor) e associar todos os dispositivos ao mesmo UID. Não compartilhe regras abertas para contornar isso.

## 5. Dados e documentos

- A ponte sincroniza o objeto principal `db` como JSON no Realtime Database.
- Uploads de documentos dos alunos podem ser feitos por `FirebaseStudio.uploadStudentDocument(studentId, file)`.
- Para obter URL de download: `FirebaseStudio.downloadStudentDocument(path)`.
- Os documentos já existentes no IndexedDB não são migrados automaticamente. Faça exportação/migração específica antes de apagar dados locais.

## 6. Segurança e produção

- Não coloque senhas privadas ou credenciais de servidor no JavaScript.
- A `apiKey` do Firebase Web não é uma senha; a segurança vem das regras e da autenticação.
- Revise as regras no Console e monitore uso/custos.
- Dados de alunos podem conter dados pessoais e informações de saúde. Restrinja acesso, colete apenas o necessário e avalie obrigações da LGPD antes de armazenar documentos na nuvem.

## Referências oficiais

- Firebase Web: https://firebase.google.com/docs/web/setup
- Firebase Hosting: https://firebase.google.com/docs/hosting
- Realtime Database Security Rules: https://firebase.google.com/docs/database/security
- Firebase Authentication: https://firebase.google.com/docs/auth
- Cloud Storage Security Rules: https://firebase.google.com/docs/storage/security
