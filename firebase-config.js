// Configuração pública do app web (louise-891b3). A apiKey do Firebase NÃO é segredo:
// quem protege os dados são o login (Authentication) e o firestore.rules.
export const firebaseConfig = {
  apiKey: "AIzaSyDLSAYuUU3O1DBXXOwP0Pt4rXEmGX6rsQ0",
  authDomain: "louise-891b3.firebaseapp.com",
  projectId: "louise-891b3",
  storageBucket: "louise-891b3.firebasestorage.app",
  messagingSenderId: "650364668322",
  appId: "1:650364668322:web:7cdd30f7a7ddb3d7c6cafb",
  measurementId: "G-JRLYKP7FZE"
};
// Versão do SDK carregada do CDN oficial (gstatic). Para atualizar, troque aqui e em README.md.
export const SDK_VERSION = "12.15.0";
// Analytics fica DESLIGADO por padrão: o app guarda dados de alunos (LGPD). Mude para true só se precisar.
export const ENABLE_ANALYTICS = false;
