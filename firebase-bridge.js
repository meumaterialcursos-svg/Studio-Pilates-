/*
 * Ponte Firebase para o Studio Pilates.
 * Usa Firebase Authentication anônimo e Realtime Database.
 * ATENÇÃO: autenticação anônima cria um UID por instalação/navegador.
 * Para sincronizar entre aparelhos, implemente login persistente (e-mail/senha)
 * e vincule os dispositivos à mesma conta Firebase.
 */
<script type="module">
  // Import the functions you need from the SDKs you need
  <script type="module">
  // Import the functions you need from the SDKs you need
  import { initializeApp } from "https://www.gstatic.com/firebasejs/13.4.0/firebase-app.js";
  import { getAnalytics } from "https://www.gstatic.com/firebasejs/13.4.0/firebase-analytics.js";
  // TODO: Add SDKs for Firebase products that you want to use
  // https://firebase.google.com/docs/web/setup#available-libraries

  // Your web app's Firebase configuration
  // For Firebase JS SDK v7.20.0 and later, measurementId is optional
  const firebaseConfig = {
    apiKey: "AIzaSyDLSAYuUU3O1DBXXOwP0Pt4rXEmGX6rsQ0",
    authDomain: "louise-891b3.firebaseapp.com",
    projectId: "louise-891b3",
    storageBucket: "louise-891b3.firebasestorage.app",
    messagingSenderId: "650364668322",
    appId: "1:650364668322:web:7cdd30f7a7ddb3d7c6cafb",
    measurementId: "G-JRLYKP7FZE"
  };

  // Initialize Firebase
  const app = initializeApp(firebaseConfig);
  const analytics = getAnalytics(app);
</script>
  const app = initializeApp(firebaseConfig);
  const analytics = getAnalytics(app);
</script>
(function () {
  "use strict";
  const SDK = "https://www.gstatic.com/firebasejs/10.14.1/";
  let app, auth, db, storage, uid, readyPromise;
  let timer = null;
  let lastPayload = "";

  function configured() {
    const c = window.FIREBASE_CONFIG;
    return !!(c && c.apiKey && c.projectId && c.databaseURL &&
      !String(c.apiKey).startsWith("SUA_") &&
      !String(c.projectId).startsWith("SEU_"));
  }

  async function loadSdk() {
    if (window.firebase) return;
    await new Promise((resolve, reject) => {
      const s = document.createElement("script");
      s.src = SDK + "firebase-app-compat.js";
      s.onload = resolve; s.onerror = reject; document.head.appendChild(s);
    });
    await Promise.all(["firebase-auth-compat.js", "firebase-database-compat.js", "firebase-storage-compat.js"].map(file =>
      new Promise((resolve, reject) => {
        const s = document.createElement("script");
        s.src = SDK + file; s.onload = resolve; s.onerror = reject; document.head.appendChild(s);
      })
    ));
  }

  async function init() {
    if (readyPromise) return readyPromise;
    readyPromise = (async () => {
      if (!configured()) throw new Error("Firebase ainda não configurado. Edite firebase-config.js.");
      await loadSdk();
      app = window.firebase.apps.length ? window.firebase.app() : window.firebase.initializeApp(window.FIREBASE_CONFIG);
      auth = window.firebase.auth();
      db = window.firebase.database();
      storage = window.firebase.storage();
      if (!auth.currentUser) await auth.signInAnonymously();
      uid = auth.currentUser.uid;
      return { uid };
    })();
    try { return await readyPromise; } catch (e) { readyPromise = null; throw e; }
  }

  async function pull() {
    await init();
    const snap = await db.ref("users/" + uid + "/studioData").get();
    if (!snap.exists()) return null;
    const row = snap.val();
    if (!row || typeof row.payload !== "string") return null;
    try { return JSON.parse(row.payload); } catch { return null; }
  }

  async function push(data) {
    await init();
    const payload = JSON.stringify(data);
    if (payload.length > 10000000) throw new Error("Dados excedem o limite de 10 MB configurado para sincronização.");
    await db.ref("users/" + uid + "/studioData").set({
      payload,
      updatedAt: Date.now()
    });
    lastPayload = payload;
    return true;
  }

  function queue(data, delay = 1200) {
    clearTimeout(timer);
    timer = setTimeout(() => push(data).catch(err => {
      console.error("[Firebase Studio Pilates]", err);
      window.dispatchEvent(new CustomEvent("firebase-sync-error", { detail: err }));
    }), delay);
  }

  async function uploadStudentDocument(studentId, file) {
    await init();
    if (!studentId || !file) throw new Error("Aluno e arquivo são obrigatórios.");
    if (file.size > 15 * 1024 * 1024) throw new Error("Arquivo acima de 15 MB.");
    if (!(file.type === "application/pdf" || file.type.startsWith("image/")))
      throw new Error("Envie PDF ou imagem.");
    const safeName = String(file.name).replace(/[^a-zA-Z0-9._-]/g, "_");
    const ref = storage.ref(`users/${uid}/student-documents/${studentId}/${Date.now()}_${safeName}`);
    const result = await ref.put(file, { contentType: file.type });
    return { path: result.ref.fullPath, name: file.name, size: file.size, contentType: file.type };
  }

  async function downloadStudentDocument(path) {
    await init();
    if (!path || !path.startsWith(`users/${uid}/student-documents/`))
      throw new Error("Caminho de arquivo inválido.");
    return storage.ref(path).getDownloadURL();
  }

  window.FirebaseStudio = {
    init, pull, push, queue,
    uploadStudentDocument, downloadStudentDocument,
    get uid() { return uid || null; },
    get configured() { return configured(); }
  };
})();
