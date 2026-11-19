/* Firebase × Studio Pilates LK — sincronização local-first.
   localStorage continua sendo a fonte primária; o Firestore é o espelho em nuvem (diff por item). */
import { initializeApp } from "https://www.gstatic.com/firebasejs/13.1.0/firebase-app.js";
import { getAnalytics, isSupported, logEvent } from "https://www.gstatic.com/firebasejs/13.1.0/firebase-analytics.js";
import { getAuth, onAuthStateChanged, signInWithEmailAndPassword, signOut, updatePassword } from "https://www.gstatic.com/firebasejs/13.1.0/firebase-auth.js";
import { getFirestore, initializeFirestore, persistentLocalCache, persistentMultipleTabManager, collection, doc, onSnapshot, writeBatch } from "https://www.gstatic.com/firebasejs/13.1.0/firebase-firestore.js";

const firebaseConfig = {
  apiKey: "AIzaSyDLSAYuUU3O1DBXXOwP0Pt4rXEmGX6rsQ0",
  authDomain: "louise-891b3.firebaseapp.com",
  projectId: "louise-891b3",
  storageBucket: "louise-891b3.firebasestorage.app",
  messagingSenderId: "650364668322",
  appId: "1:650364668322:web:7cdd30f7a7ddb3d7c6cafb",
  measurementId: "G-JRLYKP7FZE"
};

const app = initializeApp(firebaseConfig);
let analytics = null;
isSupported().then(ok => { if (ok) analytics = getAnalytics(app); }).catch(() => {});
const auth = getAuth(app);
let fs;
try { fs = initializeFirestore(app, { localCache: persistentLocalCache({ tabManager: persistentMultipleTabManager() }) }); }
catch { fs = getFirestore(app); }

const COLS = ['students', 'classes', 'finance', 'makeups', 'waitlist', 'equipment', 'plans'];
const META = 'meta/state', MAX_META = 900000;
const App = () => window.SPApp;
const enc = encodeURIComponent, dec = decodeURIComponent;
const synced = Object.create(null);
let uid = null, unsubs = [], ready = false, timer = 0, rt = 0;

const metaOf = db => { const m = {}; for (const k of Object.keys(db)) if (!COLS.includes(k)) m[k] = db[k]; return m; };
function snapshot(db) {
  const m = {};
  for (const c of COLS) for (const it of db[c] || []) if (it && typeof it.id === 'string') m[c + '/' + enc(it.id)] = JSON.stringify(it);
  m[META] = JSON.stringify(metaOf(db));
  return m;
}

function push() { if (ready && uid) { clearTimeout(timer); timer = setTimeout(flush, 700); } }
function flush() {
  const a = App(); if (!a || !uid || !ready) return;
  const cur = snapshot(a.db), ops = [];
  for (const k in cur) if (synced[k] !== cur[k]) ops.push(['set', k, cur[k]]);
  for (const k in synced) if (!(k in cur)) ops.push(['del', k]);
  if (!ops.length) return;
  if (cur[META].length > MAX_META) return a.toast('Configurações grandes demais para a nuvem.');
  for (let i = 0; i < ops.length; i += 400) {
    const part = ops.slice(i, i + 400), b = writeBatch(fs);
    part.forEach(([t, k, json]) => {
      const [c, id] = k.split('/'), r = doc(fs, 'studios', uid, c, id);
      if (t === 'set') { b.set(r, { d: json, t: Date.now() }); synced[k] = json; } else { b.delete(r); delete synced[k]; }
    });
    b.commit().catch(e => {
      console.error(e);
      part.forEach(([t, k]) => { if (t === 'del') synced[k] = 'retry'; else delete synced[k]; });
      a.toast('Falha ao enviar à nuvem. Tentarei no próximo salvamento.');
    });
  }
}

function applyDirty() {
  clearTimeout(rt);
  rt = setTimeout(() => { const a = App(); if (a && a.save()) { a.applyTheme(); a.render(); } }, 500);
}
function applyCol(c, s) {
  const a = App(); let dirty = false;
  s.docChanges().forEach(ch => {
    if (ch.doc.metadata.hasPendingWrites) return;
    const key = c + '/' + ch.doc.id, id = dec(ch.doc.id), arr = a.db[c] || (a.db[c] = []), i = arr.findIndex(x => x.id === id);
    if (ch.type === 'removed') { if (i >= 0) { arr.splice(i, 1); dirty = true; } delete synced[key]; return; }
    const json = ch.doc.data().d; let obj;
    try { obj = JSON.parse(json); } catch { return; }
    synced[key] = json;
    if (i < 0) { arr.push(obj); dirty = true; }
    else if (JSON.stringify(arr[i]) !== json) { arr[i] = obj; dirty = true; }
  });
  if (dirty) applyDirty();
}
function applyMeta(s) {
  s.docChanges().forEach(ch => {
    if (ch.doc.id !== 'state' || ch.type === 'removed' || ch.doc.metadata.hasPendingWrites) return;
    const json = ch.doc.data().d; let m;
    try { m = JSON.parse(json); } catch { return; }
    const a = App();
    synced[META] = json;
    if (JSON.stringify(metaOf(a.db)) !== json) { Object.assign(a.db, m); applyDirty(); }
  });
}

function stop() { unsubs.forEach(f => f()); unsubs = []; ready = false; for (const k in synced) delete synced[k]; }
function start() {
  stop();
  let left = COLS.length + 1;
  const first = () => { if (--left === 0) { ready = true; flush(); App().toast('☁️ Nuvem sincronizada.'); } };
  const watch = (path, handler) => {
    let init = true;
    unsubs.push(onSnapshot(collection(fs, 'studios', uid, path), s => { handler(s); if (init) { init = false; first(); } }, e => {
      console.error(e);
      App()?.toast(e.code === 'permission-denied' ? 'Nuvem: sem permissão (publique as regras do Firestore).' : 'Nuvem indisponível.');
    }));
  };
  COLS.forEach(c => watch(c, s => applyCol(c, s)));
  watch('meta', applyMeta);
}

onAuthStateChanged(auth, u => { if (u) { uid = u.uid; start(); } else { stop(); uid = null; } });

window.FB = {
  push,
  track: (n, p) => { try { analytics && logEvent(analytics, n, p); } catch {} },
  async signIn(email, pw) {
    try { await signInWithEmailAndPassword(auth, email, pw); try { localStorage.setItem('sp_fb_email', email); } catch {} return true; }
    catch (e) { App()?.toast(e.code === 'auth/network-request-failed' ? 'Sem internet: nuvem não conectada.' : 'Nuvem: e-mail ou senha inválidos.'); return false; }
  },
  async signOut() { try { await signOut(auth); } catch {} },
  async updatePassword(pw) {
    try { if (auth.currentUser) await updatePassword(auth.currentUser, pw); }
    catch (e) { App()?.toast(e.code === 'auth/requires-recent-login' ? 'Senha da nuvem não alterada: saia, entre de novo e repita.' : 'Senha da nuvem não alterada.'); }
  }
};
