/* Firebase × Studio Pilates LK — sincronização local-first.
   localStorage continua sendo a fonte primária; o Firestore é o espelho em nuvem (diff por item). */
import { initializeApp } from "https://www.gstatic.com/firebasejs/13.1.0/firebase-app.js";
import { getAnalytics, isSupported, logEvent } from "https://www.gstatic.com/firebasejs/13.1.0/firebase-analytics.js";
import { getAuth, onAuthStateChanged, signInWithEmailAndPassword, signOut, updatePassword } from "https://www.gstatic.com/firebasejs/13.1.0/firebase-auth.js";
import { getFirestore, initializeFirestore, persistentLocalCache, persistentMultipleTabManager, collection, doc, onSnapshot, writeBatch } from "https://www.gstatic.com/firebasejs/13.1.0/firebase-firestore.js";

import { firebaseConfig } from "./firebase-config.js";
import { COLS, META, MAX_META, enc, dec, metaOf, snapshot, diff } from "./sync-core.js";

const app = initializeApp(firebaseConfig);
let analytics = null;
isSupported().then(ok => { if (ok) analytics = getAnalytics(app); }).catch(() => {});
const auth = getAuth(app);
let fs;
try { fs = initializeFirestore(app, { localCache: persistentLocalCache({ tabManager: persistentMultipleTabManager() }) }); }
catch { fs = getFirestore(app); }

const App = () => window.SPApp;
const synced = Object.create(null);
let uid = null, unsubs = [], ready = false, timer = 0, rt = 0;

/* ---- indicador visual (#cloudBtn): off · connecting · live · sync · offline · error ---- */
const ST = {
  off: 'Nuvem desligada — informe o e-mail no login para sincronizar',
  connecting: 'Conectando à nuvem…',
  sync: 'Sincronizando alterações…',
  live: 'Nuvem conectada — sincronização em tempo real',
  offline: 'Sem internet — alterações ficam salvas e sobem ao reconectar',
  error: 'Erro na nuvem — verifique o login e as regras do Firestore'
};
let inflight = 0, hasErr = false, lastSync = null;
const cloudEl = () => document.getElementById('cloudBtn');
function refresh() {
  const b = cloudEl(); if (!b) return;
  const s = !uid ? 'off' : !navigator.onLine ? 'offline' : hasErr ? 'error' : !ready ? 'connecting' : inflight ? 'sync' : 'live';
  const t = ST[s] + (uid && lastSync ? ' · última: ' + lastSync.toLocaleTimeString('pt-BR') : '');
  b.dataset.s = s; b.title = t; b.setAttribute('aria-label', t);
}
function flash() {
  const b = cloudEl(); lastSync = new Date(); refresh(); if (!b) return;
  b.classList.remove('flash'); void b.offsetWidth; b.classList.add('flash');
  setTimeout(() => b.classList.remove('flash'), 1300);
}
window.addEventListener('online', refresh);
window.addEventListener('offline', refresh);
const _b = cloudEl(); if (_b) _b.onclick = () => window.SPApp && window.SPApp.toast(_b.title);


function push() { if (ready && uid) { clearTimeout(timer); timer = setTimeout(flush, 700); } }
function flush() {
  const a = App(); if (!a || !uid || !ready) return;
  const cur = snapshot(a.db), ops = diff(synced, cur);
  if (!ops.length) return;
  if (cur[META].length > MAX_META) return a.toast('Configurações grandes demais para a nuvem.');
  for (let i = 0; i < ops.length; i += 400) {
    const part = ops.slice(i, i + 400), b = writeBatch(fs);
    part.forEach(([t, k, json]) => {
      const [c, id] = k.split('/'), r = doc(fs, 'studios', uid, c, id);
      if (t === 'set') { b.set(r, { d: json, t: Date.now() }); synced[k] = json; } else { b.delete(r); delete synced[k]; }
    });
    inflight++; refresh();
    b.commit().then(() => { lastSync = new Date(); }).catch(e => {
      console.error(e);
      part.forEach(([t, k]) => { if (t === 'del') synced[k] = 'retry'; else delete synced[k]; });
      a.toast('Falha ao enviar à nuvem. Tentarei no próximo salvamento.');
    }).finally(() => { inflight--; refresh(); });
  }
}

function applyDirty() {
  flash();
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

function stop() { unsubs.forEach(f => f()); unsubs = []; ready = false; hasErr = false; lastSync = null; for (const k in synced) delete synced[k]; refresh(); }
function start() {
  stop(); refresh();
  let left = COLS.length + 1;
  const first = () => { if (--left === 0) { ready = true; lastSync = new Date(); refresh(); flush(); App().toast('☁️ Nuvem sincronizada.'); } };
  const watch = (path, handler) => {
    let init = true;
    unsubs.push(onSnapshot(collection(fs, 'studios', uid, path), s => { if (hasErr) { hasErr = false; refresh(); } handler(s); if (init) { init = false; first(); } }, e => {
      console.error(e); hasErr = true; refresh();
      App()?.toast(e.code === 'permission-denied' ? 'Nuvem: sem permissão (publique as regras do Firestore).' : 'Nuvem indisponível.');
    }));
  };
  COLS.forEach(c => watch(c, s => applyCol(c, s)));
  watch('meta', applyMeta);
}

onAuthStateChanged(auth, u => { if (u) { uid = u.uid; start(); } else { uid = null; stop(); } });

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
