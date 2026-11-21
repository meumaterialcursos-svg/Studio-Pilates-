/* Sincronização opcional com o Firebase (Auth + Firestore). Se falhar ou estiver offline, o app segue 100% local. */
import { firebaseConfig, SDK_VERSION, ENABLE_ANALYTICS } from './firebase-config.js';
import { fnv, split, join, parseDb, isEmptyDb, decide } from './sync-core.js';
const KEY = 'studio_pilates_louise_karla_v2', BKP = KEY + '_backup', VAULT = 'studio_pilates_louise_karla_students_v1', ST = 'sp_sync_state', PRE = 'sp_pre_sync';
const $ = s => document.querySelector(s), L = k => localStorage.getItem(k);
const rd = () => { try { return JSON.parse(L(ST) || 'null'); } catch { return null; } };
const wr = o => { try { localStorage.setItem(ST, JSON.stringify(o)); } catch {} };
const dev = (() => { let d = L('sp_sync_dev'); if (!d) { d = Math.random().toString(36).slice(2, 10); try { localStorage.setItem('sp_sync_dev', d); } catch {} } return d; })();
let fb = null, user = null, busy = false, again = false, timer = 0, unsub = null, S = { k: 'init' };
const TXT = { init: 'Conectando ao Firebase…', offline: 'Sem conexão com o Firebase. O app continua funcionando só neste aparelho.', out: 'Não conectado. Entre para sincronizar entre aparelhos.', ok: 'Sincronizado.', push: 'Enviando alterações…', pull: 'Baixando dados da nuvem…', avail: 'Há dados mais recentes na nuvem.', conflict: 'Este aparelho e a nuvem têm alterações diferentes. Escolha qual manter.', err: 'Não foi possível sincronizar.' };
const ERR = { 'auth/invalid-credential': 'E-mail ou senha incorretos.', 'auth/wrong-password': 'E-mail ou senha incorretos.', 'auth/user-not-found': 'E-mail ou senha incorretos.', 'auth/invalid-email': 'E-mail inválido.', 'auth/email-already-in-use': 'Este e-mail já tem conta. Use Entrar.', 'auth/weak-password': 'Use uma senha com 6 caracteres ou mais.', 'auth/too-many-requests': 'Muitas tentativas. Aguarde alguns minutos.', 'auth/network-request-failed': 'Sem internet. Tente novamente.', 'auth/operation-not-allowed': 'Login por e-mail não está ativado no Firebase.', 'auth/admin-restricted-operation': 'Criação de contas desativada. Peça à proprietária para cadastrar seu e-mail.', 'permission-denied': 'Sem permissão no Firestore. Publique o firestore.rules (veja FIREBASE.md).' };
const friendly = e => ERR[e?.code] || ERR[(e?.code || '').replace('firestore/', '')] || e?.message || 'Erro inesperado.';
const meta = () => fb.doc(fb.db, `users/${user.uid}/sync/meta`), chunk = (r, i) => fb.doc(fb.db, `users/${user.uid}/sync/d${r}_${i}`);
function mount() {
  const set = $('#page-settings'); if (!set || $('#fbCard')) return;
  const c = document.createElement('div'); c.className = 'card'; c.id = 'fbCard';
  c.innerHTML = `<h2>Nuvem (Firebase)</h2><div class="sub" id="fbSt" role="status" aria-live="polite"></div>
<div id="fbOut" hidden><div class="form"><div class="field"><label for="fbEmail">E-mail</label><input id="fbEmail" type="email" autocomplete="username" inputmode="email"></div><div class="field"><label for="fbPass">Senha da nuvem</label><input id="fbPass" type="password" autocomplete="current-password"></div></div>
<div class="row-acts" style="margin-top:10px;flex-wrap:wrap"><button type="button" class="btn primary" id="fbLogin">Entrar</button><button type="button" class="btn" id="fbCreate">Criar conta</button></div></div>
<div id="fbIn" hidden><div class="sub" id="fbWho" style="margin-top:6px"></div><div class="row-acts" style="flex-wrap:wrap;margin-top:10px"><button type="button" class="btn primary" id="fbSync">Sincronizar agora</button><button type="button" class="btn" id="fbPull">Baixar da nuvem</button><button type="button" class="btn" id="fbPush">Enviar deste aparelho</button><button type="button" class="btn" id="fbLogout">Sair</button></div></div>
<div class="err" id="fbErr" role="alert"></div><div class="sub" style="margin-top:8px">Seus dados ficam na sua conta Firebase, acessíveis só por você. A senha do app e a senha da nuvem são independentes.</div>`;
  const a = [...set.querySelectorAll('.card')].find(x => x.querySelector('h2')?.textContent.trim() === 'Dados e backup'); a ? a.before(c) : set.append(c);
  const st = document.createElement('style'); st.textContent = '#fbBn{position:fixed;left:12px;right:12px;bottom:calc(86px + env(safe-area-inset-bottom,0px));z-index:40;max-width:520px;margin:0 auto;display:flex;gap:8px;align-items:center;padding:10px 12px;background:var(--card);color:var(--ink);border:1px solid var(--line);border-radius:12px;box-shadow:0 8px 28px rgba(0,0,0,.18)}#fbBn[hidden]{display:none}#fbBn span{flex:1;font-size:13px}';
  document.head.append(st); const b = document.createElement('div'); b.id = 'fbBn'; b.hidden = true; b.setAttribute('role', 'status'); document.body.append(b);
  const on = (id, f) => $(id).addEventListener('click', f);
  on('#fbLogin', () => login(false)); on('#fbCreate', () => login(true)); on('#fbSync', () => evaluate());
  on('#fbLogout', () => fb && fb.signOut(fb.auth)); on('#fbPull', forcePull); on('#fbPush', forcePush);
  $('#fbPass').addEventListener('keydown', e => { if (e.key === 'Enter') { e.preventDefault(); login(false); } });
  b.addEventListener('click', e => { const t = e.target.closest('[data-b]')?.dataset.b; if (t === 'pull') forcePull(); else if (t === 'go') { b.hidden = true; window.go?.('settings'); } else if (t === 'x') b.hidden = true; });
}
function ui() {
  if (!$('#fbCard')) return; const k = S.k;
  $('#fbSt').textContent = TXT[k] + (k === 'ok' && rd()?.at ? ' Última sincronização: ' + new Date(rd().at).toLocaleString('pt-BR', { dateStyle: 'short', timeStyle: 'short' }) : '');
  $('#fbOut').hidden = !(fb && !user); $('#fbIn').hidden = !user; $('#fbWho').textContent = user ? 'Conectado como ' + user.email : '';
  $('#fbErr').textContent = k === 'err' ? S.m || '' : '';
  const bn = $('#fbBn'); bn.hidden = !(k === 'avail' || k === 'conflict');
  if (!bn.hidden) bn.innerHTML = k === 'avail' ? '<span>Há dados mais recentes na nuvem.</span><button type="button" class="btn sm primary" data-b="pull">Carregar</button><button type="button" class="btn sm" data-b="x" aria-label="Dispensar">×</button>' : '<span>Alterações diferentes neste aparelho e na nuvem.</span><button type="button" class="btn sm primary" data-b="go">Resolver</button><button type="button" class="btn sm" data-b="x" aria-label="Dispensar">×</button>';
}
const setS = (k, m) => { S = { k, m }; ui(); };
async function push(m, str) {
  const uid = user.uid, base = m ? m.rev : 0, rev = base + 1, parts = split(str), h = fnv(str);
  await fb.runTransaction(fb.db, async tx => {
    const s = await tx.get(meta()); if ((s.exists() ? s.data().rev : 0) !== base) throw Object.assign(new Error('rev'), { code: 'sync/conflict' });
    parts.forEach((d, i) => tx.set(chunk(rev, i), { i, d }));
    tx.set(meta(), { rev, chunks: parts.length, bytes: str.length, hash: h, device: dev, schema: 1, updatedAt: fb.serverTimestamp() });
  });
  wr({ uid, rev, hash: h, at: Date.now() });
  if (m) for (let i = 0; i < (m.chunks || 0); i++) fb.deleteDoc(chunk(base, i)).catch(() => {});
}
async function pull(m) {
  const ps = await Promise.all(Array.from({ length: m.chunks }, (_, i) => fb.getDoc(chunk(m.rev, i))));
  if (ps.some(p => !p.exists())) throw new Error('Dados da nuvem incompletos. Tente novamente.');
  const str = join(ps.map(p => p.data()).sort((a, b) => a.i - b.i).map(x => x.d)), d = parseDb(str);
  if (!d) throw new Error('Dados da nuvem inválidos. Nada foi alterado.');
  const o = [L(KEY), L(BKP), L(VAULT)], cur = o[0];
  if (cur && !isEmptyDb(parseDb(cur))) { try { localStorage.setItem(PRE, cur); } catch { throw new Error('Sem espaço para guardar a cópia de segurança. Exporte um backup e tente de novo.'); } }
  try { localStorage.setItem(KEY, str); localStorage.setItem(BKP, str); localStorage.setItem(VAULT, JSON.stringify(d.students)); }
  catch { [KEY, BKP, VAULT].forEach((k, i) => { try { o[i] == null ? localStorage.removeItem(k) : localStorage.setItem(k, o[i]); } catch {} }); throw new Error('Sem espaço no aparelho. Nada foi alterado.'); }
  wr({ uid: user.uid, rev: m.rev, hash: fnv(str), at: Date.now() }); location.reload();
}
async function evaluate() {
  if (!fb || !user) return; if (busy) { again = true; return; } busy = true;
  try {
    const s = await fb.getDoc(meta()), m = s.exists() ? s.data() : null, cur = L(KEY) || '', st = rd(), mine = st && st.uid === user.uid ? st : null;
    const a = decide({ remoteRev: m ? m.rev : null, stateRev: mine ? mine.rev : null, stateHash: mine?.hash, localHash: fnv(cur), localEmpty: isEmptyDb(parseDb(cur)) });
    if (a === 'push') { setS('push'); await push(m, cur); setS('ok'); }
    else if (a === 'pull') { setS('pull'); await pull(m); }
    else if (a === 'pull-available') setS('avail'); else if (a === 'conflict') setS('conflict'); else setS('ok');
  } catch (e) { if (e.code === 'sync/conflict') again = true; else setS('err', friendly(e)); }
  finally { busy = false; if (again) { again = false; setTimeout(evaluate, 600); } }
}
async function forcePull() { if (!user) return; try { const s = await fb.getDoc(meta()); if (!s.exists()) return setS('err', 'A nuvem ainda não tem dados.'); if (rd()?.uid === user.uid && L(KEY) && fnv(L(KEY)) !== rd().hash && !confirm('Substituir os dados deste aparelho pelos da nuvem? Uma cópia de segurança será guardada.')) return; setS('pull'); await pull(s.data()); } catch (e) { setS('err', friendly(e)); } }
async function forcePush() { if (!user || !confirm('Substituir os dados da nuvem pelos deste aparelho?')) return; try { setS('push'); const s = await fb.getDoc(meta()); await push(s.exists() ? s.data() : null, L(KEY) || ''); setS('ok'); } catch (e) { e.code === 'sync/conflict' ? evaluate() : setS('err', friendly(e)); } }
async function login(create) {
  const e = $('#fbEmail').value.trim(), p = $('#fbPass').value; if (!e || !p) return setS('err', 'Informe e-mail e senha.');
  try { await (create ? fb.createUserWithEmailAndPassword : fb.signInWithEmailAndPassword)(fb.auth, e, p); $('#fbPass').value = ''; } catch (x) { setS('err', friendly(x)); }
}
async function boot() {
  mount(); setS('init');
  try {
    const B = `https://www.gstatic.com/firebasejs/${SDK_VERSION}/`, [A, Au, F] = await Promise.all([import(B + 'firebase-app.js'), import(B + 'firebase-auth.js'), import(B + 'firebase-firestore.js')]);
    const app = A.initializeApp(firebaseConfig); fb = { ...Au, ...F, auth: Au.getAuth(app), db: F.getFirestore(app) };
    if (ENABLE_ANALYTICS) import(B + 'firebase-analytics.js').then(m => m.getAnalytics(app)).catch(() => {});
    fb.onAuthStateChanged(fb.auth, u => { user = u; unsub?.(); unsub = null; if (u) { unsub = fb.onSnapshot(meta(), snap => { const r = snap.exists() ? snap.data().rev : 0, st = rd(); if (!st || st.uid !== user?.uid || st.rev !== r) evaluate(); }, () => {}); evaluate(); } else setS('out'); });
  } catch { setS('offline'); addEventListener('online', () => { if (!fb) boot(); }, { once: true }); }
}
let seen = L(KEY);
setInterval(() => { const c = L(KEY); if (c !== seen) { seen = c; clearTimeout(timer); timer = setTimeout(evaluate, 2500); } }, 2000);
document.addEventListener('visibilitychange', () => { if (!document.hidden) evaluate(); });
boot();
