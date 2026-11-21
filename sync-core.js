/* Lógica pura de sincronização (sem Firebase). Roda no navegador e no Node, por isso é testável. */
export const CHUNK = 350000; // caracteres por documento (limite do Firestore: ~1 MiB por documento)
export function fnv(s) { let h = 0x811c9dc5; for (let i = 0; i < s.length; i++) { h ^= s.charCodeAt(i); h = Math.imul(h, 0x01000193); } return (h >>> 0).toString(16) + '.' + s.length; }
export function split(s, n = CHUNK) { // nunca corta um par substituto (emoji), para o texto voltar idêntico
  const a = []; let i = 0;
  while (i < s.length) { let e = Math.min(i + n, s.length); if (e < s.length) { const c = s.charCodeAt(e - 1); if (c >= 0xD800 && c <= 0xDBFF) e--; } a.push(s.slice(i, e)); i = e; }
  return a.length ? a : [''];
}
export const join = a => a.join('');
export function parseDb(s) { try { const d = JSON.parse(s); return d && typeof d === 'object' && Array.isArray(d.students) && Array.isArray(d.classes) ? d : null; } catch { return null; } }
export const isEmptyDb = d => !d || !((d.students || []).length || (d.classes || []).length || (d.finance || []).length || (d.makeups || []).length || (d.waitlist || []).length);
/* Decide o que fazer. Nunca sobrescreve em silêncio quando os dois lados têm alterações. */
export function decide({ remoteRev, stateRev, stateHash, localHash, localEmpty }) {
  if (remoteRev == null) return localEmpty ? 'idle' : 'push';
  if (stateRev == null) return localEmpty ? 'pull' : 'conflict';
  const dirty = localHash !== stateHash;
  if (remoteRev > stateRev) return dirty ? 'conflict' : 'pull-available';
  if (remoteRev < stateRev) return 'conflict';
  return dirty ? 'push' : 'idle';
}
