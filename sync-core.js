/* Lógica pura de sincronização (sem Firebase e sem DOM) — testável em Node. */
export const COLS = ['students', 'classes', 'finance', 'makeups', 'waitlist', 'equipment', 'plans'];
export const META = 'meta/state', MAX_META = 900000;
export const enc = encodeURIComponent, dec = decodeURIComponent;

export const metaOf = db => { const m = {}; for (const k of Object.keys(db)) if (!COLS.includes(k)) m[k] = db[k]; return m; };

/** db -> { "colecao/id": json, "meta/state": json } */
export function snapshot(db) {
  const m = {};
  for (const c of COLS) for (const it of db[c] || []) if (it && typeof it.id === 'string') m[c + '/' + enc(it.id)] = JSON.stringify(it);
  m[META] = JSON.stringify(metaOf(db));
  return m;
}

/** Diferença entre o último estado enviado (synced) e o atual (cur) -> [['set',k,json] | ['del',k]] */
export function diff(synced, cur) {
  const ops = [];
  for (const k in cur) if (synced[k] !== cur[k]) ops.push(['set', k, cur[k]]);
  for (const k in synced) if (!(k in cur)) ops.push(['del', k]);
  return ops;
}
