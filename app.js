'use strict';
/* ========== UTIL ========== */
const $=(s,r=document)=>r.querySelector(s), $$=(s,r=document)=>[...r.querySelectorAll(s)];
const esc=v=>String(v??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const uid=p=>p+'_'+Date.now().toString(36)+Math.random().toString(36).slice(2,6);
const money=v=>Number(v||0).toLocaleString('pt-BR',{style:'currency',currency:'BRL'});
const pad=n=>String(n).padStart(2,'0');
const iso=d=>`${d.getFullYear()}-${pad(d.getMonth()+1)}-${pad(d.getDate())}`;
const fmtDate=s=>s?s.split('-').reverse().join('/'):'—';
const DAY={0:'Dom',1:'Seg',2:'Ter',3:'Qua',4:'Qui',5:'Sex',6:'Sáb'};
const STATUS=['Agendada','Confirmada','Realizada','Falta','Cancelada'];
const STATUS_CLS={Agendada:'info',Confirmada:'ok',Realizada:'ok',Falta:'bad',Cancelada:'warn'};
let toastT;
function toast(m){const t=$('#toast');t.textContent=m;t.classList.add('on');clearTimeout(toastT);toastT=setTimeout(()=>t.classList.remove('on'),2400)}

/* ========== SHA-256 (compatível com o hash original) ========== */
function sha256(msg){
  const pr=[];for(let n=2;pr.length<64;n++)if(pr.every(p=>n%p))pr.push(n);
  const fr=x=>((x-Math.floor(x))*4294967296)>>>0;
  const K=pr.map(p=>fr(Math.cbrt(p))),H=pr.slice(0,8).map(p=>fr(Math.sqrt(p)));
  const d=new TextEncoder().encode(msg),l=d.length,n=((l+9+63)>>6)<<6,b=new Uint8Array(n);
  b.set(d);b[l]=0x80;const dv=new DataView(b.buffer);
  dv.setUint32(n-8,Math.floor(l/0x20000000));dv.setUint32(n-4,(l<<3)>>>0);
  const w=new Uint32Array(64),R=(x,k)=>(x>>>k)|(x<<(32-k));
  for(let o=0;o<n;o+=64){
    for(let i=0;i<16;i++)w[i]=dv.getUint32(o+i*4);
    for(let i=16;i<64;i++){const a=w[i-15],c=w[i-2];w[i]=(w[i-16]+(R(a,7)^R(a,18)^(a>>>3))+w[i-7]+(R(c,17)^R(c,19)^(c>>>10)))|0}
    let[A,B,C,D,E,F,G,J]=H;
    for(let i=0;i<64;i++){
      const t1=(J+(R(E,6)^R(E,11)^R(E,25))+((E&F)^(~E&G))+K[i]+w[i])|0;
      const t2=((R(A,2)^R(A,13)^R(A,22))+((A&B)^(A&C)^(B&C)))|0;
      J=G;G=F;F=E;E=(D+t1)|0;D=C;C=B;B=A;A=(t1+t2)|0;
    }
    [A,B,C,D,E,F,G,J].forEach((v,i)=>H[i]=(H[i]+v)|0);
  }
  return H.map(v=>(v>>>0).toString(16).padStart(8,'0')).join('');
}

/* ========== LOGIN ========== */
const Auth=(()=>{
  const DEF={salt:'studio-pilates-lk::v1',hash:'dde89813258104c6fb5af1930d840ec25ce5f61334641ca589201c3a5d819314'};
  const ITER=5000,KEY='sp_auth_v1',FAIL='sp_auth_fail_v1',SESSION=12*36e5,REMEMBER=30*864e5,MAX_FREE=5;
  let mem=false;
  const store=local=>{try{return local?localStorage:sessionStorage}catch{return null}};
  const cred=()=>{try{const c=JSON.parse(localStorage.getItem('sp_auth_cred_v1'));if(c&&c.salt&&c.hash)return c}catch{}return DEF};
  const stretch=(pw,salt)=>{let h=sha256(salt+':'+pw);for(let i=0;i<ITER;i++)h=sha256(h+salt);return h};
  const eq=(a,b)=>{if(a.length!==b.length)return false;let r=0;for(let i=0;i<a.length;i++)r|=a.charCodeAt(i)^b.charCodeAt(i);return r===0};
  const sig=exp=>sha256(cred().hash+'|'+exp);
  const fails=()=>{try{return JSON.parse(localStorage.getItem(FAIL))||{n:0,until:0}}catch{return{n:0,until:0}}};
  function valid(){
    if(mem)return true;
    for(const local of[false,true]){const s=store(local);if(!s)continue;
      try{const o=JSON.parse(s.getItem(KEY));if(o&&o.exp>Date.now()&&eq(String(o.sig),sig(o.exp)))return true;s.removeItem(KEY)}catch{}}
    return false;
  }
  function save(rem){
    const exp=Date.now()+(rem?REMEMBER:SESSION);
    try{store(rem).setItem(KEY,JSON.stringify({exp,sig:sig(exp)}));mem=false}catch{mem=true}
    try{store(!rem).removeItem(KEY)}catch{}
  }
  function logout(){mem=false;[false,true].forEach(l=>{try{store(l).removeItem(KEY)}catch{}})}
  function wait(){const f=fails();return Math.max(0,Math.ceil((f.until-Date.now())/1000))}
  async function attempt(pw,rem){
    if(wait())return{ok:false,msg:`Aguarde ${wait()}s para tentar novamente.`};
    await new Promise(r=>setTimeout(r,30)); // deixa a UI atualizar antes do cálculo
    const c=cred();
    if(eq(stretch(pw,c.salt),c.hash)){localStorage.removeItem(FAIL);save(rem);return{ok:true}}
    const f=fails();f.n++;
    if(f.n>=MAX_FREE)f.until=Date.now()+Math.min(300,Math.pow(2,f.n-MAX_FREE+2)*5)*1000;
    try{localStorage.setItem(FAIL,JSON.stringify(f))}catch{}
    return{ok:false,msg:'Senha incorreta.'};
  }
  async function change(cur,next){
    const c=cred();
    if(!eq(stretch(cur,c.salt),c.hash))return{ok:false,msg:'Senha atual incorreta.'};
    const salt=Array.from(crypto.getRandomValues(new Uint8Array(12)),b=>b.toString(16).padStart(2,'0')).join('');
    const rem=!!(store(true)&&store(true).getItem(KEY));
    try{localStorage.setItem('sp_auth_cred_v1',JSON.stringify({salt,hash:stretch(next,salt),num:/^\d+$/.test(next)}))}catch{return{ok:false,msg:'Não foi possível salvar a nova senha.'}}
    save(rem);return{ok:true};
  }
  const REQ='sp_auth_req_v1',norm=v=>{const n=String(v||'').replace(/\D/g,'');return(n.length===10||n.length===11)?'55'+n:n};
  const codeFor=p=>('000000'+(parseInt(sha256(cred().hash+'|'+p).slice(0,8),16)%1000000)).slice(-6);
  const readReq=()=>{try{const o=JSON.parse(localStorage.getItem(REQ));if(o&&o.exp>Date.now()&&o.tries<5)return o}catch{}return null};
  const writeReq=o=>{try{o?localStorage.setItem(REQ,JSON.stringify(o)):localStorage.removeItem(REQ)}catch{}};
  const pwError=(a,b)=>a.length<6?'A nova senha deve ter ao menos 6 caracteres.':a!==b?'As senhas não conferem.':/^(.)\1+$/.test(a)?'Escolha uma senha mais segura.':'';
  function request(){
    const A='ABCDEFGHJKMNPQRSTUVWXYZ23456789',r=crypto.getRandomValues(new Uint8Array(8));let p='';
    for(let i=0;i<8;i++){p+=A[r[i]%A.length];if(i===3)p+='-'}
    writeReq({p,exp:Date.now()+9e5,tries:0});return p;
  }
  function reset(code,a,b){
    const r=readReq();if(!r)return{ok:false,msg:'Nenhuma solicitação válida. Toque em "Solicitar pelo WhatsApp".'};
    const bad=pwError(a,b);if(bad)return{ok:false,msg:bad};
    if(!eq(String(code).trim(),codeFor(r.p))){r.tries++;writeReq(r.tries<5?r:null);return{ok:false,msg:r.tries<5?`Código inválido. ${5-r.tries} tentativa(s) restante(s).`:'Solicitação cancelada por excesso de tentativas. Solicite novamente.'}}
    const salt=Array.from(crypto.getRandomValues(new Uint8Array(12)),x=>x.toString(16).padStart(2,'0')).join('');
    try{localStorage.setItem('sp_auth_cred_v1',JSON.stringify({salt,hash:stretch(a,salt),num:/^\d+$/.test(a)}))}catch{return{ok:false,msg:'Não foi possível salvar a senha neste navegador.'}}
    writeReq(null);try{localStorage.removeItem(FAIL)}catch{}logout();return{ok:true};
  }
  function authorize(raw){const p=String(raw).toUpperCase().replace(/[^A-Z0-9]/g,'');if(p.length!==8)return null;const f=p.slice(0,4)+'-'+p.slice(4);return{p:f,code:codeFor(f)}}
  return{valid,attempt,logout,change,request,reset,authorize,norm};
})();

/* ========== DADOS ========== */
const MSG_DEFAULTS={billing:'{saudacao}, {nome}! 😊\n\nPassando para lembrar da mensalidade do {studio}.\n\nPlano: {plano}\nValor: {valor}\nVencimento: {vencimento} ({situacao})\n\nChave PIX ({pix_tipo}): {pix}\nBeneficiário: {pix_nome}\n\nQualquer dúvida, estamos à disposição!',late:'{saudacao}, {nome}! 😊\n\nIdentificamos que há mensalidade em aberto no {studio}:\n\n{lista_abertas}\n\nTotal em aberto: {total_aberto}\nMaior atraso: {dias_atraso} dia(s)\n\nChave PIX ({pix_tipo}): {pix}\nBeneficiário: {pix_nome}\n\nSe já realizou o pagamento, é só nos enviar o comprovante. Qualquer dúvida, estamos à disposição! 💜',reminder:'{saudacao}, {nome}! 😊\n\nSua mensalidade do {studio} {situacao} ({vencimento}).\nValor: {valor}\n\nChave PIX ({pix_tipo}): {pix}\nBeneficiário: {pix_nome}\n\nCaso já tenha pago, por favor desconsidere!','class':'{saudacao}, {nome}! 😊\n\nLembrete da sua próxima aula no {studio}:\n📅 {aula_dia}, {aula_data}\n🕒 {aula_hora}\n👤 Professor(a): {professor}\n🧘 Aparelho: {aparelho}\n\nPrecisa remarcar? Avise com antecedência para liberarmos a vaga. Até lá! 💜',classNow:'{saudacao}, {nome}! 😊\n\nSua aula das {aula_hora} no {studio} já começou. Está a caminho?\n\nSe não conseguir vir hoje, avise por aqui para ajustarmos a agenda.',birthday:'{saudacao}, {nome}! 🎂✨\n\nO {studio} deseja um feliz aniversário!\n🎈 {idade} anos de história e conquistas.\n\nQue seu novo ciclo seja cheio de saúde, movimento e muita energia. 💜',waitlist:'{saudacao}, {nome}! 😊\n\nSurgiu uma possibilidade de vaga no {studio}.\nPlano de interesse: {plano}\nHorário desejado: {horario}\n\nPodemos conversar sobre os detalhes? Fico no aguardo! 💜',general:'{saudacao}, {nome}! 😊\n\nAqui é {responsavel}, do {studio}.'};
const MSG_OLD={billing:'Olá, {nome}! 😊\n\nPassando para lembrar da mensalidade do {studio}.\n\nPlano: {plano}\nValor: {valor}\nVencimento: {vencimento}\n\nChave PIX ({pix_tipo}): {pix}\nBeneficiário: {pix_nome}\n\nQualquer dúvida, estamos à disposição!',birthday:'Olá, {nome}! 🎂✨\n\nO {studio} deseja um feliz aniversário! Que seu novo ciclo seja cheio de saúde, movimento e conquistas. 💜',reminder:'Olá, {nome}! 😊\n\nSua mensalidade do {studio} vence hoje ({vencimento}).\nValor: {valor}\nChave PIX: {pix}\n\nCaso já tenha pago, por favor desconsidere!'};
const KEY='studio_pilates_louise_karla_v2',BKP=KEY+'_backup',VAULT='studio_pilates_louise_karla_students_v1';
const DEFAULTS=()=>({
  settings:{studioName:'Studio de Pilates LOUISE KARLA',owner:'LOUISE KARLA',capacity:4,duration:60,darkMode:false,liquidGlass:false,glassV:3,theme:{preset:'marfim'},whatsapp:'',pixType:'CPF/CNPJ',pixKey:'',pixName:'',teacherRates:{},teacherFixedRates:{},teacherClassValues:{},messages:{...MSG_DEFAULTS}},
  plans:[{id:'pl1',name:'Plano 2X na semana',weekly:2,price:170},{id:'pl2',name:'Plano 3X na semana',weekly:3,price:220}],
  hours:['08:00','09:00','10:00','11:00','14:00','15:00','16:00','17:00','18:00','19:00','20:00','21:00'],
  teachers:['LOUISE KARLA','Professor 2','Prof. Substituto'],
  hourDays:{},alertDismissed:{},teacherClosings:{},students:[],classes:[],finance:[],makeups:[],waitlist:[],equipment:[{id:'eq_reformer',name:'Reformer',category:'Reformer',quantity:1,active:true,notes:''},{id:'eq_cadillac',name:'Cadillac',category:'Cadillac',quantity:1,active:true,notes:''},{id:'eq_chair',name:'Chair',category:'Chair',quantity:1,active:true,notes:''},{id:'eq_barrel',name:'Ladder Barrel',category:'Barrel',quantity:1,active:true,notes:''},{id:'eq_spine',name:'Spine Corrector',category:'Acessório',quantity:1,active:true,notes:''}]
});
let db=load();
function load(){
  const def=DEFAULTS();
  for(const k of[KEY,BKP]){
    try{const raw=localStorage.getItem(k);if(!raw)continue;const p=JSON.parse(raw);
      if(p&&typeof p==='object'&&Array.isArray(p.students)&&Array.isArray(p.classes)){
        const d={...def,...p,settings:{...def.settings,...(p.settings||{}),messages:{...def.settings.messages,...((p.settings||{}).messages||{})}}};
        ['plans','hours','teachers','finance','makeups','waitlist','equipment'].forEach(a=>{if(!Array.isArray(d[a]))d[a]=def[a]});
        Object.keys(MSG_OLD).forEach(k=>{if(d.settings.messages[k]===MSG_OLD[k])d.settings.messages[k]=MSG_DEFAULTS[k]}); // atualiza só modelos que nunca foram personalizados
        d.classes.forEach(c=>{if(!c.status)c.status='Agendada'});
        if((p.settings||{}).glassV!==3){d.settings.liquidGlass=false;d.settings.glassV=3} // migração única: visual minimalista é o padrão; escolhas feitas depois são respeitadas
        if(!d.hourDays||typeof d.hourDays!=='object'||Array.isArray(d.hourDays))d.hourDays={};
        ['alertDismissed','teacherClosings'].forEach(k=>{if(!d[k]||typeof d[k]!=='object'||Array.isArray(d[k]))d[k]={}});
        ['teacherRates','teacherFixedRates','teacherClassValues'].forEach(k=>{if(!d.settings[k]||typeof d.settings[k]!=='object')d.settings[k]={}});
        return mergeVault(d);}
    }catch(e){console.error('Falha ao ler',k,e)}
  }
  return mergeVault(def);
}
/* cofre redundante de alunos: evita perder cadastros se o banco principal falhar */
function mergeVault(d){
  try{const v=JSON.parse(localStorage.getItem(VAULT));
    if(Array.isArray(v)){const ids=new Set(d.students.map(s=>s.id));v.forEach(s=>{if(s&&s.id&&!ids.has(s.id))d.students.push(s)})}}catch{}
  return d;
}
function save(){
  try{
    const cur=localStorage.getItem(KEY);if(cur)localStorage.setItem(BKP,cur);
    localStorage.setItem(KEY,JSON.stringify(db));
    localStorage.setItem(VAULT,JSON.stringify(db.students));
    try{window.FB&&window.FB.push()}catch{} /* Firebase: espelho em nuvem */
    return true;
  }catch(e){toast('Erro ao salvar dados locais.');return false}
}

/* ========== HELPERS DE NEGÓCIO ========== */
const studentById=id=>db.students.find(s=>s.id===id);
const classById=id=>db.classes.find(c=>c.id===id);
const activeStudents=()=>db.students.filter(s=>(s.status||'Ativo')==='Ativo');
const normDays=a=>[...new Set((a||[]).map(String).filter(d=>/^[0-6]$/.test(d)))].sort();
const slotCount=(date,time,ignoreId)=>db.classes.filter(c=>c.date===date&&c.time===time&&c.id!==ignoreId&&c.status!=='Cancelada').length;
const sortCls=(a,b)=>(a.date+a.time).localeCompare(b.date+b.time);
const waLink=(num,msg)=>{const n=String(num||'').replace(/\D/g,'');return n?`https://wa.me/${n.length<=11?'55'+n:n}?text=${encodeURIComponent(msg||'')}`:''};

/* ========== NAVEGAÇÃO / TEMA ========== */
const MAIN=['dashboard','students','agenda','money'];
const MONEY_ALIAS={finance:{tab:'entries'},billing:{tab:'entries',st:'open',type:'Receita'},expenses:{tab:'gastos'}}; // endereços antigos continuam funcionando
let page='dashboard',month=new Date(),selDay=iso(new Date());
let navStack=[],navBack=false,bkDone=false;
function bkInit(){bkDone=true;document.querySelectorAll('.page > .head').forEach(h=>{const f=h.firstElementChild;if(!f||h.querySelector('.bk'))return;const w=document.createElement('div');w.className='hl';const b=document.createElement('button');b.type='button';b.className='bk';b.dataset.act='goBack';b.setAttribute('aria-label','Voltar');b.innerHTML='<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M15 5l-7 7 7 7"/></svg>';h.insertBefore(w,f);w.appendChild(b);w.appendChild(f)})}
function bkSync(){if(!bkDone)bkInit();document.querySelectorAll('.bk').forEach(b=>{b.hidden=MAIN.includes(page)})}
function go(p){
  const al=MONEY_ALIAS[p];if(al){finView=al.tab;finSt=al.st||'all';finType=al.type||'all';p='money'}
  if(page&&page!==p&&!navBack){navStack.push(page);if(navStack.length>25)navStack.shift()}navBack=false;
  page=p;pushRecent(p);$$('.page').forEach(e=>e.classList.toggle('on',e.id==='page-'+p));
  $$('#nav button').forEach(b=>{const on=b.dataset.page?b.dataset.page===p:!MAIN.includes(p);b.classList.toggle('on',on);on?b.setAttribute('aria-current','page'):b.removeAttribute('aria-current')});
  render();bkSync();scrollTo(0,0);
}
const PALETTES={
  marfim:{n:'Marfim',d:'Cinza fosco com laranja',bg:'#e8eaee',card:'#ffffff',s2:'#f2f3f6',s3:'#dcdfe6',ink:'#1c1f26',muted:'#667085',line:'#d2d6df',p:'#f08300',p2:'#ffb04d',a:'#ff5a1f',focus:'rgba(240,131,0,.26)'},
  cobalto:{n:'Cobalto',d:'Azul profundo e sóbrio',bg:'#e6eaf4',card:'#ffffff',s2:'#f1f3fa',s3:'#d9deee',ink:'#151a30',muted:'#5a6385',line:'#ccd3e8',p:'#3358f0',p2:'#8fa5ff',a:'#ff8a00',focus:'rgba(51,88,240,.26)'},
  salvia:{n:'Sálvia',d:'Verde-sálvia com dourado suave',bg:'#e5eadf',card:'#ffffff',s2:'#f1f4ec',s3:'#d3dccd',ink:'#18271d',muted:'#566a5b',line:'#c6d2c0',p:'#3a8559',p2:'#9bc9a8',a:'#c9a227',focus:'rgba(58,133,89,.26)'},
  preto:{n:'Preto',d:'Preto profundo com dourado',dark:1,onp:1,bg:'#000000',card:'#101012',s2:'#18181b',s3:'#26262b',ink:'#f5f5f5',muted:'#a1a1aa',line:'#2e2e33',p:'#f5b301',p2:'#ffd666',a:'#ff7a59',focus:'rgba(245,179,1,.28)'}
};
const LIGHT_VARS={bg:'--bg',card:'--card',s2:'--s2',s3:'--s3',ink:'--ink',muted:'--muted',line:'--line'};
function gdNorm(g){if(!g||typeof g!=='object')return null;const ok=c=>/^#[0-9a-f]{6}$/i.test(c);return{on:!!g.on,c1:ok(g.c1)?g.c1:'#7c3aed',c2:ok(g.c2)?g.c2:'#06b6d4',c3:ok(g.c3)?g.c3:'',ang:Number.isFinite(+g.ang)?((+g.ang%360)+360)%360:135}}
const gdCss=g=>`linear-gradient(${g.ang}deg,${[g.c1,g.c2,g.c3].filter(Boolean).join(',')})`;
function gdText(g){const L=c=>{const n=parseInt(c.slice(1),16),f=v=>{v/=255;return v<=.03928?v/12.92:Math.pow((v+.055)/1.055,2.4)};return .2126*f(n>>16)+.7152*f(n>>8&255)+.0722*f(n&255)},a=[g.c1,g.c2,g.c3].filter(Boolean).map(L),m=a.reduce((x,y)=>x+y,0)/a.length;return m>.4?'#111':'#fff'}
function applyTheme(){
  const st=db.settings,key=PALETTES[st.theme?.preset]?st.theme.preset:'marfim',t=PALETTES[key],dark=!!st.darkMode||!!t.dark,r=document.documentElement;r.dataset.onp=t.onp?'dark':'';
  r.dataset.theme=dark?'dark':'light';const tb=document.getElementById('themeBtn');if(tb){tb.setAttribute('aria-pressed',dark);tb.title=dark?'Mudar para claro':'Mudar para escuro'}r.dataset.glass=st.liquidGlass===true?'on':'off';
  Object.entries(LIGHT_VARS).forEach(([k,v])=>dark&&!t.dark?r.style.removeProperty(v):r.style.setProperty(v,t[k])); // no modo escuro, só o destaque muda
  [['--p',t.p],['--p2',t.p2],['--a',t.a],['--focus',t.focus]].forEach(([v,c])=>r.style.setProperty(v,c));
  const g=gdNorm(st.theme?.grad);if(g&&g.on){r.dataset.grad='on';r.style.setProperty('--g-img',gdCss(g));r.style.setProperty('--g2',g.c2);r.style.setProperty('--p',g.c2);r.style.setProperty('--p2',g.c1);{const n=parseInt(g.c2.slice(1),16);r.style.setProperty('--focus',`rgba(${n>>16},${n>>8&255},${n&255},.28)`)}r.style.setProperty('--gon',gdText(g))}else{r.removeAttribute('data-grad');['--g-img','--g2','--gon'].forEach(v=>r.style.removeProperty(v))}
}
function rPal(){
  const cur=PALETTES[db.settings.theme?.preset]?db.settings.theme.preset:'marfim';
  $('#sGlass').value=db.settings.liquidGlass===false?'0':'1';
  $('#palGrid').innerHTML=Object.entries(PALETTES).map(([k,t])=>`<button type="button" class="dot" data-act="setPal" data-k="${k}" title="${t.n}" aria-label="${t.n}" aria-pressed="${k===cur}" style="background:linear-gradient(135deg,${t.bg} 48%,${t.p} 52%)"></button>`).join('');
  rGrad();
}

/* ========== RENDER ========== */
function render(){
  $('#studioName').textContent=db.settings.studioName;
  ({dashboard:rDash,students:rStudents,agenda:rAgenda,money:rMoney,settings:rSettings,makeups:rMakeups,waitlist:rWait,birthdays:rBdays,hours:rHours,occupancy:rOcc,teachers:rTeachers,alerts:rAlerts,evolution:rEvo,reports:rReports,equipment:rEquip,guide:rGuide,tutor:rTutor,learn:rLearn,search:rSearch})[page]();badge();segRefresh();
}
function nextClass(){
  const t=iso(new Date()),d=new Date(),hm=pad(d.getHours())+':'+pad(d.getMinutes());
  return db.classes.filter(c=>c.date===t&&!['Cancelada','Realizada','Falta'].includes(c.status)&&c.time>=hm).sort(sortCls)[0]||null;
}
const stg=(l,v,pc,sub,cls='')=>`<div style="padding:8px 0"><div style="display:flex;justify-content:space-between"><b>${l}</b><b>${v}</b></div><div class="bar ${cls}" style="margin:4px 0"><i style="width:${Math.max(0,Math.min(100,pc))}%"></i></div><div class="sub">${sub}</div></div>`;
const DASH_SECS=[['alerts','Alertas'],['equip','Aparelhos de hoje'],['week','Semana'],['teach','Professores hoje'],['fin','Cobranças'],['pipe','Pipeline do Studio'],['rev','Faturamento vs Recebimento'],['mgmt','Visão gerencial'],['bday','Aniversariantes do mês']];
const dashHidden=()=>Array.isArray(db.settings.dashHidden)?db.settings.dashHidden:[];
const dashOrder=()=>{const ids=DASH_SECS.map(x=>x[0]),sv=Array.isArray(db.settings.dashOrder)?db.settings.dashOrder.filter((x,i,a)=>ids.includes(x)&&a.indexOf(x)===i):[];return[...sv,...ids.filter(x=>!sv.includes(x))]};
function dashApplyOrder(){const box=$('#dashSecs');if(!box)return;const want=dashOrder(),cur=[...box.children].map(e=>e.dataset.sec);if(want.join()===cur.join())return;want.forEach(id=>{const el=box.querySelector(`[data-sec="${id}"]`);if(el)box.appendChild(el)})}
function dashNext(){
  const t=iso(new Date()),today=db.classes.filter(c=>c.date===t&&c.status!=='Cancelada'),nx=nextClass();
  const pend=today.filter(c=>c.status==='Agendada'||c.status==='Confirmada').length;
  $('#kTodayF').textContent=nx?`Próxima ${nx.time} · ${String(nx.studentName).split(' ')[0]}`:today.length?(pend?`${pend} sem registro`:'Todas concluídas'):'Sem aulas hoje';
}
function cu(id,to,fmt){const el=$('#'+id),f=fmt||(v=>String(Math.round(v))),from=el._v||0;el._v=to;cancelAnimationFrame(el._r);
  if(from===to||matchMedia('(prefers-reduced-motion:reduce)').matches){el.textContent=f(to);return}
  const t0=performance.now(),step=n=>{const p=Math.min(1,(n-t0)/600);el.textContent=f(from+(to-from)*(1-Math.pow(1-p,3)));if(p<1)el._r=requestAnimationFrame(step)};el._r=requestAnimationFrame(step)}
function rDash(){
  const t=iso(new Date()),k=t.slice(0,7),h=new Date().getHours(),sum=(a,f)=>a.reduce((q,x)=>q+f(x),0);
  $('#greet').textContent=(h<12?'Bom dia':h<18?'Boa tarde':'Boa noite')+', '+db.settings.owner.split(' ')[0]+'!';
  const act=activeStudents(),today=db.classes.filter(c=>c.date===t&&c.status!=='Cancelada').sort(sortCls),o=occStats(),revenue=sum(act,x=>Number(x.monthly||0));
  const received=sum(db.finance.filter(f=>!isExp(f)&&f.status==='Pago'&&String(f.paidAt||f.dueDate).startsWith(k)),f=>Number(f.value||0)),pct=revenue?Math.min(100,received/revenue*100):0;
  const al=studioAlerts().filter(x=>!x.dismissed&&x.type!=='paid');
  // 4 indicadores
  $('#kStudents').textContent=act.length;$('#kStudentsF').textContent=money(revenue)+' previstos';
  $('#kReceived').textContent=money(received);$('#kReceivedF').textContent=revenue?`${Math.round(pct)}% de ${money(revenue)}`:'sem previsão';$('#mReceived').style.width=Math.max(4,pct)+'%';
  $('#kToday').textContent=today.length;dashNext();
  $('#kAlerts').textContent=al.length;$('#kAlerts').className=al.length?'neg':'';$('#kAlertsF').textContent=al[0]?al[0].title:'Tudo em ordem ✓';
  // Hoje (até 5)
  const nowM0=new Date().getHours()*60+new Date().getMinutes(),isLive=c=>{const s=tmin(c.time);return s!=null&&s<=nowM0&&nowM0<s+cDur(c)&&!['Realizada','Falta'].includes(c.status)};
  const TF={all:()=>true,rest:c=>!['Realizada','Falta'].includes(c.status),done:c=>c.status==='Realizada',fal:c=>c.status==='Falta'},tf=TF[rDash.tf]?rDash.tf:'all',tl=today.filter(TF[tf]);
  $('#todayF').innerHTML=[['all','Todas'],['rest','Restantes'],['done','Realizadas'],['fal','Faltas']].map(([k,l])=>[k,l,today.filter(TF[k]).length]).filter(x=>x[0]==='all'||x[2]||tf===x[0]).map(([k,l,n])=>`<button type="button" data-act="todayF" data-f="${k}" class="${tf===k?'on':''}" aria-pressed="${tf===k}">${l} <small>${n}</small></button>`).join('');
  $('#todayList').innerHTML=tl.length?tl.slice(0,8).map(c=>rowStu(c.studentName,`${esc(c.time)} · ${esc(c.teacher||'—')}${eqName(c)?' · '+esc(eqName(c)):''}`,(isLive(c)?'<span class="badge info">agora</span> ':'')+`<span class="badge ${STATUS_CLS[c.status]||''}">${esc(c.status)}</span>`)).join('')+(tl.length>8?`<div class="sub" style="padding-top:6px">+ ${tl.length-8} aula(s) na agenda</div>`:''):`<div class="empty">${today.length?'Nenhuma aula neste filtro.':'Nenhuma aula hoje.'}</div>`;
  // seções recolhíveis (o resumo aparece mesmo fechado)
  $('#sAlerts').textContent=al.length?`${al.length} pendência(s)`:'Tudo em ordem ✓';
  $('#dashAlerts').innerHTML=al.length?al.slice(0,4).map(x=>`<div class="item"><div><span class="badge ${AL_CLS[x.type]||''}">${esc(x.title)}</span><div class="sub" style="margin-top:3px">${esc(x.text)}</div></div><button class="btn sm" data-act="alGo" data-p="${x.page}">Abrir</button></div>`).join('')+(al.length>4?`<div class="sub" style="padding-top:8px">+ ${al.length-4} outros alertas</div>`:''):'<div class="empty">Tudo em ordem ✓</div>';
  $('#sEquip').textContent=today.length?`${today.filter(c=>c.equipmentId).length}/${today.length} com aparelho`:'sem aulas';
  const pend=Math.max(0,revenue-received);
  $('#sRev').textContent=revenue?Math.round(pct)+'% recebido':'sem previsão';
  $('#dashRev').innerHTML=stg('Previsto',money(revenue),revenue?100:0,`${act.length} alunos ativos`)+stg('Recebido',money(received),pct,revenue?Math.round(pct)+'% do previsto':'sem previsão','ok')+stg('A receber',money(pend),revenue?pend/revenue*100:0,'diferença até o previsto','warn');
  $('#sMgmt').textContent=Math.round(o.pct)+'% de ocupação';
  $('#dashMgmt').innerHTML=[['OCUPAÇÃO',Math.round(o.pct)+'%'],['VAGAS LIVRES',o.free],['PLANOS EM USO',new Set(act.map(x=>x.plan).filter(Boolean)).size],['AULAS NO MÊS',db.classes.filter(c=>c.date.startsWith(k)&&c.status!=='Cancelada').length]].map(([l,v],i)=>i<2?`<button type="button" data-act="goPage" data-p="occupancy" aria-label="${l}: ${v}. Abrir ocupação"><small>${l}</small><b>${v}</b></button>`:`<div><small>${l}</small><b>${v}</b></div>`).join('');
  const m=new Date().getMonth()+1,b=db.students.filter(x=>x.birth&&+x.birth.slice(5,7)===m).sort((a,c)=>a.birth.slice(8)-c.birth.slice(8));
  $('#sBday').textContent=b.length?`${b.length} no mês`:'nenhum';
  $('#bdayList').innerHTML=b.length?b.map(x=>rowStu(x.name,`${ico('cake')} ${x.birth.slice(8)}/${x.birth.slice(5,7)}`,'')).join(''):'<div class="empty">Sem aniversariantes neste mês.</div>';
  const hid=dashHidden();dashApplyOrder();$$('#dashSecs [data-sec]').forEach(d=>{d.hidden=hid.includes(d.dataset.sec)});
  $('#sPipe').textContent=`${today.filter(c=>c.status==='Realizada').length}/${today.length} realizadas`;
  cu('kStudents',act.length);cu('kReceived',received,money);cu('kToday',today.length);cu('kAlerts',al.length);$('#kAlerts').closest('.kpi').dataset.s=al.length?'bad':'ok';
  rPipe();rDashEq();rDashX(t,today);rDashLive();
}
function cDur(c){return Math.max(1,Number(c.duration||db.settings.duration)||60)}
function relIn(m){return m<=0?'agora':m<60?`em ${m} min`:m<1440?`em ${Math.floor(m/60)}h${m%60?pad(m%60):''}`:`em ${Math.round(m/1440)} d`}
function nowActs(c){const s=studentById(c.studentId);
  return (c.status==='Realizada'?'<span class="badge ok">Realizada</span>':`<button class="btn sm" data-act="nowSet" data-id="${c.id}" data-s="Realizada">${ico('check')} Realizada</button>`)+`<button class="btn sm bad" data-act="nowSet" data-id="${c.id}" data-s="Falta">${ico('x')} Faltou</button>`+(s&&s.whatsapp?`<button class="btn sm wa" data-act="nowWa" data-id="${c.id}">WhatsApp</button>`:'');
}
function clockTick(){
  const d=new Date(),h=d.getHours(),el=$('#clock'),ge=$('#greet');
  if(el)el.textContent=d.toLocaleDateString('pt-BR',{weekday:'long',day:'2-digit',month:'long'})+' • '+d.toLocaleTimeString('pt-BR',{hour:'2-digit',minute:'2-digit',second:'2-digit'});
  const g=(h<12?'Bom dia':h<18?'Boa tarde':'Boa noite')+', '+String(db.settings.owner||'').split(' ')[0]+'!';
  if(ge&&ge.textContent!==g)ge.textContent=g;
}
function rDayStrip(){
  const el=$('#dayStrip');if(!el)return;
  const now=new Date(),t=iso(now),nm=now.getHours()*60+now.getMinutes(),wd=String(now.getDay()),dur=Math.max(1,Number(db.settings.duration)||60);
  const sl=db.hours.filter(h=>hourDays(h).includes(wd)).map(h=>tmin(h)).filter(x=>x!=null).sort((a,b)=>a-b),cs=db.classes.filter(c=>c.date===t&&c.status!=='Cancelada'),fm=m=>`${pad(Math.floor(m/60)%24)}:${pad(m%60)}`;
  const done=cs.filter(c=>c.status==='Realizada').length,fal=cs.filter(c=>c.status==='Falta').length,live=cs.filter(c=>c.status!=='Falta'&&tmin(c.time)!=null&&tmin(c.time)<=nm&&nm<tmin(c.time)+cDur(c)).length,rest=cs.filter(c=>!['Realizada','Falta'].includes(c.status)&&tmin(c.time)>nm).length;
  let st='Sem horários hoje',pc=0,on='';
  if(sl.length){const a=sl[0],b=sl[sl.length-1]+dur;pc=Math.max(0,Math.min(100,(nm-a)/(b-a)*100));on=nm>=a&&nm<b?' on':'';st=nm<a?`Abre às ${fm(a)} · ${relIn(a-nm)}`:nm<b?`Aberto · fecha às ${fm(b)}`:'Encerrado por hoje'}
  el.innerHTML=`<div class="ds-top"><b>${esc(now.toLocaleDateString('pt-BR',{weekday:'long',day:'numeric',month:'long'}))}</b><span class="ds-chip${on}"><i></i>${st}</span></div>`
   +(sl.length?`<div class="ds-bar" role="img" aria-label="Expediente: ${Math.round(pc)}% concluído"><i style="width:${pc}%"></i><em style="left:${pc}%"></em></div><div class="ds-row"><span>${fm(sl[0])}</span><span>${fm(sl[sl.length-1]+dur)}</span></div>`:'')
   +`<div class="ds-n"><span><b>${live}</b> agora</span><span><b>${rest}</b> restantes</span><span><b>${done}</b> realizadas</span>${fal?`<span><b>${fal}</b> falta(s)</span>`:''}</div>`;
}
document.addEventListener('click',e=>{if(navigator.vibrate&&e.target.closest('nav.tabbar button,.btn,.tile'))navigator.vibrate(6)},{passive:true});
function rDashLive(){
  clockTick();rDayStrip();
  const now=new Date(),t=iso(now),nm=now.getHours()*60+now.getMinutes(),nk=`${t}T${pad(now.getHours())}:${pad(now.getMinutes())}`;
  const live=db.classes.filter(c=>c.date===t&&c.status!=='Cancelada'&&c.status!=='Falta'&&tmin(c.time)!=null&&tmin(c.time)<=nm&&nm<tmin(c.time)+cDur(c)).sort(sortCls);
  const up=db.classes.filter(c=>!['Cancelada','Realizada','Falta'].includes(c.status)&&`${c.date}T${c.time||'00:00'}`>nk).sort(sortCls),at=c=>new Date(`${c.date}T${c.time||'00:00'}`),mins=c=>Math.max(0,Math.round((at(c)-now)/6e4));
  $('#nowCard').classList.toggle('on',live.length>0);$('#nowSub').textContent=live.length?`${live.length} em andamento`:'';
  $('#nowList').innerHTML=live.length?live.map(c=>{const s=tmin(c.time),d=cDur(c),e=nm-s,pc=Math.min(100,Math.round(e/d*100)),en=s+d,end=`${pad(Math.floor(en/60)%24)}:${pad(en%60)}`;
    return `<div class="nowr"><div class="nowmain">${stuAv(studentById(c.studentId),c.studentName,'sm')}<div class="nowt"><b>${esc(c.studentName)}</b><div class="sub">${esc(c.time)}–${end} · ${esc(c.teacher||'—')} · ${esc(eqName(c)||'sem aparelho')}</div><div class="bar ok"><i style="width:${pc}%"></i></div></div><div class="nowm"><b>${d-e}</b><small>min restantes</small></div></div><div class="nowa">${nowActs(c)}</div></div>`}).join(''):`<div class="empty">Nenhuma aula em andamento.${up[0]?`<br>Próxima às ${esc(up[0].time)}${up[0].date===t?'':' de '+fmtDate(up[0].date).slice(0,5)}, ${relIn(mins(up[0]))}.`:''}</div>`;
  const gp=[];up.forEach(c=>{const k=c.date+'T'+c.time,g=gp[gp.length-1];if(g&&g.k===k)g.l.push(c);else gp.push({k,c,l:[c]})});
  $('#nextList').innerHTML=gp.length?gp.slice(0,rDashLive.n||4).map((g,i)=>{const c=g.c,m=mins(c),dl=c.date===t?'Hoje':c.date===eqAdd(t,1)?'Amanhã':at(c).toLocaleDateString('pt-BR',{weekday:'short',day:'2-digit',month:'2-digit'}).replace('.','');
    return `<div class="slot${i?'':' next'}"><div class="slot-h"><div class="slot-t"><b>${esc(c.time)}</b><small>${dl}</small></div><span class="badge ${m<=30?'warn':'info'}">${relIn(m)}</span><span class="slot-n">${g.l.length} aluno${g.l.length>1?'s':''}</span></div>${g.l.map(x=>`<div class="slot-r">${stuAv(studentById(x.studentId),x.studentName,'sm')}<b>${esc(x.studentName)}</b><span class="sub">${esc(x.teacher||'—')} · ${esc(eqName(x)||'sem aparelho')}</span>${x.status==='Confirmada'?`<span class="badge ok" title="Confirmada">${ico('check')}</span>`:''}</div>`).join('')}</div>`}).join('')+(gp.length>(rDashLive.n||4)?`<button type="button" class="btn sm" data-act="nextMore" style="grid-column:1/-1;justify-self:start">Ver mais horários (${gp.length-(rDashLive.n||4)})</button>`:(rDashLive.n>4?'<button type="button" class="btn sm" data-act="nextLess" style="grid-column:1/-1;justify-self:start">Mostrar menos</button>':'')):'<div class="empty" style="grid-column:1/-1">Nenhuma aula futura agendada.</div>';
}
function rDashX(t,today){
  const done=today.filter(c=>c.status==='Realizada').length,fal=today.filter(c=>c.status==='Falta').length,rest=today.filter(c=>!['Realizada','Falta'].includes(c.status)).length;
  $('#todaySub').textContent=today.length?`${done} realizada(s) · ${rest} restante(s)${fal?` · ${fal} falta(s)`:''}`:'';
  const days=[...Array(7)].map((_,k)=>{const d=eqAdd(t,k);return{d,k,n:db.classes.filter(c=>c.date===d&&c.status!=='Cancelada').length}}),mx=Math.max(1,...days.map(x=>x.n));
  $('#sWeek').textContent=`${days.reduce((q,x)=>q+x.n,0)} aulas em 7 dias`;
  $('#dashWeek').innerHTML=`<div class="wk">${days.map(x=>`<div${x.k?'':' class="td"'}><b>${x.n}</b><i style="height:${Math.max(4,Math.round(x.n/mx*54))}px"></i><small>${x.k?new Date(x.d+'T12:00').toLocaleDateString('pt-BR',{weekday:'short'}).replace('.',''):'hoje'}</small></div>`).join('')}</div>`;
  const g={};today.forEach(c=>(g[c.teacher||'Sem professor']=g[c.teacher||'Sem professor']||[]).push(c));
  const nowM=new Date().getHours()*60+new Date().getMinutes(),tn=Object.keys(g).sort();
  $('#sTeach').textContent=tn.length?`${tn.length} em aula`:'sem aulas';
  $('#dashTeach').innerHTML=tn.length?tn.map(n=>{const l=g[n],dn=l.filter(c=>c.status==='Realizada').length,nx=l.find(c=>!['Realizada','Falta'].includes(c.status)&&(tmin(c.time)||0)+cDur(c)>nowM);
    return rowStu(n,`${l.length} aula(s) · ${dn} realizada(s)`,nx?`<span class="badge info">${tmin(nx.time)<=nowM?'em aula':'próx. '+esc(nx.time)}</span>`:'<span class="badge ok">concluído</span>')}).join(''):'<div class="empty">Nenhum professor em aula hoje.</div>';
  const late=f=>typeof lateOf==='function'?lateOf(f):String(f.dueDate)<t,rec=db.finance.filter(f=>!isExp(f)&&f.status!=='Pago'),lt=rec.filter(late),sn=rec.filter(f=>!late(f)&&f.dueDate>=t&&f.dueDate<=eqAdd(t,7)),sm=a=>a.reduce((q,x)=>q+Number(x.value||0),0);
  $('#sFin').textContent=lt.length?`${lt.length} vencida(s)`:'em dia';
  $('#dashFin').innerHTML=`<div class="mini">${[['VENCIDAS',`${lt.length} · ${money(sm(lt))}`],['VENCEM EM 7 DIAS',`${sn.length} · ${money(sm(sn))}`],['EM ABERTO',`${rec.length} · ${money(sm(rec))}`]].map(([l,v])=>`<div><small>${l}</small><b>${v}</b></div>`).join('')}</div><div class="row-acts" style="margin-top:6px"><button class="btn sm" data-act="goPage" data-p="money">Abrir dinheiro</button></div>`;
}
function dashCustomList(){
  const hid=dashHidden(),ord=dashOrder(),lab=Object.fromEntries(DASH_SECS),box=$('#dcList');if(!box)return;
  box.innerHTML=ord.map((id,i)=>`<div class="dcr${hid.includes(id)?' off':''}"><label><input type="checkbox" data-dc="${id}" ${hid.includes(id)?'':'checked'} style="width:auto"><span>${esc(lab[id])}</span></label><div class="dcm"><button type="button" class="btn sm" data-act="dashMove" data-id="${id}" data-dir="-1" aria-label="Subir ${esc(lab[id])}"${i===0?' disabled':''}>↑</button><button type="button" class="btn sm" data-act="dashMove" data-id="${id}" data-dir="1" aria-label="Descer ${esc(lab[id])}"${i===ord.length-1?' disabled':''}>↓</button></div></div>`).join('');
}
function dashCustomModal(){
  openModal(`<h2>Personalizar painel</h2><div class="sub" style="margin-bottom:8px">Marque o que aparece e use ↑ ↓ para mudar a ordem. Os indicadores e "Hoje" ficam sempre no topo.</div><div id="dcList"></div><div class="foot"><button class="btn" data-act="dashReset">Restaurar padrão</button><button class="btn primary" data-act="closeModal">Pronto</button></div>`);
  dashCustomList();
}
function dashMove(id,dir){
  const o=dashOrder(),i=o.indexOf(id),j=i+dir;if(i<0||j<0||j>=o.length)return;
  [o[i],o[j]]=[o[j],o[i]];db.settings.dashOrder=o;if(!save())return;
  dashApplyOrder();dashCustomList();
  const sel=`#dcList [data-act="dashMove"][data-id="${id}"]`,b=$(`${sel}[data-dir="${dir}"]`)||$(sel+':not(:disabled)');b&&b.focus();
}
function rStudents(){
  const q=$('#stSearch').value.trim().toLowerCase(),st=$('#stStatus').value;
  const list=db.students.filter(s=>(!st||(s.status||'Ativo')===st)&&(!q||s.name.toLowerCase().includes(q)||String(s.whatsapp||'').includes(q))).sort((a,b)=>a.name.localeCompare(b.name,'pt-BR'));
  $('#stCount').textContent=`${activeStudents().length} ativos de ${db.students.length}`;
  const ix=idxBy();
  $('#stList').innerHTML=list.length?list.map(s=>sCard(s,ix)).join(''):'<div class="card empty">Nenhum aluno encontrado.</div>';
}
function rAgenda(){
  const y=month.getFullYear(),mo=month.getMonth(),first=new Date(y,mo,1).getDay(),days=new Date(y,mo+1,0).getDate(),t=iso(new Date());
  $('#calTitle').textContent=month.toLocaleDateString('pt-BR',{month:'long',year:'numeric'});
  let h=Object.values(DAY).map(d=>`<div class="dw">${d}</div>`).join('')+'<button class="pad" tabindex="-1" aria-hidden="true"></button>'.repeat(first);
  for(let d=1;d<=days;d++){
    const ds=`${y}-${pad(mo+1)}-${pad(d)}`,n=db.classes.filter(c=>c.date===ds&&c.status!=='Cancelada').length;
    h+=`<button data-act="selDay" data-date="${ds}" class="${ds===t?'today ':''}${ds===selDay?'sel':''}">${d}${n?`<small>${n}</small>`:''}</button>`;
  }
  $('#cal').innerHTML=h;
  const list=db.classes.filter(c=>c.date===selDay).sort(sortCls);
  $('#clsTitle').textContent='Aulas de '+fmtDate(selDay);$('#clsCount').textContent=list.length+' aulas';
  $('#clsList').innerHTML=list.length?list.map(c=>{
    const s=studentById(c.studentId),eq=db.equipment.find(e=>e.id===c.equipmentId)?.name;
    return scard({sid:c.studentId,key:'cl:'+c.id,name:c.studentName,badge:c.status,cls:STATUS_CLS[c.status],sub:`${fmtDate(c.date)} · ${esc(c.time)}${eq?' · '+esc(eq):''}`,
      mini:[['HORÁRIO',esc(c.time)],['PROFESSOR(A)',esc(c.teacher||'—')],['APARELHO',esc(eq||'—')]],det:[...stuLine(s),['Observações',esc(c.notes||'—')]],
      acts:`<select data-act="setStatus" data-id="${c.id}" style="padding:6px;width:auto">${STATUS.map(x=>`<option${x===c.status?' selected':''}>${x}</option>`).join('')}</select><button class="btn sm" data-act="editClass" data-id="${c.id}">Editar</button><button class="btn sm bad" data-act="delClass" data-id="${c.id}">Excluir</button>`});
  }).join(''):'<div class="card empty">Nenhuma aula neste dia.</div>';
}

/* ========== MODAL ========== */
let editing=null,lastFocus=null,pendingWait=null;
function openModal(html){lastFocus=document.activeElement;$('#sheet').innerHTML='<div class="mxw"><button type="button" class="mx" data-act="closeModal" aria-label="Fechar"><svg viewBox="0 0 24 24" aria-hidden="true"><path d="M6 6l12 12M18 6L6 18"/></svg></button></div>'+html;
  $$('#sheet .foot button[data-act="closeModal"]').forEach(b=>{if(b.textContent.trim()==='Fechar')b.remove()});$$('#sheet .foot').forEach(f=>{if(!f.children.length)f.remove()});$('#modal').hidden=false;document.body.style.overflow='hidden';if($('#cEquip'))fillEq(true);segUp($('#sheet'));$('#sheet input,#sheet select')?.focus()}
function closeModal(){pendingWait=null;$('#modal').hidden=true;$('#sheet').innerHTML='';document.body.style.overflow='';editing=null;lastFocus?.focus?.()}
const opts=(arr,sel)=>arr.map(v=>`<option${v===sel?' selected':''}>${esc(v)}</option>`).join('');

function studentModal(id,pre){
  const s=id?studentById(id):(pre||null);editing=id||null;
  phDraft=undefined;phTok++;avSel={cfg:s?.avatar||null,use:!!(s?.avUse&&s?.avatar)};avEd=null;
  openModal(`<h2>${s?'Editar aluno':'Novo aluno'}</h2><div class="form">
    <div class="full avp"><div id="fPhotoPrev"></div><div class="btns"><button type="button" class="btn sm" data-act="avOpen">Criar avatar</button><button type="button" class="btn sm bad" data-act="phDel" id="fPhotoDel" hidden>Remover</button></div><div class="avp-h" id="fPhotoMsg">Crie um avatar para identificar o aluno.</div></div>
    <div class="field full"><label for="fName">Nome completo *</label><input id="fName" value="${esc(s?.name)}"></div>
    <div class="field"><label for="fWhats">WhatsApp</label><input id="fWhats" type="tel" inputmode="tel" value="${esc(s?.whatsapp)}"></div>
    <div class="field"><label for="fBirth">Nascimento</label><input id="fBirth" type="date" value="${esc(s?.birth)}"></div>
    <div class="field"><label for="fStart">Início</label><input id="fStart" type="date" value="${esc(s?.startDate)}"></div>
    <div class="field"><label for="fPlan">Plano *</label><select id="fPlan"><option value="">Selecione</option>${db.plans.map(p=>`<option value="${esc(p.name)}"${p.name===s?.plan?' selected':''}>${esc(p.name)} — ${money(p.price)}</option>`).join('')}</select></div>
    <div class="field"><label for="fDue">Vencimento (dia)</label><input id="fDue" type="number" min="1" max="31" value="${esc(s?.due??10)}"></div>
    <div class="field"><label for="fTeacher">Professor(a)</label><select id="fTeacher"><option value="">—</option>${opts(db.teachers,s?.teacher)}</select></div>
    <div class="field"><label for="fTime">Horário</label><select id="fTime"><option value="">—</option>${opts(db.hours,s?.time)}</select></div>
    <div class="field"><label for="fStatus">Status</label><select id="fStatus">${opts(['Ativo','Inativo','Trancado'],s?.status||'Ativo')}</select></div>${exitFields(s)}
    <div class="field full"><label>Dias da semana *</label><div class="days">${[1,2,3,4,5,6,0].map(d=>`<label><input type="checkbox" class="fDay" value="${d}"${normDays(s?.days).includes(String(d))?' checked':''}>${DAY[d]}<small></small></label>`).join('')}</div><div class="dsum" id="fDaySum"></div><div class="dpre"><button type="button" data-act="dayPre" data-d="1,3,5">Seg · Qua · Sex</button><button type="button" data-act="dayPre" data-d="2,4">Ter · Qui</button><button type="button" data-act="dayPre" data-d="1,2,3,4,5">Dias úteis</button><button type="button" data-act="dayPre" data-d="">Limpar</button></div></div>
    ${goalPicker(s)}
    ${goalSec(s)}
    <div class="field full"><label for="fDiag">Diagnóstico clínico / CID (se houver)</label><input id="fDiag" value="${esc(s?.clinical?.diagnosis)}"></div>
    <div class="field"><label for="fPain">Dor atual, EVA (0–10)</label><input id="fPain" type="number" min="0" max="10" step="1" inputmode="numeric" value="${esc(s?.clinical?.painScore)}"></div>
    <div class="field"><label for="fMed">Liberação médica</label><select id="fMed">${[['','Não informada'],['Não necessária','Não necessária'],['Pendente','Pendente'],['Liberado','Liberado']].map(([k,l])=>`<option value="${k}"${k===(s?.medClear||'')?' selected':''}>${l}</option>`).join('')}</select></div>
    <div class="field full"><label for="fGoal">Objetivo (detalhes)</label><input id="fGoal" value="${esc(s?.goal)}"></div>
    <div class="field full"><label for="fComplaint">Queixa principal</label><textarea id="fComplaint" rows="2">${esc(s?.complaint||s?.clinical?.complaint)}</textarea></div>
    <div class="field"><label for="fMob">Mobilidade</label><select id="fMob">${MOBS.map(([k,l])=>`<option value="${k}"${k===String(s?.mobility||'2')?' selected':''}>${l}</option>`).join('')}</select></div>
    <div class="field"><label for="fLevel">Experiência com Pilates</label><select id="fLevel">${LEVELS.map(([k,l])=>`<option value="${k}"${k===String(s?.level||'1')?' selected':''}>${l}</option>`).join('')}</select></div>
    <div class="field full"><label>Condições de saúde</label><div class="days cg">${CONDS.map(([k,l])=>`<label><input type="checkbox" class="fCond" value="${k}"${(s?.conditions||[]).includes(k)?' checked':''}>${l}</label>`).join('')}</div></div>
    <div class="field full"><label for="fInjury">Lesões e cirurgias</label><textarea id="fInjury" rows="2">${esc(s?.injuries)}</textarea></div>
    <div class="field full"><label for="fNotes">Observações</label><textarea id="fNotes" rows="3">${esc(s?.notes)}</textarea></div>
  </div><div class="foot"><button class="btn" data-act="closeModal">Cancelar</button><button class="btn primary" data-act="saveStudent">Salvar</button></div><div id="avEd" hidden></div>`);
  phPreview();fDaySync();gpRender();exitSync();
  $('#sheet').oninput=e=>{if(e.target.id==='fGoalQ')gpRender()};$('#sheet').onchange=e=>{const t=e.target;if(t.classList.contains('fCond'))gpRender();else if(t.id==='fStatus')exitSync(true)};
}
function saveStudent(){
  const v=i=>String($('#'+i).value||'').trim();
  const name=v('fName');if(!name){$('#fName').focus();return toast('Informe o nome completo do aluno.')}
  const plan=db.plans.find(p=>p.name===v('fPlan'));if(!plan){$('#fPlan').focus();return toast('Selecione um plano.')}
  const days=normDays($$('.fDay:checked').map(x=>x.value));if(!days.length)return toast('Selecione pelo menos um dia da semana.');
  const due=v('fDue')===''?10:Number(v('fDue'));if(!Number.isInteger(due)||due<1||due>31)return toast('O vencimento deve estar entre 1 e 31.');
  const pain=v('fPain');if(pain!==''&&!(Number.isInteger(Number(pain))&&Number(pain)>=0&&Number(pain)<=10))return toast('A dor (EVA) deve ser um inteiro de 0 a 10.');
  const birth=v('fBirth'),start=v('fStart');if(birth&&start&&start<birth)return toast('O início não pode ser anterior ao nascimento.');
  {const tm=v('fTime'),o0=editing?studentById(editing):null,cap0=Math.max(1,Number(db.settings.capacity)||1);
   if(tm&&(v('fStatus')||'Ativo')==='Ativo'){const full=days.filter(d=>!(o0&&(o0.status||'Ativo')==='Ativo'&&o0.time===tm&&normDays(o0.days).includes(d))&&activeStudents().filter(z=>z.id!==editing&&z.time===tm&&normDays(z.days).includes(d)).length>=cap0);
    if(full.length&&!confirm(`Lotado em ${full.map(d=>DAY[d]).join(', ')} às ${tm} (limite ${cap0}). Salvar mesmo assim?`))return}}
  const old=editing?studentById(editing):null;
  const s={...(old||{}),id:old?.id||uid('stu'),name,whatsapp:v('fWhats'),birth,startDate:start,goal:v('fGoal')||gpLabels()||'',goalKey:gpS.p[0]||'',goalKeys1:gpS.p.slice(),goalKeys2:gpS.s.slice(),medClear:v('fMed'),complaint:v('fComplaint'),mobility:v('fMob')||'2',level:v('fLevel')||'1',conditions:$$('.fCond:checked').map(x=>x.value),injuries:v('fInjury'),plan:plan.name,monthly:Number(plan.price)||0,due,
    teacher:v('fTeacher'),time:v('fTime'),days,status:v('fStatus')||'Ativo',...exitVals(v),notes:$('#fNotes').value,
    evolution:old?.evolution||[],clinical:{...(old?.clinical||{}),...(v('fDiag')?{diagnosis:v('fDiag')}:{}),...(pain!==''?{painScore:pain}:{}),...(v('fComplaint')?{complaint:v('fComplaint')}:{}),...(v('fGoal')||gpLabels()?{objective:v('fGoal')||gpLabels()}:{})},createdAt:old?.createdAt||new Date().toISOString(),updatedAt:new Date().toISOString()};
  s.statusLog=[...(old?.statusLog||[])];if(!old||(old.status||'Ativo')!==s.status)s.statusLog.push({date:iso(new Date()),from:old?(old.status||'Ativo'):'',to:s.status,reason:s.exitReason||''});
  if(!old)s.intake={date:iso(new Date()),conditions:[...s.conditions],injuries:s.injuries,complaint:s.complaint,diagnosis:s.clinical.diagnosis||'',pain:s.clinical.painScore??'',mobility:s.mobility,level:s.level,medClear:s.medClear,goal:s.goal};
  if(avSel.cfg){s.avatar=avSel.cfg;s.avUse=!!avSel.use}else{delete s.avatar;delete s.avUse}
  if(phDraft!==undefined){const prev=PHOTOS[s.id];if(phDraft)PHOTOS[s.id]=phDraft;else delete PHOTOS[s.id];if(!savePhotos()){if(prev)PHOTOS[s.id]=prev;else delete PHOTOS[s.id];return}}
  if(old)db.students[db.students.indexOf(old)]=s;else db.students.push(s);
  if(pendingWait){const w=db.waitlist.find(x=>x.id===pendingWait);if(w)w.status='Convertido'}
  db.classes.forEach(c=>{if(c.studentId===s.id)c.studentName=s.name});
  if(!save())return;closeModal();render();toast(old?'Aluno atualizado.':'Aluno cadastrado.');
}
function delStudent(id){
  const s=studentById(id);if(!s||!confirm(`Excluir ${s.name}? As aulas futuras dele também serão removidas.`))return;
  const t=iso(new Date());db.students=db.students.filter(x=>x.id!==id);DOCDB.delStu(id).catch(()=>{});db.classes=db.classes.filter(c=>c.studentId!==id||c.date<t);if(PHOTOS[id]){delete PHOTOS[id];savePhotos()}
  save();render();toast('Aluno excluído.');
}

function classModal(id,date){
  const c=id?classById(id):null;editing=id||null;
  if(!db.students.length)return toast('Cadastre um aluno antes de criar aulas.');
  openModal(`<h2>${c?'Editar aula':'Nova aula'}</h2><div class="form">
    <div class="field full"><label for="cStudent">Aluno *</label><select id="cStudent">${db.students.filter(s=>s.id===c?.studentId||(s.status||'Ativo')==='Ativo').map(s=>`<option value="${s.id}"${s.id===c?.studentId?' selected':''}>${esc(s.name)}</option>`).join('')}</select></div>
    <div class="field"><label for="cDate">Data *</label><input id="cDate" type="date" value="${esc(c?.date||date||selDay)}"></div>
    <div class="field"><label for="cTime">Horário *</label><select id="cTime">${opts(db.hours,c?.time)}</select></div>
    <div class="field"><label for="cTeacher">Professor(a)</label><select id="cTeacher"><option value="">—</option>${opts(db.teachers,c?.teacher)}</select></div>
    <div class="field"><label for="cStatus">Status</label><select id="cStatus">${opts(STATUS,c?.status||'Agendada')}</select></div>
    <div class="field full"><label for="cEquip">Aparelho</label><select id="cEquip"></select></div>
    <div class="field full"><label for="cNotes">Observações</label><input id="cNotes" value="${esc(c?.notes)}"></div>
  </div><div class="foot"><button class="btn" data-act="closeModal">Cancelar</button><button class="btn primary" data-act="saveClass">Salvar</button></div>`);
}
function saveClass(){
  const studentId=$('#cStudent').value,date=$('#cDate').value,time=$('#cTime').value,s=studentById(studentId);
  if(!s||!date||!time)return toast('Informe aluno, data e horário.');
  if(db.classes.some(c=>c.id!==editing&&c.studentId===studentId&&c.date===date&&c.time===time&&c.status!=='Cancelada'))return toast('Este aluno já tem aula nesse horário.');
  const cap=Number(db.settings.capacity)||4;
  if(slotCount(date,time,editing)>=cap&&!confirm(`Horário lotado (${cap} vagas). Agendar mesmo assim?`))return;
  const old=editing?classById(editing):null;
  let eqId=$('#cEquip')?.value||'';const e0=eqId&&db.equipment.find(x=>x.id===eqId);
  if(e0&&!eqAvailable(e0,date,time,editing))return toast('Esse aparelho está ocupado nesse horário.');
  if(!eqId&&$('#cStatus').value!=='Cancelada')eqId=eqPick(studentId,date,time,editing);
  const obj={...(old||{}),id:old?.id||uid('cls'),studentId,studentName:s.name,date,time,teacher:$('#cTeacher').value||s.teacher||'',status:$('#cStatus').value,notes:$('#cNotes').value.trim(),duration:old?.duration||db.settings.duration,equipmentId:eqId,updatedAt:new Date().toISOString()};
  if(old)db.classes[db.classes.indexOf(old)]=obj;else db.classes.push(obj);
  if(!save())return;selDay=date;month=new Date(date+'T12:00');closeModal();render();toast('Aula salva.');
}
function genMonth(){
  const y=month.getFullYear(),m=month.getMonth(),n=new Date(y,m+1,0).getDate(),today=iso(new Date());let created=0;
  activeStudents().forEach(s=>{
    if(!s.time)return;const days=normDays(s.days);
    for(let d=1;d<=n;d++){
      const dt=new Date(y,m,d),ds=iso(dt);
      if(ds<today||(s.startDate&&ds<s.startDate)||!days.includes(String(dt.getDay())))continue;
      if(db.classes.some(c=>c.studentId===s.id&&c.date===ds&&c.time===s.time))continue;
      db.classes.push({id:uid('cls'),date:ds,time:s.time,studentId:s.id,studentName:s.name,teacher:s.teacher||'',status:'Agendada',notes:'Aula recorrente',duration:db.settings.duration,equipmentId:eqPick(s.id,ds,s.time)});created++;
    }
  });
  if(created)save();render();toast(created?`${created} aulas geradas.`:'Nenhuma aula nova para gerar.');
}

/* ========== EVENTOS (delegação única) ========== */
const ACT={
  newStudent:()=>studentModal(),editStudent:e=>studentModal(e.dataset.id),saveStudent,delStudent:e=>delStudent(e.dataset.id),
  newClass:()=>classModal(null,selDay),editClass:e=>classModal(e.dataset.id),saveClass,genMonth,closeModal,
  delClass:e=>{if(confirm('Excluir esta aula?')){db.classes=db.classes.filter(c=>c.id!==e.dataset.id);save();render();toast('Aula excluída.')}},
  selDay:e=>{selDay=e.dataset.date;render()},
  prevMonth:()=>{month=new Date(month.getFullYear(),month.getMonth()-1,1);render()},
  nextMonth:()=>{month=new Date(month.getFullYear(),month.getMonth()+1,1);render()}
};

/* cliques dinâmicos: ondulação + "pop" ao soltar, em todos os botões */
const FX_SEL='.btn,.gpc,.tile,.pill button,.seg button,.dpre button',fxOff=()=>matchMedia('(prefers-reduced-motion:reduce)').matches;
document.addEventListener('pointerdown',e=>{
  if(e.button>0||fxOff())return;const b=e.target.closest(FX_SEL);if(!b||b.disabled)return;
  const r=b.getBoundingClientRect(),d=Math.max(r.width,r.height)*2,i=document.createElement('u');
  i.className='rpl';i.style.cssText=`width:${d}px;height:${d}px;left:${e.clientX-r.left-d/2}px;top:${e.clientY-r.top-d/2}px`;
  b.appendChild(i);setTimeout(()=>i.remove(),520);
},{passive:true});
document.addEventListener('click',e=>{
  if(fxOff())return;const b=e.target.closest(FX_SEL);if(!b||b.disabled)return;
  b.classList.remove('clk');void b.offsetWidth;b.classList.add('clk');setTimeout(()=>b.classList.remove('clk'),400);
},{passive:true});
document.addEventListener('click',e=>{
  const nav=e.target.closest('#nav button');if(nav)return nav.dataset.more?moreMenu():go(nav.dataset.page);
  const el=e.target.closest('[data-act]');if(el&&el.tagName!=='SELECT'&&ACT[el.dataset.act])ACT[el.dataset.act](el);
  if(e.target.id==='modal')closeModal();
});
document.addEventListener('change',e=>{
  if(e.target.dataset.act==='setStatus'){const c=classById(e.target.dataset.id);if(c){c.status=e.target.value;c.updatedAt=new Date().toISOString();save();toast('Status atualizado.')}}
});
document.addEventListener('keydown',e=>{if(e.key==='Escape'&&!$('#modal').hidden)closeModal()});
$('#stSearch').addEventListener('input',rStudents);$('#stStatus').addEventListener('change',rStudents);
$('#sGlass').addEventListener('change',e=>{db.settings.liquidGlass=e.target.value==='1';save();applyTheme();toast(db.settings.liquidGlass?'Liquid Glass ligado.':'Liquid Glass desligado.')});
$('#themeBtn').onclick=()=>{const r=document.documentElement;r.classList.add('tt');db.settings.darkMode=!db.settings.darkMode;save();applyTheme();setTimeout(()=>r.classList.remove('tt'),450)};
(function(){let p,cur='';const fine=()=>matchMedia('(hover:hover) and (pointer:fine)').matches,glassOn=()=>db.settings.liquidGlass===true;
function close(){if(p)p.hidden=true;cur=''}
function view(){const v=uiGet();
 if(cur==='s')p.innerHTML=`<div class="ur"><b>Escala da interface</b><output id="uiV">${v.s}%</output></div><input type="range" id="uiS" min="60" max="120" step="5" value="${v.s}" aria-label="Escala"><div class="ub"><button type="button" class="btn sm" data-r="s">Padrão (100%)</button></div>${fine()?'':'<div class="sub">No celular a escala é aplicada ao soltar o controle.</div>'}`;
 else p.innerHTML=`<div class="ur"><b>Opacidade do vidro</b><output id="uiV">${v.o}%</output></div><input type="range" id="uiO" min="10" max="100" step="5" value="${v.o}" aria-label="Opacidade do vidro"${glassOn()?'':' disabled'}><div class="ub"><label><input type="checkbox" id="uiG"${glassOn()?' checked':''}> Liquid Glass</label><button type="button" class="btn sm" data-r="o">Padrão (50%)</button></div>${glassOn()?'':'<div class="sub">Ative o Liquid Glass para ajustar a opacidade.</div>'}`}
function open(k){if(cur===k)return close();cur=k;if(!p){p=document.createElement('div');p.id='uiPanel';p.setAttribute('role','dialog');document.body.appendChild(p);
  p.addEventListener('input',e=>{const t=e.target,v=uiGet();if(t.id==='uiS'){v.s=+t.value;uiSet(v);$('#uiV').textContent=v.s+'%';if(fine())uiApply()}if(t.id==='uiO'){v.o=+t.value;uiSet(v);$('#uiV').textContent=v.o+'%';uiApply()}});
  p.addEventListener('change',e=>{const t=e.target;if(t.id==='uiS')uiApply();if(t.id==='uiG'){db.settings.liquidGlass=t.checked;save();applyTheme();view()}});
  p.addEventListener('click',e=>{const b=e.target.closest('[data-r]');if(!b)return;const v=uiGet();if(b.dataset.r==='s')v.s=100;else v.o=50;uiSet(v);uiApply();view()})}
 view();p.hidden=false}
$('#uiBtnS').onclick=()=>open('s');$('#uiBtnO').onclick=()=>open('o');
document.addEventListener('click',e=>{if(p&&!p.hidden&&!p.contains(e.target)&&!e.target.closest('#uiBtnS,#uiBtnO'))close()});
document.addEventListener('keydown',e=>{if(e.key==='Escape')close()})})();
$('#logoutBtn').onclick=()=>{Auth.logout();Promise.resolve(window.FB&&window.FB.signOut()).catch(()=>{}).finally(()=>location.reload())};


/* ========== FINANCEIRO / COBRANÇAS ========== */
let finMonth=new Date(),finType='all',finSt='all';
const pillCounts=(sel,c)=>$$(sel+' button').forEach(b=>{b.dataset.l=b.dataset.l||b.textContent.trim();const n=c[b.dataset.f];b.textContent=n===undefined?b.dataset.l:`${b.dataset.l} · ${n}`});
const ym=d=>`${d.getFullYear()}-${pad(d.getMonth()+1)}`;
const monthName=d=>d.toLocaleDateString('pt-BR',{month:'long',year:'numeric'});
const isExp=f=>f.type==='Despesa';
const finRows=()=>db.finance.filter(f=>String(f.dueDate).startsWith(ym(finMonth))).sort((a,b)=>String(a.dueDate).localeCompare(String(b.dueDate)));
const lateOf=f=>f.status!=='Pago'&&f.dueDate<iso(new Date());
function badge(){const n=db.finance.filter(f=>!isExp(f)&&f.status!=='Pago'&&lateOf(f)).length,b=$('#billBadge');b.textContent=n;b.hidden=!n;
  const a=studioAlerts().filter(x=>!x.dismissed&&x.type!=='paid').length;const mb=$('#moreBadge');mb.textContent=a;mb.hidden=!a}
function rMoney(){
  const r=finRows(),rec=r.filter(f=>!isExp(f)),exp=r.filter(isExp),sum=a=>a.reduce((t,f)=>t+Number(f.value||0),0);
  const inn=sum(rec.filter(f=>f.status==='Pago')),out=sum(exp.filter(f=>f.status==='Pago'));
  $('#finTitle').textContent=monthName(finMonth);$('#finEntries').hidden=finView!=='entries';$('#finStudents').hidden=finView!=='students';$('#finGastos').hidden=finView!=='gastos';$('#genBillsBtn').hidden=finView==='gastos';$$('#finView button').forEach(b=>b.classList.toggle('on',b.dataset.v===finView));$$('#finSt button').forEach(b=>b.classList.toggle('on',b.dataset.f===finSt));$('#feType').value=finType;if(finView==='students')rFinStudents();if(finView==='gastos')rExpenses();
  $('#fIn').textContent=money(inn);$('#fInF').textContent=`${rec.filter(f=>f.status==='Pago').length} de ${rec.length} pago(s)`;const lateR=rec.filter(lateOf);$('#fOpen').textContent=money(sum(rec.filter(f=>f.status!=='Pago')));$('#fOpen').className=lateR.length?'neg':'';$('#fOpenF').textContent=lateR.length?`${lateR.length} vencida(s) · ${money(sum(lateR))}`:'Nada vencido ✓';$('#fOutF').textContent='Pagas: '+money(out);$('#fOut').textContent=money(sum(exp));
  const bal=$('#fBal');bal.textContent=money(inn-out);bal.className=inn-out<0?'neg':'pos';
  const q=($('#feSearch').value||'').trim().toLowerCase(),sv=$('#feSort').value,rk={late:0,open:1,paid:2},nm=f=>String(isExp(f)?f.description:(f.studentName||f.description)||'');
  const base=r.filter(f=>(finType==='all'||(finType==='Despesa')===isExp(f))&&(!q||nm(f).toLowerCase().includes(q)||String(f.description||'').toLowerCase().includes(q)));
  pillCounts('#finSt',{all:base.length,open:base.filter(f=>f.status!=='Pago').length,late:base.filter(lateOf).length,paid:base.filter(f=>f.status==='Pago').length});
  const list=base.filter(f=>finSt==='all'||(finSt==='paid'&&f.status==='Pago')||(finSt==='open'&&f.status!=='Pago')||(finSt==='late'&&lateOf(f)))
    .sort((a,b)=>sv==='status'?rk[finState([a]).k]-rk[finState([b]).k]||String(a.dueDate).localeCompare(String(b.dueDate)):sv==='value'?Number(b.value)-Number(a.value):sv==='name'?nm(a).localeCompare(nm(b),'pt-BR'):String(a.dueDate).localeCompare(String(b.dueDate)));
  $('#finList').innerHTML=list.length?list.map(f=>{
    const ex=isExp(f),s=ex?null:studentById(f.studentId),fs=finState([f]),num=s?.whatsapp,unp=!ex&&f.status!=='Pago'&&waLink(num,'');
    return scard({sid:f.studentId,key:'fe:'+f.id,tone:fs.k==='late'?'bad':'ok',name:ex?f.description:(f.studentName||f.description),av:ex?'💸':'',badge:fs.label,cls:fs.cls,
      sub:ex?`Despesa · vence ${fmtDate(f.dueDate)}`:`${esc(f.description||'')} · vence ${fmtDate(f.dueDate)}`,
      mini:[['VALOR',(ex?'− ':'')+money(f.value)],['VENCIMENTO',fmtDate(f.dueDate)],[lateOf(f)?'ATRASO':'FORMA',lateOf(f)?daysLate(f)+' dia(s)':esc(f.paymentMethod||'—')]],
      det:[...(ex?[]:stuLine(s)),['Pago em',f.paidAt?fmtDate(f.paidAt):'—'],['Observações',esc(f.notes||'—')]],
      ...(f.status==='Pago'?{prim:''}:{}),acts:(f.status!=='Pago'?`<button class="btn sm" data-act="payFin" data-id="${f.id}">Pagar</button>`+(unp?`<button class="btn sm wa" data-act="waMsg" data-k="bill" data-fid="${f.id}">Cobrar</button><button class="btn sm wa" data-act="waMsg" data-k="reminder" data-fid="${f.id}">Lembrar</button>`:''):`<button class="btn sm" data-act="unpayFin" data-id="${f.id}">Desfazer</button>`)+`<button class="btn sm" data-act="editFin" data-id="${f.id}">Editar</button><button class="btn sm bad" data-act="delFin" data-id="${f.id}">Excluir</button>`});
  }).join(''):'<div class="card empty">Nenhum lançamento neste mês.</div>';
}
const stBadge=f=>f.status==='Pago'?'<span class="badge ok">Pago</span>':lateOf(f)?'<span class="badge bad">Vencido</span>':'<span class="badge ok">A vencer</span>'; // em dia = verde, atrasado = vermelho
/* ========== MENSAGENS DE WHATSAPP — modelos dinâmicos, variáveis e editor com prévia ========== */
const MSG_KINDS=[['billing','Cobrança'],['late','Cobrança em atraso'],['reminder','Lembrete de vencimento'],['class','Lembrete de aula'],['classNow','Aula já começou'],['birthday','Aniversário'],['waitlist','Lista de espera'],['general','Contato geral']];
const MSG_VARS=[['saudacao','Saudação'],['nome','Nome'],['nome_completo','Nome completo'],['studio','Studio'],['responsavel','Responsável'],['plano','Plano'],['horario','Horário'],['dias','Dias de aula'],['professor','Professor(a)'],['valor','Valor'],['vencimento','Vencimento'],['descricao','Descrição'],['situacao','Situação'],['dias_atraso','Dias de atraso'],['total_aberto','Total em aberto'],['qtd_abertas','Qtd. em aberto'],['lista_abertas','Lista em aberto'],['pix','Chave PIX'],['pix_tipo','Tipo da chave'],['pix_nome','Beneficiário'],['proxima_aula','Próxima aula'],['aula_dia','Dia da aula'],['aula_data','Data da aula'],['aula_hora','Hora da aula'],['aparelho','Aparelho'],['idade','Idade'],['hoje','Hoje'],['mes','Mês']];
const waFmt=t=>esc(t).replace(/\*([^*\n]+)\*/g,'<b>$1</b>').replace(/_([^_\n]+)_/g,'<i>$1</i>').replace(/~([^~\n]+)~/g,'<s>$1</s>');
const openFinOf=s=>s?.id?db.finance.filter(x=>x.studentId===s.id&&!isExp(x)&&x.status!=='Pago').sort((a,b)=>String(a.dueDate).localeCompare(String(b.dueDate))):[];
function msgCtx(d){
  const n=new Date(),nk=`${iso(n)}T${pad(n.getHours())}:${pad(n.getMinutes())}`;
  let f=d.fid&&db.finance.find(x=>x.id===d.fid),c=d.cid&&classById(d.cid),w=d.wid&&db.waitlist.find(x=>x.id===d.wid),s=d.sid&&studentById(d.sid);
  if(!s&&f)s=studentById(f.studentId);if(!s&&c)s=studentById(c.studentId);
  if(w)s={name:w.name,whatsapp:w.whatsapp,plan:w.plan,time:w.time};
  if(s?.id){
    if(!f)f=openFinOf(s)[0];
    if(!c)c=db.classes.filter(x=>x.studentId===s.id&&!['Realizada','Falta','Faltou','Cancelada'].includes(x.status)&&`${x.date}T${x.time||'00:00'}`>=nk).sort((a,b)=>`${a.date}T${a.time}`.localeCompare(`${b.date}T${b.time}`))[0];
  }
  return{s,f:f||null,c:c||null};
}
function msgVars({s,f,c}){
  s=s||{};const st=db.settings,now=new Date(),t0=iso(now),h=now.getHours(),pd=d=>`${pad(d.getDate())}/${pad(d.getMonth()+1)}`;
  const dd=x=>Math.round((new Date(x+'T12:00')-new Date(t0+'T12:00'))/864e5);
  const sit=x=>{const d=dd(x.dueDate);return d<0?`venceu há ${-d} dia(s)`:d?`vence em ${d} dia(s)`:'vence hoje'};
  const open=openFinOf(s),late=open.filter(x=>dd(x.dueDate)<0),cd=c?new Date(c.date+'T12:00'):null;
  return{
    saudacao:h<12?'Bom dia':h<18?'Boa tarde':'Boa noite',
    nome:String(s.name||'').split(' ')[0],nome_completo:s.name||'',studio:st.studioName||'',responsavel:st.owner||'',
    plano:s.plan||'',horario:s.time||'',dias:(s.days||[]).map(d=>DAY[d]).filter(Boolean).join(', '),professor:c?.teacher||s.teacher||'',
    valor:f?money(f.value):'',vencimento:f?fmtDate(f.dueDate):'',descricao:f?.description||'',situacao:f?sit(f):'',
    dias_atraso:late.length?String(Math.max(...late.map(x=>-dd(x.dueDate)))):'',
    total_aberto:open.length?money(open.reduce((t,x)=>t+Number(x.value||0),0)):'',qtd_abertas:open.length?String(open.length):'',
    lista_abertas:open.map(x=>`• ${fmtDate(x.dueDate)} — ${money(x.value)} (${sit(x)})`).join('\n'),
    pix:st.pixKey||'',pix_tipo:st.pixKey?st.pixType||'':'',pix_nome:st.pixKey?st.pixName||st.owner||'':'',
    proxima_aula:cd?`${DAY[cd.getDay()]}, ${pd(cd)} às ${c.time}`:'',aula_dia:cd?cd.toLocaleDateString('pt-BR',{weekday:'long'}):'',aula_data:cd?pd(cd):'',aula_hora:c?.time||'',
    aparelho:c?db.equipment.find(e=>e.id===c.equipmentId)?.name||'':'',
    idade:s.birth?String(now.getFullYear()-Number(String(s.birth).slice(0,4))):'',hoje:fmtDate(t0),mes:now.toLocaleDateString('pt-BR',{month:'long'})
  };
}
// troca {variáveis}; linha cujo dado está vazio é omitida (sem "Chave PIX: " em branco); {tag} desconhecida fica como está
function msgRender(tpl,ctx){
  const m=msgVars(ctx);
  return String(tpl||'').split('\n').map(l=>{let drop=false;const o=l.replace(/\{(\w+)\}/g,(x,k)=>{if(!(k in m))return x;if(m[k]==='')drop=true;return m[k]});return drop?null:o}).filter(l=>l!==null).join('\n').replace(/\n{3,}/g,'\n\n').trim();
}
let waSt=null,mPk='billing';
function waCompose(d){
  const x=msgCtx(d);if(!x.s||!waLink(x.s.whatsapp,''))return toast('Aluno sem WhatsApp cadastrado.');
  const t=iso(new Date()),k=d.k==='bill'?(!x.f?'general':x.f.dueDate<t?'late':x.f.dueDate===t?'reminder':'billing'):(d.k||'general'),v=msgVars(x);
  waSt={x,num:x.s.whatsapp};
  openModal(`<h2>${ico('chat')} WhatsApp</h2><div class="prof">${stuAv(x.s,x.s.name)}<div class="sub">${esc(x.s.name)} · ${esc(x.s.whatsapp)}</div></div>
    <div class="wm-bar"><select id="wmK" aria-label="Modelo">${MSG_KINDS.map(([a,l])=>`<option value="${a}"${a===k?' selected':''}>${l}</option>`).join('')}</select><select id="wmI" aria-label="Inserir dado"><option value="">+ Dado</option>${MSG_VARS.filter(([a])=>v[a]).map(([a,l])=>`<option value="${a}">${l}</option>`).join('')}</select></div>
    <textarea id="wmT" rows="10" aria-label="Mensagem (editável)"></textarea><div class="sub" id="wmN"></div>
    <div class="foot"><button class="btn" data-act="closeModal">Cancelar</button><button class="btn" data-act="wmCopy" aria-label="Copiar mensagem">${ico('copy')}</button><a class="btn wa wm-go" id="wmGo" target="_blank" rel="noopener">${ico('chat')} Enviar</a></div>`);
  wmLoad(k);
}
function wmLoad(k){$('#wmT').value=msgRender(db.settings.messages[k]||MSG_DEFAULTS[k],waSt.x);wmSync()}
function wmSync(){const t=$('#wmT').value;$('#wmGo').href=waLink(waSt.num,t);$('#wmN').textContent=`${t.length} caracteres · ${t?t.split('\n').length:0} linha(s)`}
function msgFieldsLoad(){
  const F=$('#mFields');if(!F.children.length)F.innerHTML=MSG_KINDS.map(([k,l])=>`<details class="wmx" name="wmx"><summary>${l}</summary><textarea id="m_${k}" rows="${k==='late'?9:6}" aria-label="${l}"></textarea></details>`).join('');
  MSG_KINDS.forEach(([k])=>{$('#m_'+k).value=db.settings.messages[k]||MSG_DEFAULTS[k]});
  $('#mVars').innerHTML=MSG_VARS.map(([a,l])=>`<code>{${a}}</code> ${l}`).join(' · ');
  $('#mPrevS').innerHTML='<option value="">Exemplo</option>'+db.students.filter(x=>(x.status||'Ativo')==='Ativo').sort((a,b)=>a.name.localeCompare(b.name,'pt-BR')).map(x=>`<option value="${x.id}">${esc(x.name)}</option>`).join('');
  mPrev();
}
function mPrev(t){
  if(t?.id?.startsWith('m_'))mPk=t.id.slice(2);
  const real=studentById($('#mPrevS').value),p=db.plans[0]||{},x=real?msgCtx({sid:real.id}):{s:{name:'Maria Silva',plan:p.name||'',time:db.hours[0]||'',days:['1','3'],teacher:db.teachers[0]||''},f:{value:p.price||170,dueDate:iso(new Date()),description:'Mensalidade'},c:null};
  $('#mPrev').innerHTML=waFmt(msgRender($('#m_'+mPk)?.value||MSG_DEFAULTS[mPk],x))||'<span class="sub">Sem conteúdo</span>';
  $('#mPrevL').textContent=MSG_KINDS.find(([a])=>a===mPk)?.[1]||'';
}
Object.assign(ACT,{
  waMsg:e=>waCompose(e.dataset),
  wmCopy:()=>{const t=$('#wmT');const ok=()=>toast('Mensagem copiada.'),no=()=>{t.select();document.execCommand('copy')?ok():toast('Não foi possível copiar.')};navigator.clipboard?.writeText?navigator.clipboard.writeText(t.value).then(ok,no):no()},
  msgReset:()=>{MSG_KINDS.forEach(([k])=>{$('#m_'+k).value=MSG_DEFAULTS[k]});mPrev();toast('Modelos padrão restaurados. Toque em Salvar para aplicar.')}
});
document.addEventListener('input',e=>{const t=e.target;if(t.id==='wmT')wmSync();else if(t.matches?.('#mFields textarea'))mPrev(t)});
document.addEventListener('focusin',e=>{if(e.target.matches?.('#mFields textarea'))mPrev(e.target)});
document.addEventListener('change',e=>{const t=e.target;if(t.id==='wmK')wmLoad(t.value);else if(t.id==='mPrevS')mPrev();else if(t.id==='wmI'){const a=$('#wmT');if(t.value){a.setRangeText(msgVars(waSt.x)[t.value]||'',a.selectionStart,a.selectionEnd,'end');wmSync()}t.value='';a.focus()}});
document.addEventListener('toggle',e=>{const d=e.target;if(d.open&&d.matches?.('#mFields details'))mPrev(d.querySelector('textarea'))},true);
function finModal(id,pre){
  const f0=id?db.finance.find(x=>x.id===id):null,f=f0||pre||null;editing=f0?id:null;
  openModal(`<h2>${f0?'Editar lançamento':'Novo lançamento'}</h2><div class="form">
    <div class="field"><label for="finType">Tipo</label><select id="finType">${opts(['Receita','Despesa'],f?.type||'Receita')}</select></div>
    <div class="field"><label for="finStudent">Aluno (receitas)</label><select id="finStudent"><option value="">—</option>${db.students.map(s=>`<option value="${s.id}"${s.id===f?.studentId?' selected':''}>${esc(s.name)}</option>`).join('')}</select></div>
    <div class="field full"><label for="finDesc">Descrição *</label><input id="finDesc" value="${esc(f?.description)}"></div>
    <div class="field"><label for="finValue">Valor (R$) *</label><input id="finValue" type="number" min="0" step="0.01" inputmode="decimal" value="${esc(f?.value)}"></div>
    <div class="field"><label for="finDue">Vencimento *</label><input id="finDue" type="date" value="${esc(f?.dueDate||iso(new Date()))}"></div>
    <div class="field"><label for="finStatus">Status</label><select id="finStatus">${opts(['Pendente','Pago'],f?.status||'Pendente')}</select></div>
    <div class="field"><label for="finPay">Pagamento</label><select id="finPay"><option value="">—</option>${opts(db.payments||['PIX','Cartão de Crédito','Dinheiro','Transferência'],f?.paymentMethod)}</select></div>
    <div class="field full"><label for="finNotes">Observações</label><input id="finNotes" value="${esc(f?.notes)}"></div>
  </div><div class="foot"><button class="btn" data-act="closeModal">Cancelar</button><button class="btn primary" data-act="saveFin">Salvar</button></div>`);
}
function saveFin(){
  const sid=$('#finStudent').value,s=studentById(sid),value=Number($('#finValue').value),old=editing?db.finance.find(x=>x.id===editing):null;
  const o={...(old||{}),id:old?.id||uid('fin'),type:$('#finType').value,studentId:sid,studentName:s?.name||'',description:$('#finDesc').value.trim(),value,dueDate:$('#finDue').value,status:$('#finStatus').value,paymentMethod:$('#finPay').value,notes:$('#finNotes').value.trim()};
  if(!o.description||!o.dueDate||!(value>0))return toast('Informe descrição, valor maior que zero e vencimento.');
  if(o.status==='Pago')o.paidAt=old?.paidAt||iso(new Date());else delete o.paidAt;
  if(old)db.finance[db.finance.indexOf(old)]=o;else db.finance.push(o);
  if(!save())return;closeModal();render();toast('Lançamento salvo.');
}
function genBills(){
  const k=ym(finMonth),n=new Date(finMonth.getFullYear(),finMonth.getMonth()+1,0).getDate();let c=0;
  activeStudents().forEach(s=>{
    if(!(Number(s.monthly)>0)||(s.startDate&&s.startDate.slice(0,7)>k))return;
    if(db.finance.some(f=>!isExp(f)&&f.studentId===s.id&&String(f.dueDate).startsWith(k)&&/mensalidade/i.test(f.description)))return;
    db.finance.push({id:uid('fin'),type:'Receita',studentId:s.id,studentName:s.name,description:`Mensalidade — ${s.plan||'Pilates'}`,value:Number(s.monthly),dueDate:`${k}-${pad(Math.min(Number(s.due)||10,n))}`,status:'Pendente',paymentMethod:'',notes:''});c++;
  });
  if(c)save();render();toast(c?`${c} mensalidades geradas.`:'Todas as mensalidades do mês já existem.');
}
Object.assign(ACT,{
  newFin:()=>finModal(),editFin:e=>{const f=db.finance.find(x=>x.id===e.dataset.id);f&&isExp(f)?expModal(f.id):finModal(e.dataset.id)},saveFin,genBills,
  payFin:e=>payModal(e.dataset.id),confirmPay,
  delFin:e=>{if(confirm('Excluir este lançamento?')){db.finance=db.finance.filter(x=>x.id!==e.dataset.id);save();render();toast('Lançamento excluído.')}},
  mNew:()=>finView==='gastos'?expModal():finModal(),finPrev:()=>{finMonth=new Date(finMonth.getFullYear(),finMonth.getMonth()-1,1);render()},
  finNext:()=>{finMonth=new Date(finMonth.getFullYear(),finMonth.getMonth()+1,1);render()}
});
$('#finSt').addEventListener('click',e=>{const b=e.target.closest('button');if(!b)return;finSt=b.dataset.f;rMoney()});
$('#feType').addEventListener('change',e=>{finType=e.target.value;rMoney()});


/* ========== CONFIGURAÇÕES / BACKUP ========== */
const LH_KEYS=['name','tag','cnpj','addr','city','phone','mail','web','resp','reg','note'],LH_ID={name:'lhName',tag:'lhTag',cnpj:'lhCnpj',addr:'lhAddr',city:'lhCity',phone:'lhPhone',mail:'lhMail',web:'lhWeb',resp:'lhResp',reg:'lhReg',note:'lhNote'};
let lhLogoDraft;
const lhGet=()=>{const l=db.settings.letterhead;return l&&typeof l==='object'?l:{}};
const lhLogo=()=>{const l=lhGet().logo;return typeof l==='string'&&PH_OK.test(l)?l:''};
function lhRead(){const o={on:$('#lhOn').value!=='0'};LH_KEYS.forEach(k=>o[k]=$('#'+LH_ID[k]).value.trim().slice(0,160));const lg=lhLogoDraft===undefined?lhLogo():(lhLogoDraft||'');if(lg)o.logo=lg;return o}
function lhPrevRender(){
  const o=lhRead(),nm=o.name||$('#sName').value.trim()||db.settings.studioName,l1=[o.tag,o.cnpj&&'CNPJ/CPF: '+o.cnpj].filter(Boolean).join(' · '),l2=[o.addr,o.city].filter(Boolean).join(' · '),l3=[o.phone,o.mail,o.web].filter(Boolean).join(' · ');
  $('#lhLogoBox').innerHTML=o.logo?`<img src="${o.logo}" alt="Logo do studio">`:'Sem logo';
  $('#lhPrev').innerHTML=(o.logo?`<img src="${o.logo}" alt="">`:'')+`<div><div class="lhn">${esc(nm)}</div><div class="lhs">${[l1,l2,l3].filter(Boolean).map(esc).join('<br>')}</div></div>`;
}
function lhLoad(){
  const l=lhGet();LH_KEYS.forEach(k=>$('#'+LH_ID[k]).value=l[k]||'');$('#lhOn').value=l.on===false?'0':'1';lhLogoDraft=undefined;lhPrevRender();
}
function lhLogoFromFile(f){
  if(!f)return;if(!/^image\/(png|jpeg|webp)$/.test(f.type))return toast('Use uma imagem PNG, JPG ou WebP.');if(f.size>6e6)return toast('Imagem grande demais (máx. 6 MB).');
  const rd=new FileReader();rd.onerror=()=>toast('Não foi possível ler a imagem.');
  rd.onload=()=>{const im=new Image();im.onerror=()=>toast('Imagem inválida.');
    im.onload=()=>{const m=480,k=Math.min(1,m/Math.max(im.width,im.height)),w=Math.max(1,Math.round(im.width*k)),h=Math.max(1,Math.round(im.height*k)),c=document.createElement('canvas');c.width=w;c.height=h;c.getContext('2d').drawImage(im,0,0,w,h);
      let out='';try{out=c.toDataURL('image/png');if(out.length>180000)out=c.toDataURL('image/jpeg',.88)}catch{}
      if(!PH_OK.test(out))return toast('Não foi possível processar a imagem.');lhLogoDraft=out;lhPrevRender()};
    im.src=rd.result};
  rd.readAsDataURL(f);
}
function lhHTML(){
  const o=lhGet(),nmS=db.settings.studioName;if(o.on===false)return `<header class="pfh"><div><div class="pfk">${esc(nmS)}</div></div></header>`;
  const nm=o.name||nmS,lg=lhLogo(),l1=[o.tag,o.cnpj&&'CNPJ/CPF: '+o.cnpj].filter(Boolean),l2=[o.addr,o.city].filter(Boolean),l3=[o.phone&&'Tel.: '+o.phone,o.mail,o.web].filter(Boolean);
  return `<header class="pfh lh"><div class="pflh">${lg?`<img src="${lg}" alt="">`:''}<div class="pfid"><div class="pfx1">${esc(nm)}</div>${[l1,l2,l3].filter(a=>a.length).map(a=>`<div class="pfx2">${a.map(esc).join(' · ')}</div>`).join('')}</div></div></header>`;
}
let planDraft=[];
function planRows(){
  $('#planRows').innerHTML=planDraft.length?planDraft.map((p,i)=>`<div class="form" style="grid-template-columns:2fr 1fr 1fr auto;align-items:end;margin-bottom:8px">
    <div class="field"><label>Nome</label><input data-pl="${i}" data-k="name" value="${esc(p.name)}"></div>
    <div class="field"><label>Aulas/sem.</label><input data-pl="${i}" data-k="weekly" type="number" min="1" max="7" value="${esc(p.weekly)}"></div>
    <div class="field"><label>Valor (R$)</label><input data-pl="${i}" data-k="price" type="number" min="0" step="0.01" value="${esc(p.price)}"></div>
    <button class="btn sm bad" data-act="delPlan" data-i="${i}" aria-label="Remover plano">✕</button></div>`).join(''):'<div class="empty">Nenhum plano. Adicione um.</div>';
}
let hoursDraft=[],teachersDraft=[];
const newHr=h=>({h,orig:false,del:false,days:['1','2','3','4','5']});
const hpChanges=()=>hoursDraft.filter(x=>x.del||!x.orig||(x.orig&&x.days.join()!==x.od)).length+teachersDraft.filter(t=>t.del||!t.orig||t.name.trim()!==t.orig).length;
function hrCnt(){const c={};activeStudents().forEach(s=>{if(s.time)normDays(s.days).forEach(d=>{const k=s.time+'|'+d;c[k]=(c[k]||0)+1})});return c}
function hpSummary(){
  const cap=Math.max(1,Number(db.settings.capacity)||1),cnt=hrCnt(),hs=hoursDraft.filter(x=>!x.del),t=teachersDraft.filter(x=>!x.del).length,c=hpChanges();
  let tot=0,used=0;hs.forEach(x=>x.days.forEach(d=>{tot+=cap;used+=Math.min(cnt[x.h+'|'+d]||0,cap)}));const pct=tot?Math.round(used/tot*100):0;
  $('#hpSummary').innerHTML=`<div class="mini"><div><small>HORÁRIOS</small><b>${hs.length}</b></div><div><small>PROFESSORES</small><b>${t}</b></div><div><small>VAGAS/SEMANA</small><b>${used}/${tot}</b></div><div><small>OCUPAÇÃO</small><b class="${pct>=90?'neg':''}">${pct}%</b></div></div>`+(c?`<div class="sub" style="color:var(--warn);font-weight:600">${c} alteração(ões) não salva(s)</div>`:'');
}
function hrChips(){
  const cap=Math.max(1,Number(db.settings.capacity)||1),dur=Number(db.settings.duration)||60,cnt=hrCnt(),act=activeStudents(),end=h=>hhmm((toMin(h)+dur)%1440);
  $('#hrChips').innerHTML=hoursDraft.map((x,i)=>{
    const n=act.filter(s=>s.time===x.h).length,used=x.days.reduce((a,d)=>a+Math.min(cnt[x.h+'|'+d]||0,cap),0),tot=x.days.length*cap,pct=tot?Math.round(used/tot*100):0,tone=pct>=90?'bad':pct>=60?'warn':'ok';
    return `<div class="hrow${x.del?' del':!x.orig?' new':''}"><div class="hr-t"><b>${esc(x.h)}</b><small>até ${end(x.h)}</small></div><div class="hr-m"><div class="bar ${tone}"><i style="width:${pct}%"></i></div><div class="sub">${n} aluno${n===1?'':'s'} · ${used}/${tot} vagas · ${pct}%</div><div class="hr-d">${ORDER.map(d=>{const c=cnt[x.h+'|'+d]||0,on=x.days.includes(d);return `<button type="button" data-act="hrDay" data-i="${i}" data-d="${d}" class="${on?'on':''}${on&&c>cap?' over':on&&c>=cap?' full':''}" aria-pressed="${on}"${x.del?' disabled':''}>${DAY[d]}${on?`<small>${c}/${cap}</small>`:''}</button>`}).join('')}</div></div><button type="button" class="btn sm${x.del?'':' bad'}" data-act="hrDel" data-i="${i}" aria-label="${x.del?'Restaurar':'Remover'} horário ${esc(x.h)}">${x.del?'↺':'✕'}</button></div>`}).join('')||'<span class="sub">Nenhum horário.</span>';
  hpSummary();
}
function teachRows(){
  const act=activeStudents(),mk=ym(new Date()),load=t=>act.filter(s=>s.teacher===t).reduce((a,s)=>a+normDays(s.days).length,0),max=Math.max(1,...teachersDraft.filter(t=>!t.del).map(t=>load(t.orig||t.name)));
  const noT=act.filter(s=>!s.teacher).length;
  $('#teachRows').innerHTML=teachersDraft.map((t,i)=>{
    const k=t.orig||t.name,all=db.students.filter(x=>x.teacher===k),mine=all.filter(x=>(x.status||'Ativo')==='Ativo'),ses=load(k),
      cl=db.classes.filter(c=>c.teacher===k&&String(c.date).startsWith(mk)&&c.status!=='Cancelada'),done=cl.filter(c=>c.status==='Realizada').length,
      hrs=[...new Set(mine.map(s=>s.time).filter(Boolean))].sort(),pct=Math.round(ses/max*100);
    return `<div class="tcard${t.del?' del':''}"><div class="trow"><div class="av sm">${esc(initials(t.name||'?'))}</div><input data-ti="${i}" value="${esc(t.name)}"${t.del?' disabled':''} aria-label="Nome do professor"><button type="button" class="btn sm${t.del?'':' bad'}" data-act="tcDel" data-i="${i}" aria-label="${t.del?'Restaurar':'Remover'} professor">${t.del?'↺':'✕'}</button></div>
    <div class="bar" title="Carga semanal"><i style="width:${pct}%"></i></div>
    <div class="tstats"><span class="badge">${mine.length} aluno${mine.length===1?'':'s'} ativo${mine.length===1?'':'s'}</span><span class="badge">${ses} sessões/sem</span><span class="badge">${done}/${cl.length} aulas no mês</span></div>
    ${hrs.length?`<div class="tchips">${hrs.map(h=>`<span>${esc(h)}</span>`).join('')}</div>`:'<div class="sub" style="margin-top:6px">Sem alunos ativos atribuídos.</div>'}</div>`}).join('')||'<div class="sub">Nenhum professor.</div>';
  if(noT)$('#teachRows').insertAdjacentHTML('beforeend',`<div class="sub" style="color:var(--warn)">${noT} aluno${noT===1?'':'s'} ativo${noT===1?'':'s'} sem professor definido.</div>`);
  hpSummary();
}
function rSettings(){
  const st=db.settings,v=(i,x)=>{$('#'+i).value=x??''};
  v('sName',st.studioName);v('sOwner',st.owner);v('sWa',st.whatsapp);v('sCap',st.capacity);v('sDur',st.duration);v('sDark',st.darkMode?'1':'0');
  v('sPixT',st.pixType);v('sPixK',st.pixKey);v('sPixN',st.pixName);msgFieldsLoad();lhLoad();
  planDraft=db.plans.map(p=>({...p}));planRows();rPal();
  hoursDraft=[...db.hours].sort().map(h=>({h,orig:true,del:false,days:hourDays(h).slice(),od:hourDays(h).join()}));teachersDraft=db.teachers.map(n=>({orig:n,name:n,del:false}));hrChips();teachRows();segUp();segRefresh();
  $('#dataInfo').textContent=`${db.students.length} alunos · ${db.classes.length} aulas · ${db.finance.length} lançamentos · ${Object.keys(PHOTOS).length} foto(s)`;
}
function commitPlans(){
  const plans=planDraft.map(p=>({...p,name:String(p.name||'').trim(),weekly:Math.min(7,Math.max(1,Number(p.weekly)||1)),price:Math.max(0,Number(p.price)||0)}));
  if(!plans.length||plans.some(p=>!p.name)||new Set(plans.map(p=>p.name.toLowerCase())).size!==plans.length)return 'Planos precisam de nome único.';
  const kept=new Set(plans.map(p=>p.id)),inUse=db.plans.find(o=>!kept.has(o.id)&&db.students.some(x=>x.plan===o.name));
  if(inUse)return `O plano "${inUse.name}" tem alunos e não pode ser removido.`;
  db.students.forEach(x=>{const o=db.plans.find(q=>q.name===x.plan),n=o&&plans.find(q=>q.id===o.id);if(n&&n.name!==x.plan)x.plan=n.name});
  db.plans=plans;return '';
}
$('#lhLogoFile').addEventListener('change',e=>{const f=e.target.files[0];e.target.value='';lhLogoFromFile(f)});
$('#lhCard').addEventListener('input',lhPrevRender);
$('#lhCard').addEventListener('change',lhPrevRender);
function saveSet(){
  const st=db.settings,v=i=>$('#'+i).value.trim(),cap=Number(v('sCap')),dur=Number(v('sDur'));
  if(!v('sName'))return toast('Informe o nome do studio.');
  if(!Number.isInteger(cap)||cap<1)return toast('Vagas por horário deve ser 1 ou mais.');
  if(!(dur>=15))return toast('Duração mínima de 15 minutos.');
  const hours=[...new Set(hoursDraft.filter(x=>!x.del).map(x=>x.h))].sort();if(!hours.length)return toast('Mantenha ao menos um horário.');
  const act=teachersDraft.filter(t=>!t.del),names=act.map(t=>t.name.trim());
  if(!names.length||names.some(n=>!n))return toast('Informe o nome de todos os professores (ou remova a linha vazia).');
  if(new Set(names.map(n=>n.toLowerCase())).size!==names.length)return toast('Há professores com o mesmo nome.');
  const goneH=db.hours.filter(h=>!hours.includes(h)&&activeStudents().some(x=>x.time===h));
  if(goneH.length&&!confirm(`Há alunos ativos nos horários ${goneH.join(', ')}. Remover mesmo assim? Eles continuarão cadastrados nesse horário.`))return;
  const goneT=db.teachers.filter(o=>!act.some(t=>t.orig===o)&&db.students.some(x=>x.teacher===o));
  if(goneT.length&&!confirm(`Há alunos com os professores ${goneT.join(', ')}. Remover mesmo assim? O nome continuará nos cadastros deles.`))return;
  const err=commitPlans();if(err)return toast(err);
  act.forEach((t,i)=>{const n=names[i];if(t.orig&&t.orig!==n){
    db.students.forEach(x=>{if(x.teacher===t.orig)x.teacher=n});db.classes.forEach(c=>{if(c.teacher===t.orig)c.teacher=n});
    ['teacherRates','teacherFixedRates','teacherClassValues'].forEach(k=>{const m=st[k];if(m&&t.orig in m){m[n]=m[t.orig];delete m[t.orig]}});const PP=db.teacherProfiles;if(PP&&t.orig in PP){PP[n]=PP[t.orig];delete PP[t.orig]}}});
  Object.assign(st,{studioName:v('sName'),owner:v('sOwner')||v('sName'),whatsapp:v('sWa'),capacity:cap,duration:dur,darkMode:$('#sDark').value==='1',pixType:$('#sPixT').value,pixKey:v('sPixK'),pixName:v('sPixN')});
  st.letterhead=lhRead();
  st.messages={...st.messages,...Object.fromEntries(MSG_KINDS.map(([k])=>[k,$('#m_'+k).value.trim()||st.messages[k]||MSG_DEFAULTS[k]]))};
  const hd={};hoursDraft.filter(x=>!x.del).forEach(x=>{hd[x.h]=ORDER.filter(d=>x.days.includes(d))});
  db.hours=hours;db.teachers=names;db.hourDays=hd;
  if(!save())return;applyTheme();rSettings();$('#studioName').textContent=st.studioName;toast('Configurações salvas.');
}
const hhmm=m=>pad(Math.floor(m/60))+':'+pad(m%60),toMin=t=>{const [h,m]=String(t).split(':');return (+h)*60+(+m)};
function exportDb(){
  const blob=new Blob([JSON.stringify({app:'studio-pilates',version:2,exportedAt:new Date().toISOString(),data:db,photos:PHOTOS,exphotos:EXPH},null,1)],{type:'application/json'});
  const a=document.createElement('a');a.href=URL.createObjectURL(blob);a.download=`studio-pilates-backup-${iso(new Date())}.json`;
  document.body.appendChild(a);a.click();a.remove();setTimeout(()=>URL.revokeObjectURL(a.href),4000);toast('Backup exportado.');
}
function importDb(file){
  const r=new FileReader();
  r.onerror=()=>toast('Não foi possível ler o arquivo.');
  r.onload=()=>{
    try{
      const o=JSON.parse(r.result),d=o.data||o;
      if(!d||!Array.isArray(d.students)||!Array.isArray(d.classes))throw 0;
      if(!confirm(`Substituir TODOS os dados atuais por este backup (${d.students.length} alunos, ${d.classes.length} aulas)?\nUma cópia dos dados atuais será guardada antes.`))return;
      try{localStorage.setItem('sp_pre_restore',JSON.stringify(db))}catch{return toast('Sem espaço para guardar a cópia de segurança. Restauração cancelada.')}
      localStorage.setItem(KEY,JSON.stringify(d));localStorage.removeItem(VAULT);
      if(o.photos&&typeof o.photos==='object'&&!Array.isArray(o.photos)){PHOTOS=Object.fromEntries(Object.entries(o.photos).filter(([k,v])=>typeof v==='string'&&PH_OK.test(v)));savePhotos()}
      if(o.exphotos&&typeof o.exphotos==='object'&&!Array.isArray(o.exphotos)){EXPH=Object.fromEntries(Object.entries(o.exphotos).filter(([k,v])=>typeof v==='string'&&EXPH_OK.test(v)));exphSave();Object.keys(GXPH).forEach(k=>delete GXPH[k]);gxPhLoad()}
      db=load();if(!save())return;applyTheme();render();toast('Backup restaurado.');
    }catch{toast('Arquivo de backup inválido.')}
  };
  r.readAsText(file);
}
async function changePw(){
  const o=$('#pwOld').value,n=$('#pwNew').value,e=$('#pwErr');e.textContent='';
  if(n.length<6)return e.textContent='A nova senha precisa ter ao menos 6 caracteres.';
  if(n!==$('#pwNew2').value)return e.textContent='A confirmação não confere.';
  const r=await Auth.change(o,n);
  if(!r.ok)return e.textContent=r.msg;
  ['pwOld','pwNew','pwNew2'].forEach(i=>$('#'+i).value='');toast('Senha alterada.');if(window.FB)window.FB.updatePassword(n);
}
Object.assign(ACT,{
  setPal:e=>{{const th=db.settings.theme||{};db.settings.theme={...th,preset:e.dataset.k,grad:th.grad?{...th.grad,on:false}:th.grad}}if(!save())return;applyTheme();rPal();toast('Paleta '+PALETTES[e.dataset.k].n+' aplicada.')},
  authGen:()=>{const r=Auth.authorize($('#aoProto').value);$('#aoErr').textContent='';$('#aoOut').hidden=!r;if(!r)return $('#aoErr').textContent='Protocolo inválido (8 caracteres).';$('#aoCode').textContent=r.code;$('#aoOut').dataset.p=r.p},
  authSend:()=>{const o=$('#aoOut');window.open('https://wa.me/?text='+encodeURIComponent(`🔑 *Código de autorização*\nProtocolo: ${o.dataset.p}\nCódigo: *${$('#aoCode').textContent}*\nNão compartilhe com ninguém.`),'_blank','noopener')},
  saveSet,exportDb,changePw,
  lhLogoPick:()=>$('#lhLogoFile').click(),
  lhLogoDel:()=>{lhLogoDraft='';lhPrevRender()},
  lhFill:()=>{const st=db.settings,set=(id,v)=>{const el=$('#'+id);if(v&&!el.value.trim())el.value=v};set('lhName',st.studioName);set('lhPhone',st.whatsapp);set('lhResp',st.owner);lhPrevRender();toast('Campos vazios preenchidos com os dados do studio.')},
  hrAdd:()=>{const el=$('#hrNew'),h=el.value;if(!/^([01]\d|2[0-3]):[0-5]\d$/.test(h))return toast('Escolha um horário válido.');
    const ex=hoursDraft.find(x=>x.h===h);if(ex){if(!ex.del)return toast('Esse horário já existe.');ex.del=false}else{hoursDraft.push(newHr(h));hoursDraft.sort((a,b)=>a.h.localeCompare(b.h))}el.value='';hrChips()},
  hrDay:e=>{const x=hoursDraft[+e.dataset.i],d=e.dataset.d;if(!x)return;const q=new Set(x.days);if(q.has(d)){if(q.size<2)return toast('Mantenha ao menos um dia no horário.');q.delete(d)}else q.add(d);x.days=ORDER.filter(z=>q.has(z));hrChips()},
  hrDel:e=>{const i=Number(e.dataset.i),x=hoursDraft[i];if(!x)return;x.orig?x.del=!x.del:hoursDraft.splice(i,1);hrChips()},
  hrSeqToggle:()=>{const b=$('#hrSeqBox');b.hidden=!b.hidden},
  hrSeq:()=>{const a=toMin($('#hrFrom').value),b=toMin($('#hrTo').value),st=Number($('#hrStep').value);if(!(b>=a))return toast('O fim deve ser depois do início.');
    let add=0;for(let m=a;m<=b&&add<48;m+=st){const h=hhmm(m),ex=hoursDraft.find(x=>x.h===h);if(ex){if(ex.del){ex.del=false;add++}}else{hoursDraft.push(newHr(h));add++}}
    hoursDraft.sort((x,y)=>x.h.localeCompare(y.h));hrChips();toast(add?`${add} horário(s) incluídos.`:'Todos esses horários já existem.')},
  tcAdd:()=>{const el=$('#tcNew'),n=el.value.trim();if(!n)return toast('Digite o nome do professor.');
    const ex=teachersDraft.find(t=>t.name.trim().toLowerCase()===n.toLowerCase());if(ex){if(!ex.del)return toast('Esse professor já existe.');ex.del=false}else teachersDraft.push({orig:null,name:n,del:false});el.value='';teachRows()},
  tcDel:e=>{const i=Number(e.dataset.i),t=teachersDraft[i];if(!t)return;t.orig?t.del=!t.del:teachersDraft.splice(i,1);teachRows()},importDb:()=>$('#impFile').click(),
  addPlan:()=>{let n=1;while(planDraft.some(p=>p.name==='Novo plano '+n))n++;planDraft.push({id:uid('pl'),name:'Novo plano '+n,weekly:2,price:0});planRows()},
  delPlan:e=>{planDraft.splice(Number(e.dataset.i),1);planRows()}
});
$('#teachRows').addEventListener('input',e=>{const t=e.target;if(t.dataset.ti!==undefined){teachersDraft[+t.dataset.ti].name=t.value;hpSummary()}});
[['#hrNew','hrAdd'],['#tcNew','tcAdd']].forEach(([i,a])=>$(i).addEventListener('keydown',e=>{if(e.key==='Enter'){e.preventDefault();ACT[a]()}}));
$('#planRows').addEventListener('input',e=>{const t=e.target;if(t.dataset.pl!==undefined)planDraft[+t.dataset.pl][t.dataset.k]=t.value});
$('#impFile').addEventListener('change',e=>{const f=e.target.files[0];e.target.value='';if(f)importDb(f)});



/* ========== REPOSIÇÕES / LISTA DE ESPERA / ANIVERSÁRIOS ========== */
const MK_ST=['Pendente','Agendada','Realizada','Cancelada'],MK_CLS={Pendente:'warn',Agendada:'info',Realizada:'ok',Cancelada:''};
const WT_ST=['Contactar','Aguardando','Convertido','Cancelado'];
const stuOpts=sel=>db.students.map(x=>`<option value="${x.id}"${x.id===sel?' selected':''}>${esc(x.name)}</option>`).join('');
/* ===== menu Mais: grupos + busca + recentes ===== */
const ico=(n,c='')=>`<svg class="ico${c?' '+c:''}" aria-hidden="true" focusable="false"><use href="#i-${n}"/></svg>`;
const AVI={'\u{1F4B8}':'receipt','\u{1F3CB}':'dumbbell','\u{1F3E0}':'home','\u{1F4A1}':'bulb','\u{1F469}\u200D\u{1F3EB}':'users','\u{1F9F4}':'drop','\u{1F6E0}':'wrench','\u{1F4E3}':'megaphone','\u{1F9FE}':'receipt','\u{1F4E6}':'box'};
const avIco=a=>AVI[String(a||'').replace(/\uFE0F/g,'')];
const MORE=[
  /* grupo → ordem das seções = ordem das abas */
  ['alerts','bell','Alertas','Rotina','pendências avisos atrasos atenção'],['evolution','pulse','Evolução','Rotina','ficha clínica dor acompanhamento'],['makeups','undo','Reposições','Rotina','faltas remarcar'],['waitlist','hourglass','Lista de espera','Rotina','interessados vaga contato'],['birthdays','cake','Aniversários','Rotina','parabéns'],
  ['hours','clock','Horários','Studio','dias grade'],['occupancy','pie','Ocupação','Studio','vagas lotação'],['equipment','dumbbell','Equipamentos','Studio','aparelhos reformer cadillac'],['teachers','teacher','Professores','Studio','repasse equipe'],
  ['finance','cash','Lançamentos','Dinheiro','receitas pagamentos caixa cobranças mensalidade'],['expenses','receipt','Gastos','Dinheiro','despesas custos contas'],['reports','chart','Relatórios','Dinheiro','rentabilidade margem csv lucro'],
  ['learn','book','Guia de Aprendizado','Aprender','trilha curso fundamentos aprender estudar passo a passo iniciar iniciante'],['guide','bulb','Guia de Exercícios','Aprender','exercício objetivo aparelho sugestão consulta benefício melhora'],['tutor','teacher','Área do Professor','Aprender','ensino estudo ficha técnica clínica exercício professor aprender vídeo treino rápido'],['search','search','Pesquisa','Aprender','buscar procurar exercícios alunos telas encontrar achar'],
  ['settings','sliders','Configurações','Sistema','planos pix senha backup tema paleta mensagens'],
  ['dashboard','home','Painel','Principal','início resumo hoje',1],['students','users','Alunos','Principal','cadastro matrícula',1],['agenda','calendar','Agenda','Principal','aulas calendário',1],['money','wallet','Dinheiro','Principal','financeiro cobranças mensalidade cobrar pagar pagamentos gastos despesas',1]];
const norm=t=>String(t||'').toLowerCase().normalize('NFD').replace(/[\u0300-\u036f]/g,'');
const RK='sp_recent_v1',recents=()=>{try{return JSON.parse(localStorage.getItem(RK))||[]}catch{return[]}};
function pushRecent(p){if(MAIN.includes(p))return;const l=[p,...recents().filter(x=>x!==p)].slice(0,3);try{localStorage.setItem(RK,JSON.stringify(l))}catch{}}
var moreCat='Tudo';
const MGROUPS=['Rotina','Studio','Dinheiro','Aprender','Sistema'],MCATS=['Tudo',...MGROUPS];
function moreStats(){
  const o={alerts:0},mo=new Date().getMonth()+1;
  try{o.alerts=studioAlerts().filter(x=>!x.dismissed&&x.type!=='paid').length}catch{}
  o.waitlist=(db.waitlist||[]).filter(w=>w.status==='Contactar'||w.status==='Aguardando').length;
  o.makeups=(db.makeups||[]).filter(m=>m.status==='Pendente').length;
  o.birthdays=db.students.filter(x=>x.birth&&(x.status||'Ativo')==='Ativo'&&+x.birth.slice(5,7)===mo).length;
  const L=gxLib(),T=tuDB();o.total=L.length;o.done=L.filter(e=>T.st[e.id]===2).length;o.pct=o.total?Math.round(o.done/o.total*100):0;
  return o}
const srTok=q=>norm(q).split(/[\s,;]+/).filter(Boolean);
const SYN_RAW=[
['lombar','lombalgia','dor lombar','lombopélvica','estabilização lombar','costas','coluna lombar','lumbar'],
['hérnia','hérnia de disco','protrusão','disco','discal','estabilização'],
['cervical','cervicalgia','pescoço','trapézio','tensão cervical','neck'],
['postura','postural','hiperlordose','ombros protusos','alinhamento','cifose','ergonomia'],
['escoliose','simetria','assimetria','desvio de coluna','alongamento axial'],
['joelho','knee','patela','condromalácia','menisco','ligamento','quadríceps'],
['quadril','hip','bursite','prótese','femoroacetabular','glúteo','glúteos','pelve'],
['ombro','shoulder','manguito','capsulite','escápula','cintura escapular'],
['gestante','gestação','grávida','gravidez','pré-natal','obstétrica','pós-parto'],
['diástase','abdominal','pós-parto','transverso','linha alba'],
['assoalho pélvico','pélvico','incontinência','prolapso','kegel','períneo'],
['osteoporose','osteopenia','ossos','densidade óssea','idoso','sarcopenia'],
['idoso','idosa','terceira idade','envelhecimento','sarcopenia','equilíbrio','quedas'],
['equilíbrio','propriocepção','quedas','coordenação','controle motor','neuro'],
['core','abdômen','abdominal','centro de força','powerhouse','transverso','oblíquos','reto abdominal'],
['abdômen','abdominais','barriga','core','abdominal'],
['glúteo','glúteos','bumbum','quadril','pelve'],
['perna','pernas','coxa','quadríceps','posterior de coxa','isquiotibiais','adutores'],
['braço','braços','bíceps','tríceps','ombro','peitoral'],
['costas','dorsal','dorso','lombar','coluna','paravertebrais','romboides'],
['coluna','espinha','spine','vértebra','vertebral','torácica','tórax','mobilidade da coluna'],
['alongamento','flexibilidade','mobilidade','stretch','encurtamento','soltura'],
['fortalecimento','força','resistência','tonificação','fortalecer','condicionamento'],
['respiração','respirar','breathing','costal','pulmão','fôlego'],
['relaxamento','relaxar','estresse','ansiedade','consciência corporal','tensão'],
['emagrecimento','peso','obesidade','queima calórica','cardio','controle de peso'],
['pressão','hipertensão','cardíaco','coração','diabetes','cardiometabólico'],
['pós-operatório','cirurgia','reabilitação','fisioterapia','recuperação'],
['reabilitação','fisioterapia','recuperação','lesão','tratamento'],
['dor','algia','dolorido','desconforto','fibromialgia','dor crônica'],
['tornozelo','pé','pés','entorse','fascite','panturrilha'],
['atleta','esporte','performance','corrida','desempenho','prevenção de lesões'],
['iniciante','básico','fácil','leve','suave','nível 1'],
['intermediário','médio','nível 2'],
['avançado','difícil','desafio','intenso','nível 3'],
['reformer','reformador','carro','molas'],
['cadillac','trapézio','tower','torre'],
['chair','cadeira','wunda'],
['barrel','barril','ladder','escada'],
['solo','mat','colchonete','chão'],
['acessórios','bola','overball','faixa','elástico','rolo','anel','bastão'],
['rotação','twist','giro','rotation','torção'],
['flexão','flexion','curl','enrolar'],
['extensão','extension','cisne','swan'],
['elevação','lift','raise','levantar'],
['agachamento','squat'],['afundo','lunge','avanço'],
['prancha','plank','apoio'],['ponte','bridge','pelvic curl'],
['gato','cat','gato-camelo','cat stretch'],['cem','hundred'],
['lateral','side','lado'],['círculo','círculos','circles'],['serrote','saw']];
const SYNG=SYN_RAW.map(g=>({d:g,n:g.map(norm)}));
const srStem=w=>{w=norm(w);if(w.length<=3)return w;w=w.replace(/oes$/,'ao').replace(/(?<=[a-z]{3})s$/,'');return w};
function srLev(a,b,m){if(a===b)return 0;if(Math.abs(a.length-b.length)>m)return m+1;let p=Array.from({length:b.length+1},(_,i)=>i);
 for(let i=1;i<=a.length;i++){const c=[i];let mn=i;for(let j=1;j<=b.length;j++){const v=Math.min(p[j]+1,c[j-1]+1,p[j-1]+(a[i-1]===b[j-1]?0:1));c.push(v);if(v<mn)mn=v}if(mn>m)return m+1;p=c}return p[b.length]}
const srHC=new Map();
function srInfo(e){const sig=e.id+':'+JSON.stringify(e).length,c=srHC.get(e.id);if(c&&c.sig===sig)return c;
 let f={};try{f=gxTec(e).f||{}}catch{}
 const nm=norm((e.n||'')+' '+(e.en||'')),
  rest=norm([e.grp,e.o,e.b,e.musc,e.ind,e.t,e.ex,(e.g||[]).map(g=>GL[g]||g).join(' '),(e.a||[]).map(k=>GX_AP[k]).join(' '),gxLv[e.lv],...['musc','ind','pos','ex','reg','prog'].map(k=>f[k]&&f[k][0])].filter(Boolean).join(' ')),
  o={sig,nm,h:nm+' '+rest,words:new Set((nm+' '+rest).split(/[^a-z0-9]+/).filter(w=>w.length>2))};srHC.set(e.id,o);return o}
function srExp(q){const nq=norm(q).trim(),toks=srTok(q),rel=[],seen=new Set();
 const add=g=>g.d.forEach(d=>{const k=norm(d);if(!seen.has(k)&&k!==nq&&!toks.includes(k)){seen.add(k);rel.push(d)}});
 const gf=w=>{const st=srStem(w);return SYNG.filter(g=>g.n.includes(w)||g.n.includes(st)||(w.length>=4&&g.n.some(t=>{const ws=t.split(' ');return ws.length>1&&(ws.includes(w)||ws.includes(st))})))};
 const tk=toks.map(t=>{const gs=gf(t),v=new Set();gs.forEach(g=>{add(g);g.n.forEach(x=>v.add(x))});v.delete(t);return{t,s:srStem(t),v:[...v]}});
 const ph=toks.length>1?SYNG.filter(g=>g.n.includes(nq)):[],pv=new Set();ph.forEach(g=>{add(g);g.n.forEach(x=>pv.add(x))});
 return{toks,tk,rel,pv:[...pv]}}
function srScore(info,x,deep){const{nm,h,words}=info,s=x.s;
 if(nm.includes(x.t)||nm.includes(s))return[0,nm.startsWith(x.t)?6:5];
 if(h.includes(x.t)||(s.length>2&&h.includes(s)))return[0,3];
 for(const v of x.v)if(nm.includes(v))return[1,2.5];
 for(const v of x.v)if(h.includes(v))return[1,1.5];
 if(deep&&x.t.length>=5){const m=x.t.length>=8?2:1;for(const w of words)if(Math.abs(w.length-x.t.length)<=m&&srLev(w,x.t,m)<=m)return[2,1]}
 return[3,0]}
function srEx2(q){if(!srTok(q).length)return{exact:[],related:[],fuzzy:false,rel:[],X:null};
 const X=srExp(q),L=gxLib();
 const run=deep=>{const ex=[],re=[];L.forEach(e=>{const info=srInfo(e),r=X.tk.map(x=>srScore(info,x,deep)),hits=r.filter(a=>a[0]<3).length,sum=r.reduce((a,b)=>a+b[1],0);
   if(r.every(a=>a[0]===0))ex.push([sum,e]);
   else if(hits===r.length)re.push([sum,e]);
   else{let ph=0;for(const v of X.pv){if(info.nm.includes(v)){ph=2;break}if(info.h.includes(v))ph=1}
    if(ph)re.push([ph+sum*.2,e]);else if(r.length>1&&hits)re.push([sum*.3,e])}});return{ex,re}};
 let o=run(false),fuzzy=false;
 if(o.ex.length+o.re.length<6){const d=run(true);if(d.ex.length+d.re.length>o.ex.length+o.re.length){o=d;fuzzy=true}}
 const so=a=>a.sort((x,y)=>y[0]-x[0]||x[1].n.localeCompare(y[1].n,'pt-BR')).map(x=>x[1]);
 return{exact:so(o.ex),related:so(o.re).slice(0,60),fuzzy,rel:X.rel,X}}
const srEx=q=>{const o=srEx2(q);return[...o.exact,...o.related]};
let srVC=null;
function srDid(q,o){if(o.exact.length&&!o.fuzzy)return '';const L=gxLib();
 if(!srVC||srVC.n!==L.length){const v=new Set();L.forEach(e=>srInfo(e).nm.split(/[^a-z0-9]+/).forEach(w=>{if(w.length>3)v.add(w)}));SYNG.forEach(g=>g.n.forEach(t=>t.split(' ').forEach(w=>{if(w.length>3)v.add(w)})));srVC={n:L.length,v:[...v]}}
 let ch=false;const out=srTok(q).map(t=>{if(t.length<4||srVC.v.includes(t)||srVC.v.includes(srStem(t)))return t;const m=t.length>=8?2:1;let b=null,bd=9;srVC.v.forEach(w=>{if(Math.abs(w.length-t.length)<=m){const d=srLev(w,t,m);if(d<bd){bd=d;b=w}}});if(b&&bd<=m){ch=true;return b}return t});
 return ch?out.join(' '):''}
const srStuHay=x=>norm([x.name,x.teacher,x.complaint,x.goal,x.injuries,x.plan,x.clinical&&x.clinical.diagnosis,x.clinical&&x.clinical.complaint,goalsP(x).map(k=>GL[k]).join(' '),(x.goalKeys2||[]).map(k=>GL[k]||k).join(' '),(x.conditions||[]).map(c=>CL[c]||c).join(' ')].filter(Boolean).join(' '));
function srStus(q){const nq=norm(q.trim());if(!nq)return[];const X=srExp(q),dir=(h,t)=>h.includes(t.t)||h.includes(t.s),
 labs=x=>[...goalsP(x),...(x.goalKeys2||[])].map(k=>GL[k]).filter(Boolean).concat((x.conditions||[]).map(c=>CL[c]).filter(Boolean)),out=[];
 db.students.forEach(x=>{let sc=0,why='';if(norm(x.name).includes(nq))sc=10;else{const h=srStuHay(x);
   if(X.tk.length&&X.tk.every(t=>dir(h,t)))sc=5;else if(X.tk.length&&X.tk.every(t=>dir(h,t)||t.v.some(v=>h.includes(v))))sc=3;
   if(sc){const hit=labs(x).find(l=>{const n=norm(l);return X.tk.some(t=>dir(n,t)||t.v.some(v=>n.includes(v)))});why=hit?gxShort(hit):''}}
  if(sc)out.push([sc,x,why])});
 return out.sort((a,b)=>b[0]-a[0]||a[1].name.localeCompare(b[1].name,'pt-BR')).slice(0,10)}
function srScr(q){const nq=norm(q.trim());if(!nq)return[];const X=srExp(q),sg=srStem(nq);
 return MORE.filter(x=>{const h=norm(x[2]+' '+x[3]+' '+x[4]);return h.includes(nq)||h.includes(sg)||(X.tk.length>0&&X.tk.every(t=>h.includes(t.t)||h.includes(t.s)||t.v.some(v=>h.includes(v))))})}
function exRow(e,i=0){const v=tuDB().st[e.id]||0;
  return `<button type="button" class="srr" style="--i:${i}" data-act="tuOpen" data-id="${e.id}"><span class="srf">${tuFig(e,40)}</span><span class="srt"><b>${e.fav?'★ ':''}${esc(e.n)}</b><small>${esc(gxEqTxt(e.a))} · ${gxLv[e.lv]}${e.grp?' · '+esc(e.grp):''}</small></span><span class="badge ${v===2?'ok':v===1?'info':''}">${['Novo','Estudando','Dominado'][v]}</span></button>`}
function moreBody(q){
  const st=moreStats(),nq=norm(q.trim());let n=0;
  const badge=p=>{const m={alerts:[st.alerts,''],waitlist:[st.waitlist,'soft'],makeups:[st.makeups,'soft'],birthdays:[st.birthdays,'soft'],learn:[st.pct?st.pct+'%':0,'soft']}[p];return m&&m[0]?`<i class="tbd ${m[1]}">${m[0]}</i>`:''};
  const tile=([p,i,l])=>`<button class="tile" style="--i:${n++}" data-act="goPage" data-p="${p}"><i aria-hidden="true">${ico(i)}</i>${l}${badge(p)}</button>`;
  if(nq){
    const sc=srScr(q),ex=srEx(q);
    return (sc.length?`<div class="dk" style="margin-top:6px">TELAS</div><div class="tiles">${sc.map(tile).join('')}</div>`:'')
      +(ex.length?`<div class="dk">EXERCÍCIOS <span class="sub">· ${ex.length}</span></div><div class="mres">${ex.slice(0,4).map(exRow).join('')}</div>`:'')
      +((ex.length>4||ex.length)?`<button type="button" class="btn" data-act="srAll" style="width:100%;justify-content:center;margin-top:10px">Ver todos os resultados na Pesquisa</button>`:'')
      +(!sc.length&&!ex.length?`<div class="empty">Nada encontrado para “${esc(q.trim())}”.</div><button type="button" class="btn" data-act="srAll" style="width:100%;justify-content:center">Pesquisar na tela completa</button>`:'')}
  const show=g=>moreCat==='Tudo'||moreCat===g;
  const rec=moreCat==='Tudo'?recents().map(id=>MORE.find(x=>x[0]===id)).filter(Boolean):[];
  const hero=`<button type="button" class="mhero" data-act="goPage" data-p="learn"><span class="mh-i">${ico('book')}</span><span class="mh-t"><b>Guia de Aprendizado</b><small>${st.done} de ${st.total} exercícios dominados</small><span class="mbar"><i style="width:${st.pct}%"></i></span></span><span class="mh-go">${ico('chev-r')}</span></button>`;
  return (rec.length?`<div class="dk">RECENTES</div><div class="pill" style="margin:0">${rec.map(x=>`<button data-act="goPage" data-p="${x[0]}">${ico(x[1])} ${x[2]}</button>`).join('')}</div>`:'')
   +MGROUPS.filter(show).map(g=>{const it=MORE.filter(x=>x[3]===g&&!(g==='Aprender'&&x[0]==='learn'));  /* "learn" aparece como destaque, sem repetir como tile */
     return `<div class="dk">${g.toUpperCase()}</div>${g==='Aprender'?hero:''}<div class="tiles">${it.map(tile).join('')}</div>`}).join('')
}
function moreMenu(){
  moreCat='Tudo';
  let d=new Date().toLocaleDateString('pt-BR',{weekday:'long',day:'numeric',month:'long'});d=d[0].toUpperCase()+d.slice(1);
  openModal(`<div class="mh"><div><h2 style="margin:0">Mais</h2><div class="sub">${esc(d)}</div></div></div><div class="msearch">${ico('search')}<input id="moreQ" type="search" placeholder="Buscar telas e exercícios…" aria-label="Buscar" autocomplete="off" enterkeyhint="search"></div><div class="mchips" id="moreCats">${MCATS.map(c=>`<button type="button" data-c="${c}"${c==='Tudo'?' class="on"':''}>${c}</button>`).join('')}</div><div id="moreBody">${moreBody('')}</div><div class="foot"><button class="btn" data-act="closeModal">Fechar</button></div>`);
  const q=$('#moreQ');q.blur();
  q.addEventListener('input',()=>{$('#moreCats').hidden=!!q.value.trim();$('#moreBody').innerHTML=moreBody(q.value)});
  q.addEventListener('keydown',e=>{if(e.key==='Enter'){e.preventDefault();($('#moreBody .tile')||$('#moreBody .srr'))?.click()}});
  $('#moreCats').addEventListener('click',e=>{const b=e.target.closest('button[data-c]');if(!b)return;moreCat=b.dataset.c;$$('#moreCats button').forEach(x=>x.classList.toggle('on',x===b));$('#moreBody').innerHTML=moreBody('')});
}
function rMakeups(){
  const r=[...db.makeups].sort((a,b)=>String(b.newDate||b.originalDate).localeCompare(String(a.newDate||a.originalDate)));
  $('#mkSub').textContent=`${r.filter(m=>m.status==='Pendente'||m.status==='Agendada').length} em aberto`;
  $('#mkList').innerHTML=r.length?r.map(m=>{
    const s=studentById(m.studentId),open=m.status==='Pendente'||m.status==='Agendada';
    return scard({sid:m.studentId,key:'mk:'+m.id,name:m.studentName||s?.name||'—',badge:m.status,cls:MK_CLS[m.status],sub:`${fmtDate(m.originalDate)} → ${m.newDate?fmtDate(m.newDate)+' '+esc(m.newTime||''):'a definir'}`,
      mini:[['ORIGINAL',fmtDate(m.originalDate)],['NOVA AULA',m.newDate?fmtDate(m.newDate):'—'],['HORÁRIO',esc(m.newTime||'—')]],det:[...stuLine(s),['Observações',esc(m.notes||'—')]],
      acts:(m.status==='Pendente'&&m.newDate&&m.newTime?`<button class="btn sm" data-act="mkToAgenda" data-id="${m.id}">Agendar</button>`:'')+(open?`<button class="btn sm" data-act="mkDone" data-id="${m.id}">Concluir</button>`:'')+`<button class="btn sm" data-act="editMk" data-id="${m.id}">Editar</button><button class="btn sm bad" data-act="delMk" data-id="${m.id}">Excluir</button>`});
  }).join(''):'<div class="card empty">Nenhuma reposição.</div>';
}
function mkModal(id){
  const m=id?db.makeups.find(x=>x.id===id):null;editing=id||null;
  if(!db.students.length)return toast('Cadastre um aluno antes.');
  openModal(`<h2>${m?'Editar reposição':'Nova reposição'}</h2><div class="form">
    <div class="field full"><label for="mkStu">Aluno *</label><select id="mkStu"><option value="">Selecione</option>${stuOpts(m?.studentId)}</select></div>
    <div class="field"><label for="mkOrig">Data original</label><input id="mkOrig" type="date" value="${esc(m?.originalDate||iso(new Date()))}"></div>
    <div class="field"><label for="mkNew">Nova data</label><input id="mkNew" type="date" value="${esc(m?.newDate)}"></div>
    <div class="field"><label for="mkTime">Novo horário</label><select id="mkTime"><option value="">—</option>${opts(db.hours,m?.newTime)}</select></div>
    <div class="field"><label for="mkSt">Status</label><select id="mkSt">${opts(MK_ST,m?.status||'Pendente')}</select></div>
    <div class="field full"><label for="mkNotes">Observações</label><input id="mkNotes" value="${esc(m?.notes)}"></div>
  </div><div class="foot"><button class="btn" data-act="closeModal">Cancelar</button><button class="btn primary" data-act="saveMk">Salvar</button></div>`);
}
function saveMk(){
  const sid=$('#mkStu').value,st=studentById(sid);if(!st)return toast('Selecione o aluno.');
  const o0=$('#mkOrig').value,n0=$('#mkNew').value;if(o0&&n0&&n0<o0)return toast('A nova data não pode ser anterior à original.');
  const old=editing?db.makeups.find(x=>x.id===editing):null;
  const o={...(old||{}),id:old?.id||uid('mk'),studentId:sid,studentName:st.name,originalDate:o0,newDate:n0,newTime:$('#mkTime').value,status:$('#mkSt').value,notes:$('#mkNotes').value.trim(),createdAt:old?.createdAt||new Date().toISOString()};
  if(old)db.makeups[db.makeups.indexOf(old)]=o;else db.makeups.push(o);
  if(!save())return;closeModal();render();toast('Reposição salva.');
}
function mkToAgenda(id){
  const m=db.makeups.find(x=>x.id===id),st=m&&studentById(m.studentId);if(!st)return;
  if(db.classes.some(c=>c.studentId===st.id&&c.date===m.newDate&&c.time===m.newTime&&c.status!=='Cancelada'))return toast('O aluno já tem aula nesse horário.');
  const cap=Number(db.settings.capacity)||4;
  if(slotCount(m.newDate,m.newTime)>=cap&&!confirm(`Horário lotado (${cap} vagas). Agendar mesmo assim?`))return;
  const c={id:uid('cls'),date:m.newDate,time:m.newTime,studentId:st.id,studentName:st.name,teacher:st.teacher||'',status:'Agendada',notes:'Reposição',duration:db.settings.duration,makeupId:m.id,equipmentId:eqPick(st.id,m.newDate,m.newTime)};
  db.classes.push(c);m.status='Agendada';m.classId=c.id;save();render();toast('Aula de reposição criada na Agenda.');
}
function mkDone(id){
  const m=db.makeups.find(x=>x.id===id);if(!m)return;m.status='Realizada';
  const c=m.classId&&classById(m.classId);if(c)c.status='Realizada';
  save();render();toast('Reposição concluída.');
}
function delMk(id){
  const m=db.makeups.find(x=>x.id===id);if(!m||!confirm('Excluir esta reposição?'))return;
  const c=m.classId&&classById(m.classId);if(c&&c.status==='Agendada')db.classes=db.classes.filter(x=>x.id!==c.id);
  db.makeups=db.makeups.filter(x=>x.id!==id);save();render();toast('Reposição excluída.');
}

function rWait(){
  const r=db.waitlist.filter(w=>w.status!=='Convertido'&&w.status!=='Cancelado').sort((a,b)=>(a.priority||3)-(b.priority||3)||String(a.createdAt).localeCompare(String(b.createdAt)));
  $('#wtSub').textContent=`${r.length} aguardando`;
  $('#wtList').innerHTML=r.length?r.map(w=>{
    const wa=waLink(w.whatsapp,'');
    return scard({key:'wt:'+w.id,name:w.name,badge:w.status,cls:w.status==='Contactar'?'warn':'info',sub:`${esc(w.plan||'—')} · ${esc(w.time||'Qualquer horário')}`,
      mini:[['PRIORIDADE',w.priority||3],['PLANO',esc(w.plan||'—')],['HORÁRIO',esc(w.time||'Qualquer')]],
      det:[['WhatsApp',esc(w.whatsapp||'—')],['Entrou em',fmtDate(String(w.createdAt||'').slice(0,10))],['Observações',esc(w.notes||'—')]],
      acts:(wa?`<button class="btn sm wa" data-act="waMsg" data-k="waitlist" data-wid="${w.id}">WhatsApp</button>`:'')+`<button class="btn sm" data-act="wtConv" data-id="${w.id}">Converter</button><button class="btn sm" data-act="editWt" data-id="${w.id}">Editar</button><button class="btn sm bad" data-act="delWt" data-id="${w.id}">Excluir</button>`});
  }).join(''):'<div class="card empty">Lista de espera vazia.</div>';
}
function wtModal(id){
  const w=id?db.waitlist.find(x=>x.id===id):null;editing=id||null;
  openModal(`<h2>${w?'Editar contato':'Novo contato'}</h2><div class="form">
    <div class="field full"><label for="wtName">Nome *</label><input id="wtName" value="${esc(w?.name)}"></div>
    <div class="field"><label for="wtWa">WhatsApp</label><input id="wtWa" type="tel" inputmode="tel" value="${esc(w?.whatsapp)}"></div>
    <div class="field"><label for="wtPlan">Plano desejado</label><select id="wtPlan"><option value="">—</option>${opts(db.plans.map(p=>p.name),w?.plan)}</select></div>
    <div class="field"><label for="wtTime">Horário desejado</label><select id="wtTime"><option value="">Qualquer</option>${opts(db.hours,w?.time)}</select></div>
    <div class="field"><label for="wtPri">Prioridade (1 = alta)</label><select id="wtPri">${[1,2,3,4,5].map(n=>`<option${n===(w?.priority||3)?' selected':''}>${n}</option>`).join('')}</select></div>
    <div class="field"><label for="wtSt">Status</label><select id="wtSt">${opts(WT_ST,w?.status||'Contactar')}</select></div>
    <div class="field full"><label for="wtNotes">Observações</label><input id="wtNotes" value="${esc(w?.notes)}"></div>
  </div><div class="foot"><button class="btn" data-act="closeModal">Cancelar</button><button class="btn primary" data-act="saveWt">Salvar</button></div>`);
}
function saveWt(){
  const name=$('#wtName').value.trim();if(!name)return toast('Informe o nome.');
  const old=editing?db.waitlist.find(x=>x.id===editing):null;
  const o={...(old||{}),id:old?.id||uid('wait'),name,whatsapp:$('#wtWa').value.trim(),plan:$('#wtPlan').value,time:$('#wtTime').value,priority:Number($('#wtPri').value)||3,status:$('#wtSt').value,notes:$('#wtNotes').value.trim(),createdAt:old?.createdAt||new Date().toISOString()};
  if(old)db.waitlist[db.waitlist.indexOf(old)]=o;else db.waitlist.push(o);
  if(!save())return;closeModal();render();toast('Contato salvo.');
}
function wtConv(id){
  const w=db.waitlist.find(x=>x.id===id);if(!w)return;
  go('students');studentModal(null,{name:w.name,whatsapp:w.whatsapp,plan:w.plan,time:w.time,notes:w.notes});
  pendingWait=id; // só vira "Convertido" depois que o cadastro do aluno for salvo
}
function delWt(id){if(confirm('Remover este contato?')){db.waitlist=db.waitlist.filter(x=>x.id!==id);save();render();toast('Contato removido.')}}

function rBdays(){
  const now=new Date(),base=new Date(now.getFullYear(),now.getMonth(),now.getDate());
  const l=db.students.filter(x=>x.birth&&(x.status||'Ativo')==='Ativo').map(x=>{
    const [y,m,d]=x.birth.split('-').map(Number);let nx=new Date(base.getFullYear(),m-1,d);if(nx<base)nx=new Date(base.getFullYear()+1,m-1,d);
    return{...x,m,d,age:nx.getFullYear()-y,diff:Math.round((nx-base)/864e5)};
  }).sort((a,b)=>a.diff-b.diff);
  $('#bdSub').textContent=`${l.filter(x=>x.m===base.getMonth()+1).length} neste mês · ${l.filter(x=>x.diff===0).length} hoje`;
  $('#bdBody').innerHTML=l.length?l.slice(0,30).map(x=>{
    const wa=waLink(x.whatsapp,'');
    return scard({key:'bd:'+x.id,name:x.name,badge:x.diff===0?'Hoje':x.diff===1?'Amanhã':`em ${x.diff} dias`,cls:x.diff===0?'ok':'info',sub:`${pad(x.d)}/${pad(x.m)} · fará ${x.age} anos`,
      mini:[['ANIVERSÁRIO',pad(x.d)+'/'+pad(x.m)],['IDADE',x.age],['FALTAM',x.diff===0?'hoje':x.diff+' dia(s)']],det:stuLine(x),
      acts:(wa?`<button class="btn sm wa" data-act="waMsg" data-k="birthday" data-sid="${x.id}">Parabenizar</button>`:'<span class="sub">sem WhatsApp</span>')+`<button class="btn sm" data-act="editStudent" data-id="${x.id}">Editar</button>`});
  }).join(''):'<div class="card empty">Nenhum aniversário cadastrado.</div>';
}
Object.assign(ACT,{
  goPage:e=>{closeModal();go(e.dataset.p)},
  newMk:()=>mkModal(),editMk:e=>mkModal(e.dataset.id),saveMk,mkToAgenda:e=>mkToAgenda(e.dataset.id),mkDone:e=>mkDone(e.dataset.id),delMk:e=>delMk(e.dataset.id),
  newWt:()=>wtModal(),editWt:e=>wtModal(e.dataset.id),saveWt,wtConv:e=>wtConv(e.dataset.id),delWt:e=>delWt(e.dataset.id)
});


/* ========== HORÁRIOS / OCUPAÇÃO ========== */
const ORDER=['1','2','3','4','5','6','0'];
const hourDays=h=>{const v=db.hourDays[h];return Array.isArray(v)&&v.length?v.map(String):['1','2','3','4','5']};
function rHours(){
  $('#hoursBody').innerHTML=db.hours.map(h=>{
    const ds=hourDays(h),n=activeStudents().filter(x=>x.time===h).length;
    return `<div class="item" style="align-items:flex-start;flex-wrap:wrap"><div style="min-width:70px"><b>${esc(h)}</b><div class="sub">${n} aluno${n===1?'':'s'}</div></div>
    <div class="pill" style="margin:0;flex:1;justify-content:flex-end">${ORDER.map(d=>`<button data-act="toggleHD" data-h="${esc(h)}" data-d="${d}" class="${ds.includes(d)?'on':''}" aria-pressed="${ds.includes(d)}">${DAY[d]}</button>`).join('')}</div></div>`;
  }).join('')||'<div class="empty">Nenhum horário cadastrado. Adicione em Configurações.</div>';
}
function toggleHD(h,d){
  const ds=new Set(hourDays(h));ds.has(d)?ds.delete(d):ds.add(d);
  if(!ds.size)return toast('Mantenha ao menos um dia no horário.');
  db.hourDays[h]=ORDER.filter(x=>ds.has(x));
  const cut=activeStudents().filter(x=>x.time===h&&normDays(x.days).includes(d)&&!ds.has(d)).length;
  save();rHours();toast(cut?`${cut} aluno(s) ficam fora da grade nesse dia.`:'Horário atualizado.');
}
const DAYF={0:'Domingo',1:'Segunda',2:'Terça',3:'Quarta',4:'Quinta',5:'Sexta',6:'Sábado'};
const occNorm=v=>String(v||'').normalize('NFD').replace(/[\u0300-\u036f]/g,'').toLowerCase().trim();
const occByName=(a,b)=>String(a.name).localeCompare(String(b.name),'pt-BR');
const occDays=s=>{const d=normDays(s.days);return d.length?d.map(x=>DAY[x]).join(' · '):'sem dias'};
const occRow=(s,sub,acts)=>`<div class="item occr"><div class="occn">${stuAv(s,s.name,'sm')}<div><b>${esc(s.name)}</b><div class="sub">${sub}</div></div></div><div class="occa">${acts}</div></div>`;
const occEdit=s=>`<button type="button" class="btn sm" data-act="editStudent" data-id="${s.id}">Editar</button>`;
const occOpen=new Set();let occM={h:'',d:'',add:false,q:''};
function occStats(){
  const cap=Math.max(0,Number(db.settings.capacity)||0),offered=new Set(),cells={},per={},who={},noSchedL=[],outM=new Map();let noSched=0,outside=0;
  db.hours.forEach(h=>{per[h]={cap:0,used:0,over:0};hourDays(h).forEach(d=>{offered.add(h+'|'+d);per[h].cap+=cap})});
  activeStudents().forEach(x=>{
    const ds=normDays(x.days);if(!ds.length||!x.time){noSched++;noSchedL.push(x);return}
    ds.forEach(d=>{const k=x.time+'|'+d;if(offered.has(k)){cells[k]=(cells[k]||0)+1;(who[k]||(who[k]=[])).push(x)}else{outside++;const m=outM.get(x.id)||{s:x,days:[]};m.days.push(d);outM.set(x.id,m)}});
  });
  let used=0,over=0;
  Object.entries(cells).forEach(([k,n])=>{const h=k.split('|')[0];used+=Math.min(n,cap);over+=Math.max(0,n-cap);per[h].used+=Math.min(n,cap);per[h].over+=Math.max(0,n-cap)});
  Object.values(who).forEach(l=>l.sort(occByName));noSchedL.sort(occByName);
  const capacity=offered.size*cap;
  return{cap,capacity,used,free:capacity-used,pct:capacity?used/capacity*100:0,over,noSched,outside,cells,offered,per,who,noSchedL,outsideL:[...outM.values()].sort((x,y)=>occByName(x.s,y.s))};
}
function rOcc(){
  const o=occStats(),q=occNorm($('#occQ')?.value),tdw=String(new Date().getDay());
  $('#oCap').textContent=o.capacity;$('#oUsed').textContent=o.used;$('#oFree').textContent=o.free;$('#oPct').textContent=Math.round(o.pct)+'%';
  const w=[],wb=(c,k,t)=>`<button type="button" class="badge ${c}" data-act="occIssue" data-k="${k}">${t}</button>`;
  if(o.over)w.push(wb('bad','over',`${o.over} vaga(s) acima da capacidade`));
  if(o.outside)w.push(wb('warn','outside',`${o.outside} presença(s) fora da grade de horários`));
  if(o.noSched)w.push(wb('warn','nosched',`${o.noSched} aluno(s) sem dia ou horário`));
  $('#oWarn').innerHTML=w.length?`<div class="occw">${w.join('')}</div>`:'';
  const hit=new Set(),found=q?activeStudents().filter(s=>occNorm(s.name).includes(q)).sort(occByName):[];
  if(q)Object.entries(o.who).forEach(([k,l])=>{if(l.some(s=>found.includes(s)))hit.add(k)});
  $('#occFind').innerHTML=!q?'':found.length?'<div class="sub" style="margin:6px 0">Os horários dele(a) ficam destacados na grade.</div>'+found.slice(0,8).map(s=>occRow(s,normDays(s.days).length&&s.time?`${occDays(s)} às ${esc(s.time)}`:'Sem dia ou horário definido',occEdit(s))).join('')+(found.length>8?`<div class="sub" style="padding-top:6px">+ ${found.length-8} aluno(s). Refine a busca.</div>`:''):'<div class="empty" style="padding:12px">Nenhum aluno ativo com esse nome.</div>';
  $('#occGrid').innerHTML='<div class="h"></div>'+ORDER.map(d=>`<div class="h${d===tdw?' today':''}">${DAY[d]}</div>`).join('')+db.hours.map(h=>
    `<div class="h">${esc(h)}</div>`+ORDER.map(d=>{
      const k=h+'|'+d;if(!o.offered.has(k))return'<div class="off">—</div>';
      const n=o.cells[k]||0,cls=n>o.cap?'o3':n===o.cap&&o.cap?'o2':n?'o1':'';
      return `<button type="button" class="${cls}${hit.has(k)?' hit':''}" data-act="occCell" data-h="${esc(h)}" data-d="${d}" aria-label="${DAYF[d]} ${esc(h)}: ${n} de ${o.cap} vagas">${n}/${o.cap}</button>`}).join('')).join('');
  $('#occHours').innerHTML=db.hours.map(h=>{const x=o.per[h],pc=x.cap?Math.round(x.used/x.cap*100):0,st=activeStudents().filter(s=>s.time===h).sort(occByName);
    return `<details class="oh" data-h="${esc(h)}"${occOpen.has(h)?' open':''}><summary><b>${esc(h)}</b><div class="bar ${x.over?'bad':pc>=100?'warn':''}"><i style="width:${Math.min(100,pc)}%"></i></div><span class="sub">${x.used}/${x.cap} · ${pc}%</span></summary>${st.length?st.map(s=>occRow(s,`${occDays(s)}${s.teacher?' · '+esc(s.teacher):''}`,occEdit(s))).join(''):'<div class="sub" style="padding:4px 0 10px">Nenhum aluno neste horário.</div>'}</details>`}).join('')||'<div class="empty">Sem horários.</div>';
}
const occSheet=(html,focus)=>{const lf=$('#modal').hidden?null:lastFocus;openModal(html);if(lf)lastFocus=lf;const a=document.activeElement;if(!focus&&a&&a.matches('#sheet input'))a.blur()};
function occSlotModal(h,d,keep){
  const o=occStats(),k=h+'|'+d;if(!o.offered.has(k))return toast('Esse horário não funciona nesse dia.');
  if(!keep)occM={h,d,add:false,q:''};
  const l=o.who[k]||[],n=l.length,cap=o.cap,free=Math.max(0,cap-n),pc=cap?Math.min(100,Math.round(n/cap*100)):0;
  occSheet(`<h2>${DAYF[d]} · ${esc(h)}</h2><div class="occm"><div class="bar ${n>cap?'bad':n===cap&&cap?'warn':'ok'}"><i style="width:${pc}%"></i></div><div class="sub">${n} de ${cap} vaga${cap===1?'':'s'} · ${free} livre${free===1?'':'s'}${n>cap?` <span class="badge bad">${n-cap} acima da capacidade</span>`:''}</div></div>
  <div class="dk">ALUNOS NESTE HORÁRIO</div>${l.length?l.map(s=>occRow(s,`${occDays(s)}${s.teacher?' · '+esc(s.teacher):''}`,occEdit(s)+`<button type="button" class="btn sm bad" data-act="occRemove" data-id="${s.id}" data-h="${esc(h)}" data-d="${d}">Remover</button>`)).join(''):'<div class="empty" style="padding:14px">Nenhum aluno neste horário.</div>'}
  <div class="occadd"><button type="button" class="btn primary" data-act="occAddOpen">+ Adicionar aluno</button></div><div id="occAdd"></div>`);
  if(occM.add)occAddRender();
}
function occAddRender(){
  const box=$('#occAdd');if(!box)return;const bt=$('.occadd .btn');if(bt)bt.textContent=occM.add?'Fechar busca':'+ Adicionar aluno';
  if(!occM.add){box.innerHTML='';return}
  box.innerHTML=`<div class="field" style="margin-top:10px"><label for="occAddQ">Buscar aluno</label><input id="occAddQ" type="search" autocomplete="off" placeholder="Nome do aluno" value="${esc(occM.q)}"></div><div id="occAddL"></div>`;
  occAddList();$('#occAddQ').focus();
}
function occAddList(){
  const box=$('#occAddL');if(!box)return;const {h,d}=occM,q=occNorm(occM.q),o=occStats(),inS=new Set((o.who[h+'|'+d]||[]).map(s=>s.id));
  const rk=s=>s.time===h?0:(!s.time||!normDays(s.days).length)?1:2;
  const c=activeStudents().filter(s=>!inS.has(s.id)&&(!q||occNorm(s.name).includes(q))).sort((a,b)=>rk(a)-rk(b)||occByName(a,b));
  box.innerHTML=c.length?c.slice(0,40).map(s=>{const r=rk(s);
    return occRow(s,r===0?`Já treina às ${esc(h)} (${occDays(s)})`:r===1?'Sem horário definido':`Treina às ${esc(s.time)} (${occDays(s)}) · passaria para ${esc(h)}`,`<button type="button" class="btn sm primary" data-act="occAdd" data-id="${s.id}" data-h="${esc(h)}" data-d="${d}">${r===2?'Mover':'Adicionar'}</button>`)}).join('')+(c.length>40?`<div class="sub" style="padding-top:6px">+ ${c.length-40} aluno(s). Refine a busca.</div>`:''):'<div class="empty" style="padding:14px">Nenhum aluno disponível.</div>';
}
function occAdd(id,h,d){
  const s=studentById(id);if(!s)return;
  const o=occStats(),n=(o.who[h+'|'+d]||[]).length,nd=normDays([...normDays(s.days),d]),bad=nd.filter(x=>!o.offered.has(h+'|'+x)),m=[];
  if(n>=o.cap)m.push(`${DAYF[d]} às ${h} está lotado (${n}/${o.cap}).`);
  if(s.time&&s.time!==h)m.push(`${s.name} treina às ${s.time}; todos os dias dele passam para ${h}.`);
  if(bad.length)m.push(`${h} não funciona em: ${bad.map(x=>DAYF[x]).join(', ')}.`);
  if(m.length&&!confirm(m.join('\n')+'\n\nConfirmar mesmo assim?'))return;
  s.time=h;s.days=nd;s.updatedAt=new Date().toISOString();
  if(!save())return;occM.add=false;occM.q='';render();occSlotModal(h,d,true);toast(`${s.name} entrou em ${DAYF[d]} às ${h}.`);
}
function occRemove(id,h,d){
  const s=studentById(id);if(!s)return;const ds=normDays(s.days);
  if(ds.length<=1)return toast('Esse é o único dia do aluno. Use Editar para mudar o horário ou o status.');
  const pl=db.plans.find(x=>x.name===s.plan),w=pl&&Number(pl.weekly);
  if(!confirm(`Remover ${s.name} de ${DAYF[d]} às ${h}? Os outros dias continuam.`+(w&&ds.length-1!==w?`\nO plano dele prevê ${w}x por semana.`:'')))return;
  s.days=ds.filter(x=>x!==d);s.updatedAt=new Date().toISOString();
  if(!save())return;render();occSlotModal(h,d,true);toast('Aluno removido do horário.');
}
function occIssueModal(kind){
  const o=occStats();let t,r='';
  if(kind==='over'){t='Acima da capacidade';db.hours.forEach(h=>ORDER.forEach(d=>{const n=(o.who[h+'|'+d]||[]).length;if(o.offered.has(h+'|'+d)&&n>o.cap)r+=`<div class="item"><div><b>${DAYF[d]} · ${esc(h)}</b><div class="sub">${n} alunos para ${o.cap} vaga${o.cap===1?'':'s'} (+${n-o.cap})</div></div><button type="button" class="btn sm" data-act="occCell" data-h="${esc(h)}" data-d="${d}">Ver alunos</button></div>`}))}
  else if(kind==='outside'){t='Fora da grade de horários';r=o.outsideL.map(x=>occRow(x.s,`${x.days.map(d=>DAYF[d]).join(', ')} às ${esc(x.s.time)} · ${db.hours.includes(x.s.time)?'horário não funciona nesses dias':'horário não existe em Horários'}`,occEdit(x.s))).join('')}
  else{t='Alunos sem dia ou horário';r=o.noSchedL.map(s=>occRow(s,!s.time&&!normDays(s.days).length?'Sem dia e sem horário':!s.time?`Sem horário · ${occDays(s)}`:`Sem dia · ${esc(s.time)}`,occEdit(s))).join('')}
  occSheet(`<h2>${t}</h2>${r||'<div class="empty">Nada pendente.</div>'}`);
}
$('#occQ').addEventListener('input',rOcc);
$('#occHours').addEventListener('toggle',e=>{const h=e.target.dataset&&e.target.dataset.h;if(h===undefined)return;e.target.open?occOpen.add(h):occOpen.delete(h)},true);
document.addEventListener('input',e=>{if(e.target.id==='occAddQ'){occM.q=e.target.value;occAddList()}});
Object.assign(ACT,{toggleHD:e=>toggleHD(e.dataset.h,e.dataset.d),
  occCell:e=>occSlotModal(e.dataset.h,e.dataset.d),occIssue:e=>occIssueModal(e.dataset.k),
  occAddOpen:()=>{occM.add=!occM.add;occAddRender()},occAdd:e=>occAdd(e.dataset.id,e.dataset.h,e.dataset.d),occRemove:e=>occRemove(e.dataset.id,e.dataset.h,e.dataset.d),
  occOf:e=>{const s=studentById(e.dataset.id);if(!s)return;$('#occQ').value=s.name;closeModal();go('occupancy')}});


/* ========== PROFESSORES ========== */
let tMonth=new Date();
const tKey=()=>ym(tMonth);
const allTeachers=()=>[...new Set([...db.teachers,...db.classes.map(c=>c.teacher).filter(Boolean)])];
function tModel(t,key){
  const st=db.settings,rows=db.classes.filter(c=>c.teacher===t&&String(c.date).startsWith(key)),done=rows.filter(c=>c.status==='Realizada');
  const rate=Number(st.teacherRates[t]||0),fixed=Number(st.teacherFixedRates[t]||0),per=Number(st.teacherClassValues[t]||0);
  const base=done.reduce((a,c)=>a+Number(c.classValue||c.value||per),0);
  return{done:done.length,cancel:rows.filter(c=>c.status==='Cancelada').length,students:new Set(done.map(c=>c.studentId)).size,rate,fixed,per,base,total:base*rate/100+fixed};
}
function rTeachers(){
  const key=tKey(),rows=allTeachers().map(t=>({t,...tModel(t,key)})),cl=db.teacherClosings[key],tot=rows.reduce((a,x)=>a+x.total,0);
  $('#tTitle').textContent=monthName(tMonth);
  $('#tDone').textContent=rows.reduce((a,x)=>a+x.done,0);$('#tCancel').textContent=rows.reduce((a,x)=>a+x.cancel,0);$('#tTotal').textContent=money(tot);
  $('#tStatus').innerHTML=cl?`<span class="badge ${Math.abs(cl.total-tot)<.005?'ok':'warn'}">Fechado em ${fmtDate(cl.closedAt.slice(0,10))}${Math.abs(cl.total-tot)<.005?'':' · alterado depois'}</span>`:'';
  $('#tCloseBtn').dataset.act=cl?'tOpen':'tClose';$('#tCloseBtn').textContent=cl?'Reabrir mês':'Fechar mês';
  $('#tList').innerHTML=rows.length?rows.map(x=>scard({key:'tc:'+x.t,name:x.t,badge:money(x.total),cls:x.total>0?'ok':'',sub:`${x.rate}%${x.fixed?' + '+money(x.fixed)+' fixo':''} de repasse`,
    mini:[['REALIZADAS',x.done],['CANCELADAS',x.cancel],['ALUNOS',x.students]],det:[...tpDet(x.t),['Base (aulas × valor)',money(x.base)],['Valor por aula',money(x.per)],['Repasse %',x.rate+'%'],['Valor fixo',money(x.fixed)],['Repasse total',money(x.total)]],
    acts:`<button class="btn sm" data-act="tEdit" data-t="${esc(x.t)}">Taxas</button><button class="btn sm" data-act="tpEdit" data-t="${esc(x.t)}">Perfil</button>`})).join(''):'<div class="card empty">Nenhum professor cadastrado.</div>';
  const f=$('#tFilter'),cur=f.value;f.innerHTML='<option value="">Todos</option>'+allTeachers().map(t=>`<option${t===cur?' selected':''}>${esc(t)}</option>`).join('');
  const td=db.classes.filter(c=>c.date===iso(new Date())&&c.status!=='Cancelada'&&(!f.value||c.teacher===f.value)).sort(sortCls);
  $('#tToday').innerHTML=td.length?td.map(c=>rowStu(c.studentName,`${esc(c.time)} · ${esc(c.teacher||'—')}`,`<span class="badge ${STATUS_CLS[c.status]||''}">${esc(c.status)}</span>`)).join(''):'<div class="empty">Sem aulas hoje.</div>';
}
function tModal(t){
  const m=tModel(t,tKey());editing=t;
  openModal(`<h2>Taxas — ${esc(t)}</h2><div class="form">
    <div class="field"><label for="tRate">Repasse (% sobre a base)</label><input id="tRate" type="number" min="0" max="100" step="0.1" value="${m.rate}"></div>
    <div class="field"><label for="tFixed">Valor fixo mensal (R$)</label><input id="tFixed" type="number" min="0" step="0.01" value="${m.fixed}"></div>
    <div class="field full"><label for="tPer">Valor por aula realizada (R$)</label><input id="tPer" type="number" min="0" step="0.01" value="${m.per}"></div>
  </div><div class="sub" style="margin-top:8px">Repasse = (aulas realizadas × valor por aula) × % + valor fixo.</div>
  <div class="foot"><button class="btn" data-act="closeModal">Cancelar</button><button class="btn primary" data-act="tSave">Salvar</button></div>`);
}
function tSave(){
  const r=Number($('#tRate').value||0),f=Number($('#tFixed').value||0),v=Number($('#tPer').value||0);
  if(!(r>=0&&r<=100)||f<0||v<0)return toast('Valores inválidos. O percentual vai de 0 a 100.');
  const st=db.settings;st.teacherRates[editing]=r;st.teacherFixedRates[editing]=f;st.teacherClassValues[editing]=v;
  if(!save())return;closeModal();render();toast('Taxas salvas.');
}
function tClose(){
  const key=tKey(),rows=allTeachers().map(t=>({teacher:t,...tModel(t,key)}));
  db.teacherClosings[key]={closedAt:new Date().toISOString(),total:rows.reduce((a,x)=>a+x.total,0),classes:rows.reduce((a,x)=>a+x.done,0),teachers:rows.map(x=>({teacher:x.teacher,total:x.total,classes:x.done}))};
  save();render();toast('Fechamento registrado.');
}

/* ========== ALERTAS ========== */
let alType='all';
function studioAlerts(){
  const a=[],today=iso(new Date()),day=n=>iso(new Date(Date.now()+n*864e5)),soon=day(3),rev=day(7),from=day(-30);
  db.finance.filter(f=>!isExp(f)&&f.status!=='Pago'&&f.dueDate).forEach(f=>{
    const x=`${f.studentName||'Aluno'} · ${money(f.value)} · ${fmtDate(f.dueDate)}`;
    if(f.dueDate<today)a.push({id:'overdue-'+f.id,sid:f.studentId,fid:f.id,type:'overdue',title:'Mensalidade atrasada',text:x,page:'billing'});
    else if(f.dueDate<=soon)a.push({id:'due-'+f.id,sid:f.studentId,fid:f.id,type:'due',title:'Mensalidade vencendo',text:x,page:'billing'});
  });
  const tracking=db.classes.some(c=>c.date>=from&&c.status==='Realizada');
  activeStudents().forEach(x=>{
    const ds=normDays(x.days),enrolled=(x.startDate||String(x.createdAt||'').slice(0,10)||'0000')<=from;
    if(tracking&&enrolled&&ds.length){
      const n=db.classes.filter(c=>c.studentId===x.id&&c.date>=from&&c.date<=today&&c.status==='Realizada').length,exp=Math.max(1,Math.round(ds.length*4.33));
      if(n<Math.max(1,Math.floor(exp*.6)))a.push({id:'freq-'+x.id,sid:x.id,type:'frequency',title:'Baixa frequência',text:`${x.name} · ${n} de ~${exp} aulas em 30 dias`,page:'students'});
    }
    const r=x.clinical?.nextReview;if(r&&r>=today&&r<=rev)a.push({id:'review-'+x.id,sid:x.id,type:'review',title:'Reavaliação próxima',text:`${x.name} · ${fmtDate(r)}`,page:'evolution'});
  });
  if(activeEq().length){const byD={};db.classes.filter(c=>c.date>=today&&c.date<=rev&&(c.status==='Agendada'||c.status==='Confirmada')&&!c.equipmentId).forEach(c=>byD[c.date]=(byD[c.date]||0)+1);
    Object.entries(byD).forEach(([d,n])=>a.push({id:'equip-'+d,type:'equipment',title:'Aulas sem aparelho',text:`${n} aula${n>1?'s':''} em ${fmtDate(d)}`,page:'equipment'}))}
  db.finance.filter(f=>!isExp(f)&&f.status==='Pago'&&f.paidAt&&f.paidAt>=day(-7)).forEach(f=>a.push({id:'paid-'+f.id,sid:f.studentId,fid:f.id,type:'paid',title:'Pagamento recebido',text:`${f.studentName||'Aluno'} · ${money(f.value)}`,page:'finance'}));
  if(activeEq().length>1)db.students.filter(s=>(s.status||'Ativo')==='Ativo').forEach(s=>{
    const q=db.classes.filter(c=>c.studentId===s.id&&c.equipmentId&&!['Cancelada','Falta'].includes(c.status)&&c.date>=from&&c.date<=rev).sort(sortCls);
    for(let i=q.length-1;i>0;i--)if(q[i].equipmentId===q[i-1].equipmentId){const e=eqById(q[i].equipmentId);
      if(e&&e.active!==false&&q[i].date>=day(-14))a.push({id:`eqrep-${s.id}-${q[i].date}`,sid:s.id,type:'equipment',title:'Aparelho repetido',text:`${e.name} em ${fmtDate(q[i-1].date)} e ${fmtDate(q[i].date)}`,page:'equipment'});break}});
  return a.map(x=>({...x,dismissed:!!db.alertDismissed[x.id]}));
}
const AL_CLS={overdue:'bad',due:'warn',frequency:'warn',review:'info',paid:'ok',equipment:'info'};
function rAlerts(){
  const all=studioAlerts(),on=all.filter(x=>!x.dismissed),list=on.filter(x=>alType==='all'||x.type===alType);
  $('#alSub').textContent=`${on.filter(x=>x.type!=='paid').length} pendências · ${all.length-on.length} dispensados`;
  $('#alBody').innerHTML=list.length?list.map(x=>{
    const s=x.sid&&studentById(x.sid),ed=x.fid?`<button class="btn sm" data-act="alEdit" data-k="fin" data-id="${x.fid}">Editar</button>`:s?`<button class="btn sm" data-act="alEdit" data-k="stu" data-id="${s.id}">Editar</button>`:'',acts=`<button class="btn sm" data-act="alGo" data-p="${x.page}">Abrir</button>${ed}<button class="btn sm" data-act="alDismiss" data-id="${esc(x.id)}">Dispensar</button>`;
    return scard({compact:true,key:'al:'+x.id,name:s?s.name:x.title,av:s?'':'🏋',badge:s?x.title:'',cls:AL_CLS[x.type],sub:esc(x.text),acts});
  }).join(''):'<div class="card empty">Nenhum alerta. Tudo em dia! ✓</div>';
}
Object.assign(ACT,{
  tPrev:()=>{tMonth=new Date(tMonth.getFullYear(),tMonth.getMonth()-1,1);render()},tNext:()=>{tMonth=new Date(tMonth.getFullYear(),tMonth.getMonth()+1,1);render()},
  tEdit:e=>tModal(e.dataset.t),tSave,tClose,tOpen:()=>{delete db.teacherClosings[tKey()];save();render();toast('Mês reaberto.')},
  alGo:e=>go(e.dataset.p),alDismiss:e=>{db.alertDismissed[e.dataset.id]=true;save();render()},
  alRestore:()=>{db.alertDismissed={};save();render();toast('Alertas restaurados.')}
});
$('#tFilter').addEventListener('change',rTeachers);
$('#alFilter').addEventListener('click',e=>{const b=e.target.closest('button');if(!b)return;alType=b.dataset.f;$$('button',$('#alFilter')).forEach(x=>x.classList.toggle('on',x===b));rAlerts()});


/* ========== EVOLUÇÃO ========== */
let evoStu=null;
const CF=[['complaint','Queixa principal','ta'],['objective','Objetivo','ta'],['diagnosis','Diagnóstico','tx'],['medicalHistory','Histórico médico','ta'],['contraindications','Contraindicações','ta'],['alerts','Alertas clínicos','ta'],['baselineDate','Avaliação inicial','date'],['nextReview','Próxima reavaliação','date'],['painScore','Dor atual (0–10)','n'],['painLocation','Local da dor','tx'],['functionalScore','Funcional (0–10)','n'],['postureScore','Postura (0–10)','n'],['mobilityScore','Mobilidade (0–10)','n'],['strengthScore','Força (0–10)','n'],['balanceScore','Equilíbrio (0–10)','n'],['controlScore','Controle motor (0–10)','n'],['frequency','Frequência recomendada','tx'],['plan','Plano de tratamento','ta'],['homecare','Orientações para casa','ta']];
const EF=[['title','Título','tx'],['date','Data','date'],['complaint','Queixa / relato','ta'],['objective','Objetivo da sessão','ta'],['assessment','Avaliação','ta'],['painBefore','Dor antes (0–10)','n'],['painAfter','Dor depois (0–10)','n'],['functionalScore','Funcional (0–10)','n'],['mobilityScore','Mobilidade (0–10)','n'],['strengthScore','Força (0–10)','n'],['balanceScore','Equilíbrio (0–10)','n'],['controlScore','Controle (0–10)','n'],['exercises','Exercícios realizados','ta'],['intervention','Intervenção','ta'],['response','Resposta do aluno','ta'],['nextSteps','Próximos passos','ta'],['nextReview','Próxima reavaliação','date'],['professional','Profissional','tx']];
const fld=(pf,[k,l,t],v)=>{const id=pf+k,val=esc(v??'');return `<div class="field${t==='ta'?' full':''}"><label for="${id}">${l}</label>${t==='ta'?`<textarea id="${id}" rows="2">${val}</textarea>`:`<input id="${id}" type="${t==='n'?'number':t==='date'?'date':'text'}"${t==='n'?' min="0" max="10" step="1" inputmode="numeric"':''} value="${val}">`}</div>`};
function readFields(pf,defs){
  const o={};
  for(const d of defs){
    const el=$('#'+pf+d[0]),v=el.value.trim();
    if(d[2]==='n'&&v!==''&&!(Number.isInteger(Number(v))&&v>=0&&v<=10)){el.focus();toast(`${d[1].replace(/ \(.*\)/,'')}: use um inteiro de 0 a 10.`);return null}
    o[d[0]]=d[2]==='ta'?el.value.trim():v;
  }
  return o;
}
const evoSorted=x=>[...(x.evolution||[])].sort((a,b)=>String(b.date).localeCompare(String(a.date)));
function rEvo(){
  const st=evoStu&&studentById(evoStu);if(!st)evoStu=null;
  $('#evoList').hidden=!!st;$('#evoDetail').hidden=!st;
  if(!st){
    const q=($('#evoSearch').value||'').trim().toLowerCase(),t=iso(new Date()),soon=iso(new Date(Date.now()+7*864e5));
    const l=db.students.filter(x=>!q||x.name.toLowerCase().includes(q)).sort((a,b)=>a.name.localeCompare(b.name,'pt-BR'));
    $('#evoCards').innerHTML=l.length?l.map(x=>{
      const ev=evoSorted(x),last=ev[0],r=x.clinical?.nextReview,due=r&&r<=soon,pain=last&&last.painAfter!==''&&last.painAfter!=null?last.painAfter+'/10':'—';
      return scard({key:'ev:'+x.id,name:x.name,badge:due?`Reavaliar ${fmtDate(r)}`:'',cls:due&&r<t?'bad':'warn',sub:esc(x.plan||'—'),
        mini:[['REGISTROS',ev.length],['ÚLTIMO',last?fmtDate(last.date):'—'],['DOR',pain]],det:[['Objetivo',esc(x.goal||x.clinical?.objective||'—')],['Diagnóstico',esc(x.clinical?.diagnosis||'—')],['Reavaliação',r?fmtDate(r):'—']],
        acts:`<button class="btn sm primary" data-act="evoPick" data-id="${x.id}">Abrir evolução</button><button class="btn sm" data-act="evoClin" data-id="${x.id}">Editar ficha</button>`});
    }).join(''):'<div class="card empty">Nenhum aluno encontrado.</div>';
    return;
  }
  const c=st.clinical||{},ev=evoSorted(st),asc=[...ev].reverse().filter(e=>e.painAfter!==''&&e.painAfter!=null);
  const sc=[['functionalScore','Funcional'],['postureScore','Postura'],['mobilityScore','Mobilidade'],['strengthScore','Força'],['balanceScore','Equilíbrio'],['controlScore','Controle']].filter(([k])=>c[k]!==''&&c[k]!=null);
  const first=asc[0],last=asc[asc.length-1];
  let svg='';
  if(asc.length>1){
    const W=300,H=90,pts=asc.map((e,i)=>`${(8+i*(W-16)/(asc.length-1)).toFixed(1)},${(H-8-(Number(e.painAfter)/10)*(H-16)).toFixed(1)}`);
    svg=`<svg viewBox="0 0 ${W} ${H}" style="width:100%;max-height:110px" role="img" aria-label="Evolução da dor"><polyline fill="none" stroke="var(--p)" stroke-width="2.5" stroke-linejoin="round" points="${pts.join(' ')}"/>${pts.map(q=>`<circle cx="${q.split(',')[0]}" cy="${q.split(',')[1]}" r="3.5" fill="var(--a)"/>`).join('')}</svg><div class="sub">Dor após a sessão (0–10): de ${first.painAfter} para ${last.painAfter}</div>`;
  }
  $('#evoDetail').innerHTML=`<div class="head"><div><button class="btn sm" data-act="evoBack">← Alunos</button><h1 style="margin-top:8px">${esc(st.name)}</h1><div class="sub">${esc(c.objective||st.goal||'Sem objetivo definido')}</div></div><button class="btn primary" data-act="newEvo">+ Registrar evolução</button></div>
  ${c.alerts||c.contraindications?`<div class="card" style="border-left:4px solid var(--bad)"><b>${ico('alert')} Atenção clínica</b><div class="sub" style="white-space:pre-wrap;color:var(--ink)">${esc([c.alerts,c.contraindications&&'Contraindicações: '+c.contraindications].filter(Boolean).join('\n'))}</div></div>`:''}
  <div class="card"><div class="head" style="margin:0 0 8px"><h2 style="margin:0">Ficha clínica</h2><button class="btn sm" data-act="editClin">Editar ficha</button></div>
    <div class="sub" style="white-space:pre-wrap;color:var(--ink)">${esc([c.complaint&&'Queixa: '+c.complaint,c.diagnosis&&'Diagnóstico: '+c.diagnosis,c.painScore!==''&&c.painScore!=null?`Dor atual: ${c.painScore}/10${c.painLocation?' ('+c.painLocation+')':''}`:'',c.nextReview&&'Reavaliação: '+fmtDate(c.nextReview),c.plan&&'Plano: '+c.plan].filter(Boolean).join('\n')||'Ficha ainda não preenchida.')}</div>
    ${sc.map(([k,l])=>`<div class="item" style="padding:6px 0"><span style="min-width:90px">${l}</span><div class="bar" style="flex:1"><i style="width:${Number(c[k])*10}%"></i></div><b>${c[k]}</b></div>`).join('')}</div>
  ${svg?`<div class="card"><h2>Evolução da dor</h2>${svg}</div>`:''}
  <div class="card"><h2>Registros (${ev.length})</h2>${ev.length?ev.map(e=>`<div class="item" style="align-items:flex-start"><div><b>${esc(e.title||'Evolução da sessão')}</b><div class="sub">${fmtDate(e.date)}${e.professional?' · '+esc(e.professional):''}${e.painBefore!==''&&e.painAfter!==''?` · dor ${esc(e.painBefore)}→${esc(e.painAfter)}`:''}</div>
    ${e.assessment?`<div style="margin-top:4px">${esc(e.assessment)}</div>`:''}${e.nextSteps?`<div class="sub" style="margin-top:2px">Próximos passos: ${esc(e.nextSteps)}</div>`:''}</div>
    <div class="row-acts"><button class="btn sm" data-act="editEvo" data-id="${e.id}">Editar</button><button class="btn sm bad" data-act="delEvo" data-id="${e.id}">Excluir</button></div></div>`).join(''):'<div class="empty">Nenhum registro ainda.</div>'}</div>`;
}
function clinModal(){
  const st=studentById(evoStu);if(!st)return toast('Aluno não encontrado.');const c=st.clinical||{};
  openModal(`<h2>Ficha clínica — ${esc(st.name)}</h2><div class="form">${CF.map(d=>fld('cf_',d,c[d[0]])).join('')}</div><div class="foot"><button class="btn" data-act="closeModal">Cancelar</button><button class="btn primary" data-act="saveClin">Salvar</button></div>`);
}
function saveClin(){
  const st=studentById(evoStu);if(!st)return toast('Aluno não encontrado.');const o=readFields('cf_',CF);if(!o)return;
  st.clinical={...(st.clinical||{}),...o};if(o.objective)st.goal=o.objective;st.updatedAt=new Date().toISOString();
  if(!save())return;closeModal();render();toast('Ficha clínica salva.');
}
function evoModal(id){
  const st=studentById(evoStu);if(!st)return toast('Aluno não encontrado.');const c=st.clinical||{},old=id?(st.evolution||[]).find(e=>e.id===id):null;editing=id||null;
  const v=old||{title:'Evolução da sessão',date:iso(new Date()),objective:c.objective||st.goal||'',nextSteps:c.plan||'',nextReview:c.nextReview||'',professional:st.teacher||''};
  openModal(`<h2>${old?'Editar evolução':'Registrar evolução'} — ${esc(st.name)}</h2><div class="form">${EF.map(d=>fld('ev_',d,v[d[0]])).join('')}</div><div class="foot"><button class="btn" data-act="closeModal">Cancelar</button><button class="btn primary" data-act="saveEvo">Salvar</button></div>`);
}
function saveEvo(){
  const st=studentById(evoStu);if(!st)return toast('Aluno não encontrado.');const o=readFields('ev_',EF);if(!o)return;
  if(!o.date)return toast('Informe a data.');
  if(!Array.isArray(st.evolution))st.evolution=[];
  const old=editing?st.evolution.find(e=>e.id===editing):null;
  const e={...(old||{}),...o,id:old?.id||uid('evo'),studentId:st.id,title:o.title||'Evolução da sessão',pain:o.painAfter};
  if(old)st.evolution[st.evolution.indexOf(old)]=e;else st.evolution.push(e);
  if(o.nextReview)st.clinical={...(st.clinical||{}),nextReview:o.nextReview};
  st.updatedAt=new Date().toISOString();
  if(!save())return;closeModal();render();toast('Evolução salva.');
}
Object.assign(ACT,{
  evoOf:e=>{evoStu=e.dataset.id;go('evolution')},evoPick:e=>{evoStu=e.dataset.id;render();scrollTo(0,0)},evoBack:()=>{evoStu=null;render()},
  editClin:clinModal,saveClin,newEvo:()=>evoModal(),editEvo:e=>evoModal(e.dataset.id),saveEvo,
  delEvo:e=>{const st=studentById(evoStu);if(st&&confirm('Excluir este registro de evolução?')){st.evolution=st.evolution.filter(x=>x.id!==e.dataset.id);save();render();toast('Registro excluído.')}}
});
$('#evoSearch').addEventListener('input',rEvo);


/* ========== GUIA DE EXERCÍCIOS + PERFIL DO ALUNO (v13) ========== */
const GOALS=[['lombar','Lombalgia / estabilização lombopélvica'],['hernia','Hérnia ou protrusão discal (fase de estabilização)'],['cervical','Cervicalgia / tensão cervical'],['postura','Disfunção postural (hiperlordose, ombros protusos)'],['escoli','Escoliose (exercícios de simetria)'],['cifose','Hipercifose torácica / retificação de coluna'],['fibro','Fibromialgia / dor crônica'],['ombro','Reabilitação de ombro (manguito, capsulite)'],['oc','Cintura escapular e cervical (tensão, ergonomia)'],['joelho','Reabilitação de joelho (condromalácia, pós-lesão)'],['quadril','Quadril (bursite, prótese, impacto femoroacetabular)'],['mq','Condicionamento de joelho e quadril'],['pe','Tornozelo e pé (entorse, fascite, propriocepção)'],['pos','Pós-operatório (com liberação médica)'],['gest','Gestação (com liberação obstétrica)'],['diast','Diástase abdominal / pós-parto'],['pelv','Assoalho pélvico (incontinência, prolapso leve)'],['osteo','Osteopenia / osteoporose'],['idoso','Saúde do idoso / sarcopenia'],['equil','Equilíbrio e prevenção de quedas'],['neuro','Controle motor e propriocepção'],['core','Fortalecimento de core'],['flex','Ganho de mobilidade / encurtamentos'],['cond','Condicionamento físico / controle de peso'],['cardio','Saúde cardiometabólica (HAS, diabetes, obesidade)'],['atleta','Performance esportiva / prevenção de lesões'],['rel','Estresse, respiração e consciência corporal'],['resp','Reeducação respiratória']];
const GOAL_GROUPS=[['Coluna e dor',['lombar','hernia','cervical','postura','escoli','cifose','fibro']],['Articulações e reabilitação',['ombro','oc','joelho','quadril','mq','pe','pos']],['Saúde da mulher',['gest','diast','pelv']],['Geriatria e neurofuncional',['osteo','idoso','equil','neuro']],['Condicionamento e bem-estar',['core','flex','cond','cardio','atleta','rel','resp']]];
const goalOpts=sel=>GOAL_GROUPS.map(([g,ks])=>`<optgroup label="${g}">${ks.map(k=>GOALS.find(x=>x[0]===k)).filter(Boolean).map(([k,l])=>`<option value="${k}"${k===sel?' selected':''}>${esc(l)}</option>`).join('')}</optgroup>`).join('');
const CONDS=[['osteo','Osteoporose'],['hernia','Hérnia / protrusão discal'],['gest','Gestante'],['hta','Hipertensão'],['cardio','Cardiopatia'],['pos','Pós-operatório recente'],['artrose','Artrose'],['joelho','Lesão de joelho'],['ombro','Lesão de ombro'],['vert','Labirintite / vertigem'],['lomb','Dor lombar crônica'],['cerv','Dor / hérnia cervical'],['esco','Escoliose'],['diast','Diástase abdominal'],['quadril','Lesão / prótese de quadril'],['glauc','Glaucoma'],['obes','Obesidade'],['diab','Diabetes'],['fibro','Fibromialgia'],['resp','Asma / doença respiratória']];
const MOBS=[['1','Limitada (usa apoio / dificuldade no solo)'],['2','Moderada'],['3','Boa']],LEVELS=[['1','Iniciante'],['2','Intermediário'],['3','Avançado']];
const GX_AP={M:'Solo / Mat',R:'Reformer',C:'Cadillac',H:'Chair',B:'Ladder Barrel',S:'Spine Corrector',A:'Acessórios',F:'Funcional',P:'Ped-O-Pul'};
const GX_RX={R:/reformer/i,C:/cadillac|trap[eé]zio|tower/i,H:/chair|cadeira/i,B:/barrel|barril|ladder/i,S:/spine|corrector|coluna/i};
const GL=Object.fromEntries(GOALS),CL=Object.fromEntries(CONDS),gxLv=['Nível não informado','Básico','Intermediário','Avançado'];
/* nome|aparelhos|objetivos|serve para|nível mínimo de mobilidade|evitar em|ajuste */
const GXC=`Respiração lateral costal|M,R|rel,core,postura,gest|Expande o tórax, ativa o transverso do abdome e reduz a tensão cervical.|1||Pode ser feita sentada.
Ativação do assoalho pélvico + transverso|M|pelv,gest,core,rel|Consciência e força do assoalho pélvico, base da estabilidade lombo-pélvica.|1||Sem prender a respiração; sem empurrar o abdome para fora.
Ponte pélvica (Pelvic Curl)|M,R|lombar,core,pelv,flex,mq|Mobilidade segmentar da coluna, glúteos e estabilidade lombar.|1|pos|Amplitude curta se houver dor; manter pelve estável.
Gato-camelo (Cat Stretch)|M,B|flex,lombar,rel,gest,postura|Mobilidade de coluna em baixa carga e alívio de tensão lombar.|1||Almofada sob joelhos e punhos.
Quadrúpede alternado (Bird-dog)|M,R|lombar,core,postura,osteo,equil|Estabilidade de coluna, glúteo e controle de tronco.|2|ombro|Começar só com os braços ou só com as pernas.
Ostra (Clam)|M|mq,pelv,lombar,gest|Fortalece glúteo médio e estabiliza o quadril.|1||Deitada de lado com apoio sob a cabeça.
Círculo de Pilates entre os joelhos|M|pelv,mq,gest|Adutores e assoalho pélvico; melhora o alinhamento do joelho.|1||Resistência leve; sem dor no joelho.
Retração escapular com faixa|M,R|postura,oc,osteo|Fortalece romboides e trapézio médio; combate a postura protusa.|1||Pode ser sentada; ombros longe das orelhas.
Parede: deslizar braços (Wall Slide)|M|postura,osteo,oc|Alinhamento, extensão torácica e mobilidade de ombro.|1|ombro|Amplitude sem dor, sem arquear a lombar.
Footwork no Reformer|R|mq,equil,lombar,cond,osteo,postura|Força de membros inferiores, alinhamento e carga axial controlada.|1||Mola mais pesada para estabilidade; sem hiperextender os joelhos.
Footwork na Chair (pedal)|H|mq,equil,osteo,lombar|Força de pernas com apoio estável; muito indicado para idosos.|1|joelho|Pedal com mola leve e amplitude reduzida.
Equilíbrio unipodal com apoio|M,H|equil,mq,osteo|Propriocepção e prevenção de quedas.|1|vert|Próximo a barra ou parede; olhar fixo em um ponto.
Remada no Reformer (Rowing / Pull Straps)|R,H|postura,oc,osteo,cond|Fortalece dorsais e escápulas; melhora cifose postural.|1||Carga leve; sem elevar os braços acima de 90° se houver lesão de ombro.
Sereia (Mermaid)|R,H,B|flex,postura,oc|Alongamento lateral do tronco e mobilidade costal.|1||Realizar sentada, sem rodar a coluna.
Rotação de tronco sentada (Spine Twist)|M,H|flex,oc,lombar,postura|Mobilidade rotacional torácica com coluna alta.|1|vert|Coluna longa; rotação suave.
Alongamento posterior no Barrel|B|flex,lombar,postura|Alonga isquiotibiais, panturrilha e cadeia posterior.|1||Apoio de pés estável; sem dor.
Leg Springs (Cadillac)|C|mq,flex,lombar|Mobilidade de quadril com molas de assistência.|1||Molas que sustentam o peso da perna.
Cadillac: Push Through sentada|C|postura,core,oc,flex|Extensão torácica, mobilidade de ombro e ativação abdominal.|2|ombro,pos|Coluna ereta, sem flexão lombar.
Cadillac: Roll Down com barra|C|flex,lombar,postura|Flexão segmentar controlada e alongamento posterior.|2|osteo,hernia,pos|Reduzir a amplitude e evitar carga na flexão.
Extensão em prono (Swan prep.)|M,B,C|postura,osteo,oc|Fortalece extensores da coluna e abre o tórax.|2|gest,pos|Pequena amplitude, pescoço neutro.
Arco no Spine Corrector|S,B|postura,flex,oc|Extensão torácica e abertura da caixa torácica.|2|gest,pos,vert,cardio|Apoio da cabeça e amplitude curta.
Single Leg Stretch|M,R|core,cond,lombar|Estabilidade lombo-pélvica com dissociação de membros.|2|gest,osteo,hernia|Cabeça apoiada, pernas mais altas.
Hundred (pernas na mesa, cabeça apoiada)|M,R|core,cond,rel|Resistência de core e controle respiratório.|2|gest,pos|Cabeça no apoio; joelhos dobrados.
Elephant no Reformer|R|core,flex,postura|Alongamento posterior com ativação de core.|2|ombro,gest,hta|Molas leves; sem apneia.
Série lateral (Side Kick)|M,R|core,mq,cond,equil|Estabilidade pélvica e glúteo médio.|2||Apoio no antebraço; amplitude curta.
Step down na Chair|H|equil,mq,cond|Força excêntrica de pernas e equilíbrio unipodal.|2|joelho,artrose|Degrau baixo, mão apoiada.
Rolling like a Ball|M|core,flex,rel|Massagem da coluna e controle de equilíbrio.|2|osteo,hernia,gest|Segurar atrás dos joelhos e rolar pouco.
Serra (Saw)|M,R|flex,oc,lombar|Rotação com flexão; alonga isquiotibiais e oblíquos.|2|osteo,hernia,pos|Manter coluna alta e rotação curta.
Roll Up|M,C|flex,core|Mobilidade de flexão da coluna e força abdominal.|3|osteo,hernia,gest,pos,hta|Usar o Roll Down assistido com faixa.
Teaser|M,R|core,cond|Força abdominal, equilíbrio e controle.|3|osteo,hernia,gest,pos,hta,cardio|Teaser com joelhos dobrados.
Ponte de ombros (Shoulder Bridge)|M|core,mq,lombar|Glúteos, isquiotibiais e estabilidade pélvica.|3|hernia,pos,gest|Apoiar os pés; quadril baixo.
Jump Board no Reformer|R|cond,osteo|Impacto controlado, estímulo ósseo e condicionamento.|3|joelho,artrose,pos,gest,cardio,hta|Aterrissagem silenciosa, joelhos alinhados.`.split('\n').map(r=>{const[n,a,g,b,lv,av,t]=r.split('|');return{n,a:a.split(','),g:g.split(','),b,lv:+lv,av:av?av.split(','):[],t}});
const GX=GXC;
function gxProfile(s){
  const mob=Number(s.mobility)||2,age=ageOf(s.birth),cond=new Set(s.conditions||[]);
  if(goalsP(s).includes('gest'))cond.add('gest');
  let cap=mob;if(age!==''&&age>=60)cap=Math.min(cap,2);if(cond.has('pos')||cond.has('cardio'))cap=Math.min(cap,2);
  return{mob,age,cond,cap};
}
const gxCheck=(e,pf)=>{const bad=(e.av||[]).filter(c=>pf.cond.has(c));
  if(bad.length)return{k:'avoid',t:'Evitar: '+bad.map(c=>(CL[c]||c).toLowerCase()).join(', ')};
  if(e.lv>pf.cap)return{k:'adapt',t:'Nível acima do indicado: adaptar'};
  return{k:'ok',t:'Compatível com o perfil'}};
function gxPlan(s){
  const {mob,age,cond,cap}=gxProfile(s);
  const ok=[],no=[];
  const gs=[...goalsP(s),...(s.goalKeys2||[])];
  gxLib().filter(e=>gs.some(k=>e.g.includes(k))).forEach(e=>{
    const bad=e.av.filter(c=>cond.has(c));
    if(bad.length)no.push([e,'evitar em: '+bad.map(c=>CL[c].toLowerCase()).join(', ')]);
    else if(e.lv>cap)no.push([e,'nível acima do indicado para a mobilidade/idade']);
    else ok.push(e)});
  ok.sort((a,b)=>a.lv-b.lv);const top=ok.slice(0,7),cnt={};
  top.forEach(e=>e.a.forEach(k=>{if(GX_RX[k])cnt[k]=(cnt[k]||0)+1}));
  const tips=[];
  if(age!==''&&age>=60)tips.push('Idade ≥ 60: priorize apoio (Chair/Cadillac com molas de assistência), transições lentas e níveis básicos.');
  if(age!==''&&age<18)tips.push('Menor de 18: foque em postura, consciência corporal e técnica, com carga leve.');
  if(mob===1)tips.push('Mobilidade limitada: comece sentado ou em pé com apoio e evite longos períodos no solo.');
  if(cond.has('gest'))tips.push('Gestante: exigir liberação médica; evitar decúbito dorsal prolongado após o 1º trimestre e compressão abdominal.');
  if(cond.has('osteo'))tips.push('Osteoporose: evitar flexão e rotação de coluna sob carga; priorizar extensão leve, carga axial e equilíbrio.');
  if(cond.has('hernia'))tips.push('Hérnia discal: evitar flexão lombar sob carga; manter coluna neutra.');
  if(cond.has('hta')||cond.has('cardio'))tips.push('Pressão/coração: evitar apneia e inversões; respiração contínua e progressão lenta.');
  if((cond.has('gest')||cond.has('cardio')||cond.has('pos')||cond.has('hta'))&&s.medClear!=='Liberado'&&s.medClear!=='Não necessária')tips.push('Sem liberação médica registrada para esta condição: iniciar só com exercícios de baixo risco e solicitar o atestado.');
  if(cond.has('vert'))tips.push('Vertigem: evitar mudanças rápidas de posição e de cabeça.');
  if(cond.has('lomb'))tips.push('Dor lombar crônica: coluna neutra, ativar o core antes do movimento; evitar flexão repetida e movimentos balísticos.');
  if(cond.has('cerv'))tips.push('Cervical: manter a cabeça apoiada, não elevar a cabeça com fadiga e evitar inversões.');
  if(cond.has('esco'))tips.push('Escoliose: priorizar simetria e rotações controladas; adaptar conforme a avaliação.');
  if(cond.has('diast'))tips.push('Diástase abdominal: evitar flexões abdominais e pranchas sem liberação; priorizar transverso e respiração.');
  if(cond.has('quadril'))tips.push('Quadril (lesão/prótese): respeitar a amplitude indicada pelo médico; evitar rotações e flexão acima de 90°.');
  if(cond.has('glauc'))tips.push('Glaucoma: evitar inversões e posições com a cabeça abaixo do corpo.');
  if(cond.has('obes'))tips.push('Obesidade: evitar impacto; progressão gradual e com apoio.');
  if(cond.has('diab'))tips.push('Diabetes: orientar o aluno a se alimentar antes da aula e a avisar sintomas de hipoglicemia (tontura, suor frio).');
  if(cond.has('fibro'))tips.push('Fibromialgia: sessões curtas, intensidade baixa a moderada e progressão lenta; respeitar os dias de dor.');
  if(cond.has('resp'))tips.push('Asma / doença respiratória: respiração contínua, pausas e medicação de resgate disponível se prescrita.');
  if(cond.has('artrose')||cond.has('joelho'))tips.push('Joelho / artrose: amplitude sem dor, sem hiperextensão e sem impacto.');
  if(cond.has('ombro'))tips.push('Ombro: evitar elevação acima de 90° sob carga e manter as escápulas estáveis.');
  return{ok:top,no,eq:Object.entries(cnt).sort((a,b)=>b[1]-a[1]).map(x=>x[0]),age,cond:[...cond],tips};
}
const GXCAT=`#M
The Hundred|I|Resistência abdominal
Roll Up|M|Articulação da coluna
Roll Over|A|Controle e mobilidade
Single Leg Circles|I|Mobilidade do quadril
Rolling Like a Ball|M|Controle corporal
Single Leg Stretch|I|Estabilidade abdominal
Double Leg Stretch|M|Coordenação
Single Straight Leg Stretch|M|Controle abdominal
Double Straight Leg Stretch|A|Estabilidade do tronco
Criss Cross|M|Rotação do tronco
Spine Stretch Forward|I|Mobilidade da coluna
Open Leg Rocker|A|Equilíbrio e controle
Corkscrew|A|Controle do tronco
Saw|M|Rotação e mobilidade
Swan|M|Extensão da coluna
Swimming|M|Resistência posterior
Side Kick Series|M|Estabilidade pélvica
Teaser|A|Controle global
Seal|M|Coordenação
Push Up|A|Força e estabilidade
#R
Footwork|I|Alinhamento e força dos membros inferiores
Hundred|M|Resistência abdominal
Coordination|A|Coordenação e estabilidade
Frog|I|Controle dos membros inferiores
Leg Circles|M|Mobilidade do quadril
Short Spine Massage|M|Mobilidade e controle
Long Spine Massage|A|Controle corporal
Stomach Massage|M|Mobilidade e força
Short Box Round|M|Controle do tronco
Short Box Flat|M|Estabilidade
Short Box Side to Side|M|Controle lateral
Elephant|M|Estabilidade e mobilidade
Knee Stretch Round|M|Controle lombo-pélvico
Knee Stretch Arched|A|Controle e extensão
Running|I|Mobilidade dos tornozelos
Pelvic Lift|M|Controle pélvico
Long Stretch|A|Estabilidade global
Down Stretch|A|Extensão e controle
Up Stretch|A|Força e coordenação
Scooter|M|Estabilidade unilateral
Eve's Lunge|M|Mobilidade do quadril
Mermaid|I|Mobilidade lateral
Side Splits|A|Equilíbrio e força
Front Splits|A|Mobilidade e controle
#C
Roll Down Bar|I|Articulação da coluna
Arm Springs|I|Estabilidade dos ombros
Leg Springs|M|Controle dos membros inferiores
Breathing|I|Coordenação respiratória
Push Through|M|Mobilidade da coluna
Tower|M|Controle lombo-pélvico
Monkey|M|Mobilidade posterior
Roll Back|I|Articulação vertebral
Swan|M|Extensão da coluna
Teaser|A|Controle global
Hanging|A|Força e controle corporal
Leg Circles|M|Mobilidade do quadril
Frog|I|Controle dos quadris
Bicycle|M|Coordenação dos membros inferiores
Chest Expansion|I|Estabilidade escapular
Mermaid|I|Mobilidade lateral
Pull Up|A|Força e estabilidade
#H
Footwork|I|Força dos membros inferiores
Pumping|I|Controle do pedal
Standing Pumping|M|Equilíbrio
Seated Pumping|I|Coordenação
Going Up Front|A|Força e equilíbrio
Going Up Side|A|Estabilidade lateral
Swan|M|Extensão da coluna
Mountain Climber|M|Estabilidade
Pike|A|Força abdominal
Teaser|A|Controle global
Mermaid|I|Mobilidade lateral
Side Stretch|M|Controle lateral
Leg Press|I|Força dos membros inferiores
Hamstring Stretch|I|Mobilidade posterior
#B
Swan on Barrel|M|Extensão da coluna
Backbend|M|Mobilidade em extensão
Side Bend|M|Controle lateral
Horseback|M|Estabilidade
Hamstring Stretch|I|Mobilidade posterior
#S
Mermaid|I|Mobilidade lateral
Swan Prep|M|Extensão
Abdominal Curl|M|Controle abdominal
Scissors|M|Coordenação
Bicycle|M|Mobilidade dos quadris
Shoulder Bridge|M|Estabilidade pélvica
Chest Expansion|I|Mobilidade torácica
#A
Chest Squeeze (Magic Circle)|I|
Inner Thigh Press (Magic Circle)|I|
Arm Press (Magic Circle)|I|
Bridge (Bola suíça)|I|
Hamstring Curl (Bola suíça)|I|
Wall Squat (Bola suíça)|I|
Roll Out (Bola suíça)|I|
Pelvic Curl (Mini Ball)|I|
Abdominal Curl (Mini Ball)|I|
Adductor Squeeze (Mini Ball)|I|
Arm Pull (Faixa elástica)|I|
Leg Press (Faixa elástica)|I|
Shoulder Mobility (Faixa elástica)|I|
Balance (Foam Roller)|I|
Bridge (Foam Roller)|I|
Thoracic Extension (Foam Roller)|I|
Arm Circles (Halteres)|I|
Biceps Curl (Halteres)|I|
Lateral Raise (Halteres)|I|
Abdominal Prep (Overball)|I|
Spine Mobility (Overball)|I|
Leg Press (Overball)|I|
Standing Balance (Disco de equilíbrio)|I|
Squat (Disco de equilíbrio)|I|
Single Leg Balance (Disco de equilíbrio)|I|
#F
Bridge|I|Estabilidade pélvica
Shoulder Bridge|M|Controle do tronco
Bird Dog|I|Estabilidade
Dead Bug|I|Controle abdominal
Plank|M|Estabilidade global
Side Plank|M|Força lateral
Squat|I|Força funcional
Lunge|M|Equilíbrio
Standing Leg Extension|I|Controle unilateral
Hip Hinge|I|Controle do quadril
Clam|I|Controle do quadril
Wall Roll Down|I|Mobilidade vertebral`;
const nz=s=>norm(s).replace(/[^a-z0-9]+/g,' ').trim(),fam=a=>a==='F'?'M':a;
const GXFICHA={o:'Desenvolver controle abdominal e coordenação dos movimentos dos membros inferiores.',pos:'Decúbito dorsal, tronco estabilizado, cabeça e ombros elevados conforme a capacidade individual.',ex:'Aproximar um joelho em direção ao tronco; estender a perna oposta; alternar as pernas de maneira controlada; manter a estabilidade da pelve durante o movimento.',resp:'Coordenar a respiração com a alternância das pernas, evitando bloqueios respiratórios.',rep:'Sugestão inicial de 6 a 10 alternâncias, ajustável à avaliação individual.',care:'Evitar compensações cervicais, perda do controle lombopélvico e amplitude incompatível com a capacidade do aluno.',t:'Manter a cabeça apoiada e reduzir a amplitude dos movimentos.'};
const GXG=t=>[['core',/abdomin|tronco|global|estabilidade|controle/],['flex',/mobilidade|articula|rota|lateral|extens/],['lombar',/lombo|pelvic|coluna/],['mq',/quadril|membros inferiores/],['equil',/equil/],['oc',/ombro|escapular|toracic/],['postura',/escapular|posterior|extens|alinhamento/],['cond',/forca|resist/],['pelv',/pelvic/]].filter(([k,r])=>r.test(norm(t))).map(x=>x[0]);
const GXGR=t=>{t=norm(t);return /abdomin|core|teaser|hundred|global/.test(t)?'Abdômen / core':/ombro|escapular|braco|arm|chest|toracic/.test(t)?'Ombros e braços':/coluna|vertebral|extens|lombo|posterior|rotacao|lateral/.test(t)?'Coluna':/quadril|inferiores|pelvic|tornozelo|equil|squat|lunge|leg/.test(t)?'Quadril e pernas':'Corpo todo'};
const GXGRS=['Abdômen / core','Coluna','Quadril e pernas','Ombros e braços','Corpo todo'];
const GXAV=n=>{n=norm(n);const a=new Set();
  if(/roll up|roll over|roll down|roll back|teaser|corkscrew|open leg|rolling|saw|spine stretch|short box round|spine massage|stomach massage|knee stretch round|double|single straight|criss|abdominal curl|hundred/.test(n))['osteo','hernia','gest','pos'].forEach(c=>a.add(c));
  if(/swan|backbend|up stretch|down stretch|arched|swimming|thoracic extension/.test(n))['gest','pos','vert'].forEach(c=>a.add(c));
  if(/hanging|pull up|push up|plank|long stretch|down stretch|up stretch|going up|pike|splits|mountain climber/.test(n))['ombro','pos','gest','hta'].forEach(c=>a.add(c));
  if(/lunge|squat/.test(n))a.add('joelho');
  if(/roll over|corkscrew|hundred|abdominal curl|criss|teaser|double leg|single leg stretch/.test(n))a.add('cerv');
  if(/roll up|roll over|teaser|double straight|corkscrew|open leg|long stretch|hanging|pull up|push up|plank|criss|abdominal|hundred|double leg|single leg stretch|pike|stomach massage|short box round|rolling/.test(n))a.add('diast');
  if(/roll over|teaser|double straight|corkscrew|open leg|long stretch|hanging|pull up/.test(n))a.add('lomb');
  if(/corkscrew|saw|criss|side bend|backbend|swan on barrel|side splits/.test(n))a.add('esco');
  if(/leg circles|frog|splits|eve|lunge|squat|bicycle|mountain climber|jump/.test(n))a.add('quadril');
  if(/roll over|long spine|short spine|hanging|pike|down stretch|monkey|elephant|jump/.test(n)){a.add('glauc');a.add('hta')}
  if(/jump|plank|push up|hanging|pull up|teaser|roll up|roll over|rolling|mountain climber/.test(n))a.add('obes');
  if(/jump|lunge|squat|mountain climber/.test(n))a.add('artrose');
  return[...a]};
const GXPTX={'Footwork no Reformer':'Trabalho de pés no Reformer','Footwork na Chair (pedal)':'Trabalho de pés na Chair (pedal)','Elephant no Reformer':'Elefante no Reformer','Rolling like a Ball':'Rolando como uma bola','Jump Board no Reformer':'Salto no Jump Board (Reformer)','Cadillac: Push Through sentada':'Cadillac: Empurrar através, sentada','Cadillac: Roll Down com barra':'Cadillac: Rolamento para baixo com barra','Step down na Chair':'Descida de degrau na Chair','Leg Springs (Cadillac)':'Molas para as pernas (Cadillac)','Single Leg Stretch':'Alongamento de uma perna','Hundred (pernas na mesa, cabeça apoiada)':'Os Cem (pernas na mesa, cabeça apoiada)','Roll Up':'Rolamento para cima','Teaser':'Teaser (abdominal em V)'};
const GXPTB={'The Hundred':'Os Cem','Hundred':'Os Cem','Roll Up':'Rolamento para cima','Roll Over':'Rolamento sobre a cabeça','Single Leg Circles':'Círculos com uma perna','Rolling Like a Ball':'Rolando como uma bola','Single Leg Stretch':'Alongamento de uma perna','Double Leg Stretch':'Alongamento de duas pernas','Single Straight Leg Stretch':'Alongamento de uma perna estendida','Double Straight Leg Stretch':'Alongamento de duas pernas estendidas','Criss Cross':'Cruzado','Spine Stretch Forward':'Alongamento da coluna à frente','Open Leg Rocker':'Balanço com pernas abertas','Corkscrew':'Saca-rolhas','Saw':'Serra','Swan':'Cisne','Swimming':'Natação','Side Kick Series':'Série de chutes laterais','Seal':'Foca','Push Up':'Flexão de braços','Footwork':'Trabalho de pés','Coordination':'Coordenação','Frog':'Rã','Leg Circles':'Círculos com as pernas','Short Spine Massage':'Massagem curta da coluna','Long Spine Massage':'Massagem longa da coluna','Stomach Massage':'Massagem do abdômen','Short Box Round':'Short Box arredondado','Short Box Flat':'Short Box reto','Short Box Side to Side':'Short Box lateral','Elephant':'Elefante','Knee Stretch Round':'Alongamento de joelhos arredondado','Knee Stretch Arched':'Alongamento de joelhos arqueado','Running':'Corrida','Pelvic Lift':'Elevação pélvica','Long Stretch':'Alongamento longo','Down Stretch':'Alongamento para baixo','Up Stretch':'Alongamento para cima','Scooter':'Patinete',"Eve's Lunge":'Avanço de Eve','Mermaid':'Sereia','Side Splits':'Espacate lateral','Front Splits':'Espacate frontal','Roll Down Bar':'Rolamento para baixo com barra','Arm Springs':'Molas para os braços','Leg Springs':'Molas para as pernas','Breathing':'Respiração','Push Through':'Empurrar através','Tower':'Torre','Monkey':'Macaco','Roll Back':'Rolamento para trás','Hanging':'Suspensão','Bicycle':'Bicicleta','Chest Expansion':'Expansão do peito','Pull Up':'Barra fixa','Pumping':'Bombeamento','Standing Pumping':'Bombeamento em pé','Seated Pumping':'Bombeamento sentado','Going Up Front':'Subida frontal','Going Up Side':'Subida lateral','Mountain Climber':'Escalador','Pike':'Canivete','Side Stretch':'Alongamento lateral','Leg Press':'Pressão de pernas','Hamstring Stretch':'Alongamento de isquiotibiais','Swan on Barrel':'Cisne no Barrel','Backbend':'Extensão de coluna','Side Bend':'Flexão lateral','Horseback':'Cavalgada','Swan Prep':'Preparação do Cisne','Abdominal Curl':'Flexão abdominal','Scissors':'Tesoura','Shoulder Bridge':'Ponte de ombros','Chest Squeeze':'Compressão do peito','Inner Thigh Press':'Pressão de coxas internas','Arm Press':'Pressão de braços','Bridge':'Ponte','Hamstring Curl':'Flexão de joelhos','Wall Squat':'Agachamento na parede','Roll Out':'Rolamento para fora','Pelvic Curl':'Enrolamento pélvico','Adductor Squeeze':'Compressão de adutores','Arm Pull':'Puxada de braços','Shoulder Mobility':'Mobilidade de ombros','Balance':'Equilíbrio','Thoracic Extension':'Extensão torácica','Arm Circles':'Círculos de braços','Biceps Curl':'Rosca de bíceps','Lateral Raise':'Elevação lateral','Abdominal Prep':'Preparação abdominal','Spine Mobility':'Mobilidade da coluna','Standing Balance':'Equilíbrio em pé','Squat':'Agachamento','Single Leg Balance':'Equilíbrio unipodal','Bird Dog':'Quadrúpede alternado (Bird Dog)','Dead Bug':'Inseto morto (Dead Bug)','Plank':'Prancha','Side Plank':'Prancha lateral','Lunge':'Avanço','Standing Leg Extension':'Extensão de perna em pé','Hip Hinge':'Dobradiça de quadril','Clam':'Ostra','Wall Roll Down':'Descida vertebral na parede'};
const GXPTS=t=>t.replace(/Magic Circle/g,'Círculo de Pilates').replace(/Mini Ball/g,'Mini bola').replace(/Foam Roller/g,'Rolo de espuma');
const gxPt=n=>{n=String(n);if(GXPTX[n])return GXPTX[n];const m=n.match(/^(.*?)(\s*\(.*\))?$/),b=GXPTB[m[1]];return b?b+GXPTS(m[2]||''):n};
function gxLocalize(e){const p=gxPt(e.n);if(p!==e.n){e.en=e.en||e.n;e.n=p}}
function gxGoalsX(e){const g=e.g||[],av=e.av||[],has=(...k)=>k.some(x=>g.includes(x)),ok=(...k)=>!k.some(x=>av.includes(x)),nm=nz(e.en||e.n),r=[];
  if(has('lombar','core')&&ok('hernia')&&e.lv<=2)r.push('hernia');
  if(has('oc','postura','rel')&&ok('cerv')&&e.lv<=2)r.push('cervical');
  if(has('postura','flex')&&ok('esco'))r.push('escoli');
  if(has('postura','osteo'))r.push('cifose');
  if(has('oc')&&ok('ombro'))r.push('ombro');
  if(has('mq')&&ok('joelho','artrose')&&e.lv<=2)r.push('joelho');
  if(has('mq')&&ok('quadril')&&e.lv<=2)r.push('quadril');
  if(/footwork|trabalho de pes|running|corrida|pumping|bombeamento|equilibrio/.test(nm))r.push('pe');
  if(has('pelv','core')&&ok('diast')&&e.lv<=2)r.push('diast');
  if(has('equil','osteo')&&e.lv<=2)r.push('idoso');
  if(has('rel','flex')&&e.lv<=2&&ok('fibro'))r.push('fibro');
  if(e.lv<=1&&ok('pos'))r.push('pos');
  if(has('equil','core')&&e.lv<=2&&ok('vert'))r.push('neuro');
  if(has('rel'))r.push('resp');
  if(has('cond','core')&&e.lv>=2)r.push('atleta');
  if(has('cond')&&ok('hta','cardio','obes'))r.push('cardio');
  return r}
function gxGoalsAdd(e){e.g=[...new Set([...(e.g||[]),...gxGoalsX(e)])]}
function gxMigrate(){db.exLib.forEach(e=>{if(!/^x\d+$/.test(e.id))return;const src=e.en||e.n;gxLocalize(e);e.av=[...new Set([...(e.av||[]),...GXAV(src)])];gxGoalsAdd(e)});db.settings.gxMig=3}
function gxSeed(){
  const used=new Set(),L=[];let e='M',i=0;
  GXCAT.split('\n').forEach(r=>{
    if(r[0]==='#'){e=r[1];return}
    const[n,l,o]=r.split('|'),x={id:'x'+i++,n,en:n,a:[e],lv:{I:1,M:2,A:3}[l]||1,o,g:GXG(o),av:GXAV(n),b:o,t:'',grp:GXGR(o+' '+n),sup:l==='A',fav:false,media:''};
    const c=GX.find(c=>nz(c.n).includes(nz(n).replace(/^the /,''))&&c.a.some(y=>fam(y)===fam(e)));
    if(c){used.add(c);Object.assign(x,{g:c.g,b:c.b,av:[...new Set([...c.av,...x.av])],t:c.t})}
    if(n==='Single Leg Stretch'&&e==='M')Object.assign(x,GXFICHA);
    L.push(x)});
  GX.filter(c=>!used.has(c)).forEach(c=>L.push({...c,av:[...new Set([...c.av,...GXAV(c.n)])],id:'x'+i++,o:'',grp:GXGR(c.b+' '+c.n),sup:c.lv===3,fav:false,media:''}));
  L.forEach(gxLocalize);L.forEach(gxGoalsAdd);return L;
}
/* v17: novos exercícios (lista geral por aparelho). nome em português|original|nível|foco. Sem duplicar: compara nome original e nome em português no mesmo aparelho. */
const GXNEW=`#M
Mergulho do Cisne|Swan Dive|A|Extensão e controle
Chute com uma perna|Single Leg Kick|M|Posterior de coxa e extensão
Chute com duas pernas|Double Leg Kick|M|Extensão da coluna
Puxada de pescoço|Neck Pull|A|Articulação da coluna
Tesoura|Scissors|M|Coordenação e controle
Bicicleta|Bicycle|A|Mobilidade dos quadris
Canivete|Jackknife|A|Controle global
Prancha com elevação de perna (frente)|Leg Pull Front|A|Estabilidade global
Prancha com elevação de perna (costas)|Leg Pull Back|A|Força e estabilidade
Flexão lateral|Side Bend|A|Controle lateral
Bumerangue|Boomerang|A|Controle global
Caranguejo|Crab|A|Mobilidade e coordenação
Balanço|Rocking|A|Mobilidade em extensão
Equilíbrio controlado|Control Balance|A|Força e controle global
#R
Massagem de estômago redonda|Stomach Massage Round|M|Mobilidade e força
Massagem de estômago com mãos atrás|Stomach Massage Hands Back|M|Mobilidade e força
Massagem de estômago com alcance|Stomach Massage Reach|A|Mobilidade e força
Alongamento do tendão|Tendon Stretch|A|Mobilidade posterior
Short Box com rotação|Short Box Twist|M|Rotação do tronco
Short Box árvore|Short Box Tree|M|Mobilidade posterior
Elefante (variação)|Elephant Variation|M|Estabilidade e mobilidade
Alongamento de joelhos fora do apoio|Knee Stretch Knees Off|A|Controle lombo-pélvico
Expansão do peito|Chest Expansion|I|Estabilidade escapular
Alongamento de coxa|Thigh Stretch|A|Extensão e força de quadríceps
Círculos de braços|Arm Circles|I|Estabilidade dos ombros
Abraço na árvore|Hug a Tree|I|Mobilidade torácica
Bandeja de serviço|Serving Tray|I|Estabilidade dos ombros
Saudação|Salute|M|Controle e coordenação
Splits russo|Russian Splits|A|Mobilidade e controle
Serpente|Snake|A|Força e mobilidade
Torção|Twist|A|Rotação e controle
Semicírculo|Semi Circle|A|Mobilidade da coluna
Controle frontal|Control Front|A|Estabilidade global
#C
Push Through reverso|Push Through Reverse|M|Mobilidade da coluna
Molas de perna: caminhada|Leg Springs Walking|M|Mobilidade do quadril
Molas de perna: tesoura|Leg Springs Scissors|M|Controle dos membros inferiores
Molas de perna: batidas|Leg Springs Beats|M|Estabilidade pélvica
Molas de braço: círculos|Arm Springs Circles|I|Estabilidade dos ombros
Molas de braço: abraço|Arm Springs Hug|I|Estabilidade escapular
Molas de braço: bíceps|Arm Springs Biceps|I|Força de braços
Molas de braço: tríceps|Arm Springs Triceps|I|Força de braços
Rolamento sobre a cabeça no Cadillac|Roll Over|A|Controle e mobilidade
Coluna curta|Short Spine|M|Mobilidade e controle
Coluna longa|Long Spine|A|Controle corporal
Águia aberta|Spread Eagle|A|Força e controle corporal
Barras suspensas: puxada|Hanging Pull Ups|A|Força e controle corporal
Barras suspensas: costas|Hanging Back|A|Mobilidade em extensão
Barras suspensas: macaco|Hanging Monkey|A|Força e controle corporal
Gato|Cat|M|Mobilidade da coluna
Avião|Airplane|A|Extensão e estabilidade
Molas laterais de perna|Side Leg Springs|M|Estabilidade pélvica
Molas de braço ajoelhado|Kneeling Arm Springs|M|Estabilidade dos ombros
Molas de braço em pé|Standing Arm Springs|M|Estabilidade dos ombros
Respiração com a barra de empurrar|Breathing with Push Through Bar|I|Coordenação respiratória
Tower com a barra de empurrar|Tower with Push Through Bar|M|Controle lombo-pélvico
#H
Footwork sentado|Footwork Seated|I|Força dos membros inferiores
Footwork em pé|Footwork Standing|M|Equilíbrio e força
Subida da montanha|Going Up Mountain|A|Força e equilíbrio
Escalada lateral|Side Mountain Climb|A|Estabilidade lateral
Cisne frontal|Swan Front|M|Extensão da coluna
Cisne para trás|Swan Back|M|Extensão da coluna
Alongamento da coluna|Spine Stretch|I|Mobilidade da coluna
Sapo|Frog|I|Controle do quadril
Pressão lateral da perna|Side Leg Press|I|Estabilidade lateral
Alongamento do calcanhar|Achilles Stretch|I|Mobilidade dos tornozelos
Alongamento do tendão|Tendon Stretch|M|Mobilidade posterior
Empurrar para baixo|Push Down|I|Força de braços
Tríceps|Triceps Press|I|Força de braços
Pressão de braços|Arm Press|I|Estabilidade dos ombros
Gato|Cat|I|Mobilidade da coluna
Sereia ajoelhada|Kneeling Mermaid|M|Mobilidade lateral
Cisne reverso|Reverse Swan|A|Extensão e controle
Subir no degrau|Step Up|I|Força dos membros inferiores
Puxada na Chair|Pull Up|A|Força e estabilidade
Controle de equilíbrio|Control Balance|A|Força e controle global
#B
Extensão de costas|Back Extension|M|Extensão da coluna
Sereia no Barrel|Mermaid|I|Mobilidade lateral
Short Box redondo|Short Box Round|M|Controle do tronco
Short Box plano|Short Box Flat|M|Estabilidade
Short Box lateral|Short Box Side to Side|M|Controle lateral
Short Box com rotação|Short Box Twist|M|Rotação do tronco
Short Box árvore|Short Box Tree|M|Mobilidade posterior
Alongamento de flexores do quadril|Hip Flexor Stretch|I|Mobilidade do quadril
Alongamento de quadríceps|Quadriceps Stretch|I|Mobilidade do quadril
Flexão abdominal|Abdominal Curl|I|Controle abdominal
Rolamento sobre a cabeça|Roll Over|A|Controle e mobilidade
Círculos de perna|Leg Circles|M|Mobilidade do quadril
Natação|Swimming|M|Resistência posterior
Elevação lateral da perna|Side Leg Lift|I|Estabilidade pélvica
Ponte de ombros|Shoulder Bridge|M|Estabilidade pélvica
Extensão da coluna|Spine Extension|M|Extensão da coluna
Flexão da coluna|Spine Flexion|M|Articulação da coluna
Descida no Barrel|Barrel Roll Down|I|Articulação da coluna
Mergulho do Cisne|Swan Dive|A|Extensão e controle
#S
Respiração|Breathing|I|Coordenação respiratória
Curva pélvica|Pelvic Curl|I|Controle pélvico
Os Cem|Hundred|M|Resistência abdominal
Rolamento para cima|Roll Up|A|Articulação da coluna
Rolamento sobre a cabeça|Roll Over|A|Controle e mobilidade
Círculo com uma perna|Single Leg Circle|M|Mobilidade do quadril
Alongamento de duas pernas|Double Leg Stretch|M|Coordenação
Alongamento de uma perna|Single Leg Stretch|M|Estabilidade abdominal
Teaser|Teaser|A|Controle global
Cisne|Swan|M|Extensão da coluna
Mergulho do Cisne|Swan Dive|A|Extensão e controle
Alongamento da coluna|Spine Stretch|I|Mobilidade da coluna
Flexão lateral|Side Bend|I|Controle lateral
Alongamento de flexores do quadril|Hip Flexor Stretch|I|Mobilidade do quadril
Alongamento de quadríceps|Quadriceps Stretch|I|Mobilidade do quadril
Extensão torácica|Thoracic Extension|I|Extensão torácica
Abertura do peito|Chest Opening|I|Mobilidade torácica
Série lateral de pernas|Side Leg Series|M|Estabilidade pélvica
#A
Pressão externa da coxa (Círculo de Pilates)|Outer Thigh Press (Magic Circle)|I|
Pressão dos pés (Círculo de Pilates)|Foot Press (Magic Circle)|I|
Pressão de uma perna (Círculo de Pilates)|Single Leg Press (Magic Circle)|I|
Pressão de duas pernas (Círculo de Pilates)|Double Leg Press (Magic Circle)|I|
Os Cem (Círculo de Pilates)|Hundred (Magic Circle)|M|
Rolamento para cima (Círculo de Pilates)|Roll Up (Magic Circle)|M|
Alongamento de uma perna (Círculo de Pilates)|Single Leg Stretch (Magic Circle)|M|
Alongamento de duas pernas (Círculo de Pilates)|Double Leg Stretch (Magic Circle)|M|
Pressão lateral da perna (Círculo de Pilates)|Side Leg Press (Magic Circle)|I|
Ponte de ombros (Círculo de Pilates)|Shoulder Bridge (Magic Circle)|M|
Expansão do peito (Círculo de Pilates)|Chest Expansion (Magic Circle)|I|
Bíceps (Círculo de Pilates)|Biceps Press (Magic Circle)|I|
Tríceps (Círculo de Pilates)|Triceps Press (Magic Circle)|I|
Sereia (Círculo de Pilates)|Mermaid (Magic Circle)|I|
Pressão em pé (Círculo de Pilates)|Standing Leg Press (Magic Circle)|I|
Os Cem (Mini bola)|Hundred (Mini Ball)|M|
Alongamento de uma perna (Mini bola)|Single Leg Stretch (Mini Ball)|M|
Alongamento de duas pernas (Mini bola)|Double Leg Stretch (Mini Ball)|M|
Ponte (Mini bola)|Bridge (Mini Ball)|I|
Elevação lateral da perna (Mini bola)|Side Leg Lift (Mini Ball)|I|
Preparação do cisne (Mini bola)|Swan Prep (Mini Ball)|I|
Rotação da coluna (Mini bola)|Spine Twist (Mini Ball)|I|
Extensão em prono (Bola suíça)|Prone Extension (Bola suíça)|I|
Pike (Bola suíça)|Pike (Bola suíça)|A|
Prancha (Bola suíça)|Plank on Ball (Bola suíça)|M|
Prancha lateral (Bola suíça)|Side Plank (Bola suíça)|A|
Natação (Bola suíça)|Swimming (Bola suíça)|M|
Extensão de costas (Bola suíça)|Back Extension (Bola suíça)|M|
Expansão do peito (Faixa elástica)|Chest Expansion (Faixa elástica)|I|
Remada (Faixa elástica)|Rowing (Faixa elástica)|I|
Alongamento posterior (Faixa elástica)|Hamstring Stretch (Faixa elástica)|I|
Alongamento de uma perna (Faixa elástica)|Single Leg Stretch (Faixa elástica)|M|
Pressão lateral da perna (Faixa elástica)|Side Leg Press (Faixa elástica)|I|
Rolamento para cima (Faixa elástica)|Roll Up (Faixa elástica)|M|
Rotação da coluna (Faixa elástica)|Spine Twist (Faixa elástica)|I|
Sereia (Faixa elástica)|Mermaid (Faixa elástica)|I|
Curva pélvica (Rolo de espuma)|Pelvic Curl (Foam Roller)|I|
Marcha (Rolo de espuma)|Marching (Foam Roller)|I|
Inseto morto (Rolo de espuma)|Dead Bug (Foam Roller)|I|
Círculos de perna (Rolo de espuma)|Leg Circles (Foam Roller)|I|
Rotação da coluna (Rolo de espuma)|Spine Twist (Foam Roller)|I|
Ponte de ombros (Rolo de espuma)|Shoulder Bridge (Foam Roller)|M|
Prancha (Rolo de espuma)|Plank (Foam Roller)|M|
Preparação do cisne (Rolo de espuma)|Swan Prep (Foam Roller)|I|`;
function gxAddNew(L){
  const ids=new Set(L.map(e=>e.id)),seen=new Set();
  L.forEach(e=>{const a=(e.a||[])[0]||'M';seen.add(a+'|'+nz(e.en||'').replace(/^the /,''));seen.add(a+'|'+nz(e.n));seen.add(a+'|'+nz(gxPt(e.en||e.n)))});
  let a='M',i=0,add=0;
  GXNEW.split('\n').forEach(r=>{
    if(r[0]==='#'){a=r[1];return}
    const[pt,en,l,o]=r.split('|'),k1=a+'|'+nz(en).replace(/^the /,''),k2=a+'|'+nz(pt);
    if(!pt||!en||seen.has(k1)||seen.has(k2))return;
    seen.add(k1);seen.add(k2);while(ids.has('x'+i))i++;ids.add('x'+i);
    const x={id:'x'+i,n:pt,en,a:[a],lv:{I:1,M:2,A:3}[l]||1,o:o||'',g:GXG(o||''),av:GXAV(en),b:o||'',t:'',grp:GXGR((o||'')+' '+en),sup:l==='A',fav:false,media:''};
    gxGoalsAdd(x);L.push(x);add++});
  return add;
}
const gxLib=()=>{if(!Array.isArray(db.exLib)){db.exLib=gxSeed();gxAddNew(db.exLib);db.settings.gxMig=4;save()}else if(db.settings.gxMig!==4){if(db.settings.gxMig!==3)gxMigrate();gxAddNew(db.exLib);db.settings.gxMig=4;save()}return db.exLib};
const gxSeqs=()=>{if(!Array.isArray(db.exSeq))db.exSeq=[];return db.exSeq};
const gxById=id=>gxLib().find(e=>e.id===id);
let gxMode='ex',gxStuSel='',gxFav=false,gxShown=40,gxCur=null,gxHide=true,gxPf=null;
const gxEqTxt=a=>a.map(k=>GX_AP[k]).join(', '),gxVal=id=>$('#'+id)?$('#'+id).value:'';
const gxImg=u=>/\.(png|jpe?g|gif|webp|svg)(\?|#|$)/i.test(u);
const gxOwn=e=>!!(e.media&&/^https:\/\//i.test(e.media)),gxQ=e=>e.a.map(k=>({M:'mat',F:'',A:''}[k]??GX_AP[k].toLowerCase())).filter(Boolean)[0]||'',
  gxVid=e=>gxOwn(e)?e.media:'https://www.youtube.com/results?search_query='+encodeURIComponent(`pilates ${e.en||e.n} ${gxQ(e)} como fazer execução correta`.replace(/\s+/g,' '));
const gxThumb=e=>`<span class="gxth">${eqIcon({name:GX_AP[e.a[0]]||''},30)}${e.thumb&&/^https:\/\//i.test(e.thumb)?`<img src="${esc(e.thumb)}" alt="Miniatura: ${esc(e.n)}" loading="lazy" referrerpolicy="no-referrer" onerror="this.remove()">`:''}</span>`;
const GXT=Object.fromEntries(`hundred|Reto e transverso do abdome, oblíquos, serrátil anterior|Decúbito dorsal, pernas em mesa ou estendidas a 45°, cabeça e escápulas elevadas|Elevar cabeça e escápulas; braços estendidos junto ao corpo; bombear os braços em pequena amplitude; inspirar em 5 batidas e expirar em 5; completar 10 ciclos|Inspirar por 5 tempos e expirar por 5, em ritmo contínuo|1 série de 10 ciclos (100 batidas); iniciantes: 5 a 8 ciclos|Reduzir a alavanca se a lombar sair do apoio; sem tensão cervical|Queixo projetado; lombar arqueada; ombros tensos; prender o ar|Estender as pernas a 45° mantendo a lombar neutra|Cabeça apoiada e joelhos fletidos|Costelas em direção à pelve, pescoço longo.
roll up|Reto do abdome, flexores do quadril, eretores da espinha|Decúbito dorsal, pernas alongadas, braços acima da cabeça|Inspirar e elevar os braços; expirar e flexionar o tronco vértebra a vértebra; alcançar os pés com a coluna em C; inspirar no topo; expirar e retornar com controle|Expirar na subida e na descida; inspirar no topo|1 a 2 séries de 4 a 6 repetições|Evitar em osteoporose e hérnia discal; sem impulso|Usar impulso; elevar os pés; perder o controle na descida|Reduzir a velocidade e aumentar a amplitude de forma gradual|Joelhos fletidos ou faixa nos pés|Uma vértebra de cada vez, como uma roda.
single leg circles|Flexores e rotadores do quadril, abdominais, estabilizadores da pelve|Decúbito dorsal, uma perna estendida ao teto, a outra alongada no solo|Fixar a pelve; desenhar círculos pequenos com a perna elevada; inverter o sentido; trocar de lado|Inspirar em meio círculo e expirar no outro meio|1 série de 5 círculos por sentido e por perna|Pelve imóvel; joelho da perna de apoio levemente fletido se houver desconforto|Girar a pelve; arquear a lombar; círculos amplos demais|Aumentar o diâmetro do círculo mantendo a pelve fixa|Joelho flexionado ou faixa no pé|Círculo pequeno, pelve de pedra.
rolling like a ball|Reto do abdome, flexores do quadril, eretores da espinha|Sentado em equilíbrio sobre os ísquios, joelhos fletidos, mãos nas canelas|Arredondar a coluna e levar o queixo ao peito; inspirar e rolar até os ombros; expirar e voltar ao equilíbrio sem apoiar os pés|Inspirar ao rolar para trás e expirar ao retornar|1 série de 6 a 8 rolamentos|Evitar em osteoporose e hérnia discal; rolar sobre colchonete firme|Rolar sobre o pescoço; perder a curva em C; usar impulso|Pausar no equilíbrio por 2 segundos|Rolar em amplitude menor|Mantenha a bola redonda.
double leg stretch|Reto e transverso do abdome, flexores do quadril, serrátil anterior|Decúbito dorsal, joelhos ao peito, cabeça e escápulas elevadas|Inspirar estendendo braços e pernas; expirar circulando os braços e abraçando os joelhos; manter a lombar estável|Inspirar ao estender e expirar ao recolher|1 a 2 séries de 6 a 8 repetições|Cabeça apoiada se houver cervicalgia; pernas mais altas protegem a lombar|Pernas muito baixas; lombar arqueada; tensão no pescoço|Estender os braços e as pernas em ângulo mais baixo|Pernas mais altas e cabeça apoiada|Alongar do centro para fora, recolher para o centro.
criss cross|Oblíquos do abdome, reto do abdome, flexores do quadril|Decúbito dorsal, mãos atrás da cabeça, pernas em mesa, cabeça e escápulas elevadas|Rodar o tronco levando o cotovelo ao joelho oposto; estender a outra perna; alternar os lados com fluidez|Expirar a cada rotação|1 série de 8 a 10 alternâncias|Evitar em hérnia discal e osteoporose; cotovelos abertos, sem puxar a cabeça|Puxar o pescoço; trazer só o cotovelo, sem girar o tronco|Pernas mais baixas e ritmo constante|Manter os pés apoiados e rotação curta|Gire a partir das costelas.
spine stretch forward|Eretores da espinha, reto do abdome, isquiotibiais|Sentado com pernas afastadas na largura do tapete, braços à frente na altura dos ombros|Inspirar alongando a coluna; expirar arredondando a partir da cabeça; aprofundar o abdome; inspirar e empilhar vértebra a vértebra|Expirar na flexão e inspirar no retorno|1 série de 5 a 6 repetições|Sentar sobre uma almofada se a pelve retrovertir; joelhos levemente fletidos|Cair para frente em bloco; elevar os ombros|Aumentar a amplitude com a pelve ancorada|Elevar o quadril com apoio e joelhos fletidos|Alongar para cima antes de ir para a frente.
saw|Oblíquos, isquiotibiais, eretores da espinha|Sentado, pernas abertas, braços em T na altura dos ombros|Girar o tronco; inspirar alongando; expirar curvando e levando a mão ao pé oposto; inspirar e desenrolar; alternar os lados|Expirar na rotação com flexão|1 série de 4 a 6 repetições por lado|Evitar flexão profunda em osteoporose e hérnia; rotação curta|Mover só os braços; pelve que sai do apoio|Aumentar a amplitude de rotação com ísquios ancorados|Sentar sobre apoio e joelhos fletidos|Gire como quem torce uma toalha.
swan|Eretores da espinha, glúteos, extensores torácicos|Decúbito ventral, mãos sob os ombros, cotovelos junto ao corpo|Alongar a coluna e elevar o tronco em extensão torácica; manter o abdome ativo; descer com controle|Inspirar ao subir e expirar ao descer|1 série de 4 a 6 repetições|Evitar em gestação e pós-operatório recente; extensão curta se houver dor lombar|Comprimir a lombar; elevar os ombros; empurrar demais com as mãos|Estender mais a coluna com apoio mínimo das mãos|Extensão em prono com antebraços apoiados|Alongue-se para a frente antes de subir.
swimming|Eretores da espinha, glúteos, deltoides posteriores|Decúbito ventral, braços e pernas alongados|Elevar braços e pernas a pequena altura; alternar braço e perna opostos em batidas curtas; manter o pescoço alongado|Inspirar em 5 batidas e expirar em 5|1 série de 20 a 30 batidas|Evitar em gestação e pós-operatório; sem hiperextensão cervical|Hiperextender o pescoço; balançar a pelve; elevar demais os membros|Ritmo mais rápido mantendo a pelve estável|Elevar só os braços, depois só as pernas|Cresça para a frente e para fora.
teaser|Reto e transverso do abdome, flexores do quadril, eretores da espinha|Decúbito dorsal, pernas em 45°, braços acima da cabeça|Elevar o tronco em C; equilibrar no sacro com pernas e braços paralelos; manter a coluna alongada; desenrolar até o solo|Inspirar para subir, expirar para manter, inspirar para retornar|1 série de 3 a 5 repetições|Evitar em osteoporose, hérnia, cardiopatia e hipertensão; avançar só com domínio do Roll Up|Subir com impulso; perder a curva em C; prender o ar|Aumentar o tempo de equilíbrio e a distância dos braços|Teaser com joelhos dobrados e mãos atrás das coxas|Equilíbrio em V com o peito aberto.
side kick series|Glúteo médio, adutores, oblíquos, abdominais profundos|Decúbito lateral, quadris empilhados, cabeça apoiada no braço, pernas levemente à frente|Elevar a perna superior à altura do quadril; chutar para frente em 2 pulsos; levar a perna para trás com a pelve fixa; trocar de lado|Inspirar à frente e expirar ao estender para trás|1 série de 8 a 10 repetições por lado|Cintura alongada; amplitude curta se houver dor lombar|Rodar a pelve; arquear a lombar; descer o tronco|Adicionar círculos e elevações com carga leve|Apoiar a cabeça e o antebraço, amplitude curta|Quadris empilhados como paredes.
footwork|Quadríceps, glúteos, isquiotibiais, gastrocnêmios, estabilizadores da pelve|Decúbito dorsal no carro do Reformer, cabeça apoiada, pés na barra em paralelo|Pressionar a barra estendendo os quadris e joelhos; manter a pelve neutra; retornar com controle sem bater o carro; variar apoio dos pés (calcanhares, arcos, ponta)|Expirar ao empurrar e inspirar ao retornar|2 séries de 10 a 15 repetições|Sem hiperextensão dos joelhos; mola ajustada ao controle do aluno|Hiperextender joelhos; rodar a pelve; bater o carro|Reduzir a mola e variar a base de apoio|Mola mais pesada e amplitude curta|Pressione a barra para longe e retorne com controle.
shoulder bridge|Glúteos, isquiotibiais, eretores da espinha, abdominais|Decúbito dorsal, joelhos fletidos, pés apoiados no quadril, braços ao lado do corpo|Retroverter a pelve e subir vértebra a vértebra até os ombros; manter a pelve nivelada; descer em segmentos|Expirar ao subir e inspirar ao descer|1 série de 6 a 8 repetições|Amplitude curta em dor lombar; sem hiperextensão lombar|Elevar demais o quadril; abrir os joelhos; sobrecarregar o pescoço|Estender uma perna ao teto mantendo a pelve nivelada|Ponte pélvica simples com amplitude curta|Suba pelo cóccix, desça pelas vértebras.
bird dog|Multífidos, glúteo máximo, eretores da espinha, deltoide|Quatro apoios, mãos sob os ombros e joelhos sob o quadril, coluna neutra|Estender a perna e o braço opostos sem mover a coluna; manter a pelve nivelada; retornar sem perder o alinhamento; alternar|Expirar ao estender e inspirar ao voltar|2 séries de 6 a 8 por lado|Joelhos acolchoados; evitar em lesão aguda de ombro|Arquear a lombar; rodar a pelve; elevar o ombro|Elevar braço e perna a partir do tronco com pausa de 3 segundos|Estender só uma perna ou só um braço|Alongue-se de ponta a ponta com a coluna parada.
dead bug|Transverso do abdome, reto do abdome, flexores do quadril|Decúbito dorsal, joelhos a 90° sobre o quadril, braços ao teto|Manter a lombar neutra; baixar o braço e a perna opostos; retornar sem perder o controle; alternar|Expirar ao baixar e inspirar ao retornar|2 séries de 6 a 8 por lado|Interromper se a lombar arquear; sem dor|Arquear a lombar; apressar o movimento; prender o ar|Estender completamente braço e perna opostos|Baixar só os calcanhares até o solo|Costelas pesadas no tapete.
clam|Glúteo médio, rotadores externos do quadril, abdominais|Decúbito lateral, quadris e joelhos fletidos, pés juntos|Manter os pés unidos; abrir o joelho superior sem rodar a pelve; retornar com controle|Expirar ao abrir e inspirar ao fechar|2 séries de 10 a 15 repetições por lado|Mini band apenas se não houver dor no joelho|Rolar a pelve para trás; elevar o pé; usar impulso|Faixa elástica e abertura mais lenta|Sem faixa e amplitude curta|A pelve fica parada e o joelho abre sozinho.
plank|Reto do abdome, transverso, serrátil anterior, glúteos, deltoides|Quatro apoios, mãos sob os ombros, pernas estendidas|Alinhar cabeça, tronco e pernas; ativar o abdome e as escápulas; sustentar a posição; descer com controle|Respiração contínua sem apneia|2 a 3 séries de 20 a 30 segundos|Evitar em lesão de punho/ombro; apoiar os joelhos se a lombar ceder|Quadril alto ou baixo; ombros colapsados; prender o ar|Prancha com elevação alternada de pernas ou braços|Prancha inclinada com as mãos num apoio ou joelhos no solo|Longo da cabeça aos calcanhares.`.split('\n').map(r=>{const[k,musc,pos,ex,resp,dos,care,err,prog,t,cue]=r.split('|');return[k,{musc,pos,ex,resp,dos,care,err,prog,t,cue}]}));
const gxTec=e=>{const T=GXT[nz(e.en||e.n).replace(/^the /,'')]||{},m={...T};Object.entries(e).forEach(([k,v])=>{if(v&&!(Array.isArray(v)&&!v.length))m[k]=v});return{T,f:tuF(m),full:!!(T.ex||e.ex)}};
const GXPH={};
const gxPh=e=>GXPH[e.id]?`<img class="gph" src="${GXPH[e.id].u}" alt="Foto: ${esc(e.n)}" loading="lazy">`:'';
const gxPhBtn=e=>`<div class="row-acts" style="margin-top:10px;flex-wrap:wrap">`+(GXPH[e.id]?`<button type="button" class="btn sm" data-act="gxPhoto" data-id="${esc(e.id)}">Trocar foto</button><button type="button" class="btn sm bad" data-act="gxPhotoDel" data-id="${esc(e.id)}">Remover foto</button>`:`<button type="button" class="btn sm primary" data-act="gxPhoto" data-id="${esc(e.id)}">+ Anexar foto</button>`)+`</div>`;
const gxAfter=id=>{try{document.querySelectorAll('.gxc[data-id="'+id+'"] .gxtabs button[data-k="ex"]').forEach(b=>b.click());if($('#tuNote'))tuSheet(id)}catch{}};
const gxShort=l=>String(l).split(/ \/ | \(/)[0];
const CONDX={
osteo:['Evitar','Flexão e rotação de coluna sob carga aumentam o risco de fratura por compressão vertebral.','coluna neutra, extensão leve, carga axial e trabalho de equilíbrio.'],
hernia:['Evitar','Flexão lombar sob carga e rotação aumentam a pressão sobre o disco e podem reproduzir dor irradiada.','coluna neutra, amplitude curta, joelhos fletidos; progredir só sem dor irradiada.'],
gest:['Exige liberação','Decúbito dorsal prolongado (após o 1º trimestre), compressão abdominal e risco de queda.','tronco elevado com cunha, quatro apoios, sentada ou decúbito lateral; respiração contínua, sem apneia.'],
hta:['Cuidado','Apneia, inversões e esforço isométrico elevam a pressão arterial.','respiração contínua, cabeça acima do nível do coração, ritmo lento e progressão gradual.'],
cardio:['Exige liberação','Esforço intenso, apneia e inversões sobrecarregam o coração.','carga leve, ritmo controlado, pausas frequentes e liberação do cardiologista.'],
pos:['Exige liberação','Tecido em cicatrização não tolera carga, alongamento ou tensão na região operada.','somente com liberação do cirurgião; começar por respiração, mobilidade ativa leve e amplitude protegida.'],
artrose:['Cuidado','Impacto, compressão e amplitude extrema irritam a articulação acometida.','cadeia fechada com molas de assistência, amplitude sem dor e sem impacto.'],
joelho:['Evitar','Flexão profunda sob carga e torção do joelho sobrecarregam ligamentos, menisco e patela.','amplitude reduzida e sem dor, joelho alinhado ao pé, apoio ou molas de assistência.'],
ombro:['Evitar','Apoio de peso nas mãos, elevação acima da cabeça e tração irritam manguito e cápsula articular.','trabalhar abaixo da linha do ombro, escápula estável, molas leves e sem apoio nas mãos.'],
vert:['Evitar','Mudança rápida de posição da cabeça, extensão cervical e inversões podem provocar tontura.','cabeça neutra, transições lentas, posição sentada ou semi-inclinada com apoio.'],
lomb:['Cuidado','Flexão repetida, pernas estendidas pesadas e alavancas longas aumentam a demanda sobre a lombar.','joelhos fletidos, pelve e coluna neutras, alavanca curta e ativação do transverso antes de mover.'],
cerv:['Evitar','Flexão cervical forçada e o peso da cabeça sem apoio agravam a compressão da cervical.','apoiar a cabeça, queixo neutro, reduzir a elevação do tronco ou usar apoio.'],
esco:['Cuidado','Rotações e flexões laterais sem controle podem acentuar assimetrias.','alongamento axial e simetria, com ajuste individual orientado pelo fisioterapeuta.'],
diast:['Evitar','Flexão de tronco e pressão intra-abdominal podem ampliar a separação da linha alba.','ativar o transverso, evitar o “domo” abdominal; variações em quatro apoios ou com apoio de cabeça.'],
quadril:['Cuidado','Flexão acentuada, rotações e adução forçada sobrecarregam prótese ou articulação com impacto femoroacetabular.','respeitar as restrições de movimento do cirurgião, amplitude reduzida e apoio.'],
glauc:['Evitar','Inversões e cabeça abaixo do nível do coração elevam a pressão intraocular.','manter a cabeça acima do tronco e evitar apneia.'],
obes:['Cuidado','Impacto, apoio prolongado do peso e posições no solo podem sobrecarregar articulações e a respiração.','começar com apoio e aparelhos (Reformer/Chair), séries curtas e pausas.'],
diab:['Cuidado','Esforço intenso sem alimentação adequada pode causar hipoglicemia; atenção aos pés.','conferir glicemia antes, ter carboidrato à mão e evitar apoio sobre pés com feridas.'],
fibro:['Cuidado','Esforço intenso e alongamento brusco podem agravar dor e fadiga.','intensidade leve, progressão gradual, pausas e respeito ao dia do aluno.'],
resp:['Cuidado','Apneia e compressão do tórax pioram a falta de ar.','respiração contínua, ritmo lento, pausas e broncodilatador ao alcance quando prescrito.']};
const gxLvTxt=['Nível não informado.','Básico: indicado para iniciantes e para quem precisa de apoio; boa porta de entrada para o aparelho.','Intermediário: exige bom controle de core, coluna neutra e coordenação entre respiração e movimento.','Avançado: para alunos experientes, sem dor, com boa estabilidade e controle de amplitude.'];
const gxSum=e=>{const g=(e.g||[]).filter(k=>GL[k]),av=(e.av||[]).filter(Boolean);
  const ch=(a,lab,n)=>a.slice(0,n).map(k=>`<span>${esc(gxShort(lab[k]||k))}</span>`).join('')+(a.length>n?`<span class="mo">+${a.length-n}</span>`:'');
  return `<div class="gxsm"><div class="gxrec"><b>✔ Recomendado para</b>${g.length?ch(g,GL,3):'<span class="mo">não cadastrado</span>'}</div><div class="gxav"><b>⚠ Evitar em</b>${av.length?ch(av,CL,4):'<span class="ok">sem restrição específica</span>'}</div></div>`};
const gxRecHtml=(e,f)=>{const g=(e.g||[]).filter(k=>GL[k]);
  const grp=GOAL_GROUPS.map(([t,ks])=>{const m=ks.filter(k=>g.includes(k));return m.length?`<div class="gxg"><b>${esc(t)}</b><ul class="gxul">${m.map(k=>`<li>${esc(GL[k])}</li>`).join('')}</ul></div>`:''}).join('');
  const ind=f&&f.ind&&f.ind[0]?`<div class="gxr"><span>Indicações clínicas</span>${esc(f.ind[0])}</div>`:'';
  return `<div class="gxr"><span>Recomendado para</span>${grp||'<div>Ainda não cadastrado. Marque em “Ficha” → “Serve para melhora de”.</div>'}</div>`+ind
   +`<div class="gxr"><span>Perfil indicado</span>${esc(gxLvTxt[e.lv||0])}</div><div class="gxr"><span>Aparelhos</span>${esc(gxEqTxt(e.a))}</div>`
   +(e.sup?'<div class="gxr"><span>Supervisão</span>Exige acompanhamento direto do instrutor durante a execução.</div>':'')};
const gxAvHtml=e=>{const av=(e.av||[]).filter(Boolean);
  const li=av.map(c=>{const x=CONDX[c],cl=x?({'Evitar':'r','Cuidado':'a','Exige liberação':'b'})[x[0]]:'';return `<div class="gxa"><div class="gxah"><b>${esc(CL[c]||c)}</b>${x?`<em class="${cl}">${x[0]}</em>`:''}</div>${x?`<div>${esc(x[1])}</div><div class="gxalt"><b>Alternativa:</b> ${esc(x[2])}</div>`:''}</div>`}).join('');
  return `<div class="gxr"><span>Evitar em</span>${av.length?li:'<div>Sem restrição específica cadastrada. Aplique as regras gerais e avalie cada aluno.</div>'}</div><div class="sub" style="margin-bottom:8px">Orientação geral: ajuste sempre pela avaliação do aluno e peça liberação profissional quando houver diagnóstico ou cirurgia.</div>`};
const gxNm=n=>String(n||'').trim().split(/\s+/).slice(0,2).join(' ');
const gxStuAll=e=>{const r=[],av=[],ad=[];
 activeStudents().forEach(s=>{const pf=gxProfile(s),gs=[...goalsP(s),...(s.goalKeys2||[])],bad=(e.av||[]).filter(c=>pf.cond.has(c));
  if(bad.length){av.push([s,bad.map(c=>(CL[c]||c).split(' / ')[0].toLowerCase()).join(', ')]);return}
  const m=gs.filter(k=>(e.g||[]).includes(k));if(!m.length)return;
  const t=gxShort(GL[m[0]]).toLowerCase()+(m.length>1?' +'+(m.length-1):'');
  if(e.lv>pf.cap)ad.push([s,'nível acima · '+t]);else r.push([s,t])});
 return{r,av,ad}};
const gxStuLine=(cls,lab,a,n=4)=>a.length?`<div class="gxsl ${cls}"><b>${lab}</b>${a.map(([s,t],i)=>`<button type="button" data-act="gxStuGo" data-id="${esc(s.id)}" title="${esc(s.name)}"${i>=n?' class="x" hidden':''}>${esc(gxNm(s.name))}${t?` <i>${esc(t)}</i>`:''}</button>`).join('')}${a.length>n?`<button type="button" class="mo" data-act="gxStuMore">+${a.length-n}</button>`:''}</div>`:'';
const gxStuSum=(e,full)=>{if(!activeStudents().length)return '';const {r,av,ad}=gxStuAll(e),n=full?999:4,h=gxStuLine('ok','✔ Recomendado para o aluno',r,n)+gxStuLine('ad','◐ Adaptar para o aluno',ad,n)+gxStuLine('no','⚠ Evitar para o aluno',av,n);
 return `<div class="gxst">${h||'<div class="gxsl"><span class="mo">Nenhum aluno ativo com objetivo ou restrição ligados a este exercício.</span></div>'}</div>`};
const gxStuCnt=e=>{if(!activeStudents().length)return '';const {r,av,ad}=gxStuAll(e),b=(c,n,t)=>n?`<button type="button" class="${c}" data-act="gxTabGo" data-k="al">${n} ${t}</button>`:'';
 const h=b('co',r.length,r.length>1?'recomendados':'recomendado')+b('ca',ad.length,'adaptar')+b('cn',av.length,'evitar');
 return `<div class="gxsl gxcnt"><b>👤 Alunos</b>${h||'<span class="mo">nenhum ligado a este exercício</span>'}</div>`};
function gxCard(e,x=''){
  const ck=gxPf&&gxMode!=='stu'?(c=>`<div class="gxck ${c.k}">${esc(c.t)}</div>`)(gxCheck(e,gxPf)):'';
  const{T,f,full}=gxTec(e),own=gxOwn(e),st=(T.ex||e.ex||'').split(/;\s*/).filter(Boolean),cue=T.cue||e.cue;
  const R=(k,l)=>f[k]&&f[k][0]?`<div class="gxr"><span>${l}</span>${esc(f[k][0])}</div>`:'';
  const eq=[...new Set(e.a.map(k=>TU_EQ[k]).filter(Boolean))].join(' '),av=(e.av||[]).map(c=>CL[c]||c);
  const P={
    ex:(st.length?`<ol class="gxo">${st.map(i=>`<li>${esc(i)}</li>`).join('')}</ol>`:`<div class="gxr">${esc(e.b||e.o||'Passo a passo ainda não cadastrado. Complete em “Ficha”.')}</div>`)+R('pos','Posição inicial')+R('resp','Respiração')+gxPh(e)+gxPhBtn(e),
    te:(cue?`<div class="gxq">${esc(cue)}</div>`:'')+R('musc','Músculos-alvo')+R('ind','Indicações clínicas')+`<div class="gxr"><span>Preparação do aparelho</span>${esc(eq)}</div>`,
    cu:R('care','Cuidados')+R('err','Erros comuns')+gxAvHtml(e)+`<div class="gxr"><span>Interromper se</span>dor aguda, formigamento, tontura ou perda de controle da pelve e da coluna.</div>`,
    re:gxRecHtml(e,f),
    pr:R('reg','Regressão')+R('prog','Progressão')+R('dos','Dosagem')};
  const TB=[['ex','Execução'],['te','Técnica'],['re','Indicações'],['cu','Cuidados'],['al','Alunos']];
  P.te+=(P.pr?'<div class="gxr gxsec"><span>Regressão, progressão e dosagem</span></div>'+P.pr:'');
  P.al=gxStuSum(e,true)||'<div class="gxr">Nenhum aluno ativo cadastrado.</div>';P.al+='<div class="sub">Toque em um nome para abrir o Guia com o perfil desse aluno.</div>';
  return `<div class="card gxc" data-id="${esc(e.id)}"><div class="gxh">${gxThumb(e)}<div class="gxn"><h2>${e.fav?'★ ':''}${esc(e.n)}</h2><div class="gxm"><span>${esc(gxEqTxt(e.a))}</span>${e.lv?`<span class="gxd" title="${gxLv[e.lv]}">${'●'.repeat(e.lv)}${'○'.repeat(3-e.lv)}</span><span>${gxLv[e.lv]}</span>`:''}${e.grp?`<span>${esc(e.grp)}</span>`:''}</div></div>${e.sup?'<span class="badge warn">Supervisão</span>':''}</div>`
  +(e.en&&nz(e.en)!==nz(e.n)?`<div class="sub" style="margin-top:6px">Nome original: ${esc(e.en)}</div>`:'')+ck
  +((e.o||e.b)?`<p class="gxob">${esc(e.o||e.b)}</p>`:'')
  +`<div class="gxch">${(f.musc[0]||'').split(/,\s*/).filter(Boolean).slice(0,4).map(m=>`<span>${esc(m)}</span>`).join('')}</div>`+gxSum(e)+gxStuCnt(e)
  +`<div class="gxtabs" role="tablist">${TB.map(([k,l])=>`<button type="button" role="tab" data-act="gxTab" data-k="${k}">${l}</button>`).join('')}</div>`
  +TB.map(([k])=>`<div class="gxp" data-k="${k}" hidden>${P[k]}${k==='te'&&!full?'<div class="sub">Ficha base: gerada a partir do grupo muscular e do nível. Personalize em “Ficha”.</div>':''}</div>`).join('')
  +(e.t&&!T.t?`<div class="sub" style="margin-top:8px">Adaptação: ${esc(e.t)}</div>`:'')
  +(e.fonte_url&&/^https:\/\//i.test(e.fonte_url)?`<div class="sub">Fonte: <a href="${esc(e.fonte_url)}" target="_blank" rel="noopener noreferrer">${esc(e.fonte||'link original')}</a></div>`:'')
  +(own&&gxImg(e.media)?`<img src="${esc(e.media)}" alt="Demonstração: ${esc(e.n)}" loading="lazy" style="max-width:100%;border-radius:12px;margin-top:8px">`:'')
  +`<div class="gxl"><a href="${esc(gxVid(e))}" target="_blank" rel="noopener noreferrer">▶ Vídeo</a><a href="${esc('https://www.google.com/search?tbm=isch&q='+encodeURIComponent('pilates '+(e.en||e.n)+' '+gxQ(e)))}" target="_blank" rel="noopener noreferrer">Imagens</a></div>`
  +x+`</div>`;
}
Object.assign(ACT,{goBack:()=>{const p=navStack.pop()||'dashboard';navBack=true;go(p)},gxTabGo:b=>{const c=b.closest('.gxc'),t=c&&c.querySelector('.gxtabs button[data-k="'+b.dataset.k+'"]');if(t&&!t.classList.contains('on'))t.click();if(t)t.scrollIntoView({block:'nearest',behavior:'smooth'})},gxStuGo:e=>{try{closeModal()}catch{}ACT.gStu(e)},gxStuMore:b=>{b.parentElement.querySelectorAll('.x').forEach(x=>{x.hidden=false});b.remove()},gxTab:b=>{const c=b.closest('.gxc'),on=b.classList.contains('on');c.querySelectorAll('.gxtabs button').forEach(y=>y.classList.remove('on'));c.querySelectorAll('.gxp').forEach(p=>p.hidden=true);if(!on){b.classList.add('on');c.querySelector('.gxp[data-k="'+b.dataset.k+'"]').hidden=false}}});
const gxActs=e=>`<div class="row-acts" style="margin-top:8px;flex-wrap:wrap"><button class="btn sm" data-act="gxFavT" data-id="${e.id}">${e.fav?'Desfavoritar':'Favoritar'}</button><button class="btn sm" data-act="gxAssign" data-id="${e.id}">Aluno</button><button class="btn sm" data-act="gxSeqAdd" data-id="${e.id}">Sequência</button><button class="btn sm" data-act="tuOpen" data-id="${e.id}">Estudar</button><button class="btn sm" data-act="gxEdit" data-id="${e.id}">Ficha</button><button class="btn sm bad" data-act="gxDel" data-id="${e.id}">Excluir</button></div>`;
const gxChk=(cls,arr,sel)=>`<div class="days cg">${arr.map(([k,l])=>`<label><input type="checkbox" class="${cls}" value="${k}"${(sel||[]).includes(k)?' checked':''}>${esc(l)}</label>`).join('')}</div>`;
function gxModal(id){
  const e=id?gxById(id):null;gxCur=id||null;const t=(k,l,r=2)=>`<div class="field full"><label for="gx_${k}">${l}</label><textarea id="gx_${k}" rows="${r}">${esc(e?.[k])}</textarea></div>`;
  openModal(`<h2>${e?'Ficha do exercício':'Novo exercício'}</h2><div class="form"><div class="field full"><label for="gx_n">Nome em português *</label><input id="gx_n" value="${esc(e?.n)}"></div><div class="field full"><label for="gx_en">Nome original (opcional)</label><input id="gx_en" value="${esc(e?.en)}"></div>
  <div class="field full"><label>Equipamentos *</label>${gxChk('gxA',Object.entries(GX_AP),e?.a||['M'])}</div>
  <div class="field"><label for="gx_lv">Nível</label><select id="gx_lv">${[0,1,2,3].map(n=>`<option value="${n}"${n===(e?.lv??1)?' selected':''}>${gxLv[n]}</option>`).join('')}</select></div>
  <div class="field"><label for="gx_grp">Grupo muscular</label><select id="gx_grp">${GXGRS.map(g=>`<option${g===(e?.grp||'Corpo todo')?' selected':''}>${g}</option>`).join('')}</select></div>
  ${t('o','Objetivo principal')}<div class="field full"><label>Serve para melhora de</label>${gxChk('gxG',GOALS,e?.g)}</div><div class="field full"><label>Evitar em</label>${gxChk('gxV',CONDS,e?.av)}</div>
  ${t('musc','Músculos-alvo (principais)',1)}${t('ind','Indicações clínicas')}${t('dos','Dosagem sugerida')}${t('pos','Posição inicial')}${t('ex','Execução',3)}${t('resp','Respiração')}${t('rep','Repetições')}${t('care','Cuidados')}${t('err','Erros comuns')}${t('t','Adaptação para iniciantes')}${t('prog','Progressão para avançados')}
  <div class="field full"><label for="gx_media">Link próprio de imagem ou vídeo (https) — substitui a busca automática</label><input id="gx_media" type="url" inputmode="url" value="${esc(e?.media)}"></div>
  <div class="field full"><label for="gx_thumb">Miniatura: link (https) de uma imagem sua ou autorizada</label><input id="gx_thumb" type="url" inputmode="url" value="${esc(e?.thumb)}"></div>
  <div class="field full"><label class="chk"><input type="checkbox" id="gx_sup"${e?.sup?' checked':''}> Exige supervisão ou cuidado especial</label></div></div>
  <div class="foot"><button class="btn" data-act="closeModal">Cancelar</button><button class="btn primary" data-act="gxSave">Salvar</button></div>`);
}
function gxSave(){
  const v=i=>$('#gx_'+i).value.trim(),n=v('n'),a=$$('.gxA:checked').map(x=>x.value),m=v('media'),th=v('thumb');
  if(!n){$('#gx_n').focus();return toast('Informe o nome do exercício.')}
  if(!a.length)return toast('Selecione ao menos um equipamento.');
  if(m&&!/^https:\/\/[^\s]+$/i.test(m)){$('#gx_media').focus();return toast('O link deve começar com https://')}
  if(th&&!/^https:\/\/[^\s]+$/i.test(th)){$('#gx_thumb').focus();return toast('O link da miniatura deve começar com https://')}
  const L=gxLib(),old=gxCur?gxById(gxCur):null,o={...(old||{fav:false}),id:old?.id||uid('exe'),n,en:v('en'),a,lv:+v('lv'),grp:v('grp'),g:$$('.gxG:checked').map(x=>x.value),av:$$('.gxV:checked').map(x=>x.value),sup:$('#gx_sup').checked,media:m,thumb:th};
  ['o','pos','ex','resp','rep','care','err','prog','t','musc','ind','dos'].forEach(k=>o[k]=v(k));o.b=o.b&&old?o.b:o.o;
  if(old)L[L.indexOf(old)]=o;else L.unshift(o);
  if(!save())return;closeModal();render();toast('Exercício salvo.');
}
function gxPick(title,body,act){openModal(`<h2>${title}</h2><div class="form">${body}</div><div class="foot"><button class="btn" data-act="closeModal">Cancelar</button><button class="btn primary" data-act="${act}">Salvar</button></div>`)}
function rGuide(){
  const L=gxLib(),S=gxSeqs(),sh=(id,on)=>{$('#'+id).hidden=!on};
  $$('#gSeg button').forEach(b=>b.classList.toggle('on',b.dataset.m===gxMode));
  ['gxQ','gxEq','gxLvS','gxGrp','gxFavB'].forEach(i=>sh(i,gxMode==='ex'));sh('gxGoal',gxMode==='goal');sh('gxStu',gxMode!=='seq');sh('gxHideB',gxMode!=='seq'&&gxMode!=='stu'&&!!gxStuSel);
  $('#gxCnt').textContent=`${L.length} exercícios · ${L.filter(e=>gxTec(e).full).length} com ficha técnica completa`;
  $('#gxFavB').classList.toggle('primary',gxFav);
  if(!$('#gxEq').options.length){$('#gxEq').innerHTML='<option value="">Equipamento</option>'+Object.entries(GX_AP).map(([k,l])=>`<option value="${k}">${l}</option>`).join('');$('#gxLvS').innerHTML='<option value="">Nível</option>'+[1,2,3].map(n=>`<option value="${n}">${gxLv[n]}</option>`).join('');$('#gxGrp').innerHTML='<option value="">Grupo muscular</option>'+GXGRS.map(g=>`<option>${g}</option>`).join('');$('#gxGoal').innerHTML=GOALS.map(([k,l])=>`<option value="${k}">${esc(l)}</option>`).join('')}
  $('#gxStu').innerHTML='<option value="">'+(gxMode==='stu'?'Selecione o aluno':'Aluno: sem filtro de condições')+'</option>'+db.students.filter(x=>(x.status||'Ativo')==='Ativo').sort((a,b)=>a.name.localeCompare(b.name,'pt-BR')).map(x=>`<option value="${x.id}"${x.id===gxStuSel?' selected':''}>${esc(x.name)}</option>`).join('');
  const stuSel=gxStuSel&&studentById(gxStuSel),ban=l=>{if(!stuSel)return '';const n=l.filter(e=>gxCheck(e,gxPf).k==='avoid').length;return `<div class="card"><b>${esc(stuSel.name)}</b><div class="sub" style="color:var(--ink);line-height:1.6">Condições: ${gxPf.cond.size?esc([...gxPf.cond].map(c=>CL[c]||c).join(', ')):'nenhuma informada'}${stuSel.injuries?'<br>Lesões/cirurgias: '+esc(stuSel.injuries):''}<br>${n} de ${l.length} exercícios desta lista estão marcados para evitar neste perfil.</div></div>`};
  gxPf=stuSel?gxProfile(stuSel):null;$('#gxHideB').textContent=gxHide?'Ocultando exercícios a evitar':'Mostrando todos';$('#gxHideB').classList.toggle('primary',gxHide);
  const o=$('#gxOut'),more=n=>n>gxShown?`<button class="btn" data-act="gxMore" style="width:100%;justify-content:center">Mostrar mais (${n-gxShown})</button>`:'';
  if(gxMode==='ex'){
    const q=norm(gxVal('gxQ')),eq=gxVal('gxEq'),lv=gxVal('gxLvS'),gr=gxVal('gxGrp');
    const l0=L.filter(e=>(!q||norm([e.n,e.en,e.o,e.b,gxEqTxt(e.a),e.g.map(g=>GL[g]).join(' ')].join(' ')).includes(q))&&(!eq||e.a.includes(eq))&&(!lv||e.lv===+lv)&&(!gr||e.grp===gr)&&(!gxFav||e.fav)),l=stuSel&&gxHide?l0.filter(e=>gxCheck(e,gxPf).k!=='avoid'):l0;
    o.innerHTML=ban(l0)+`<div class="sub" style="margin:8px 0">${l.length} exercício(s)</div>`+(l.slice(0,gxShown).map(e=>gxCard(e,gxActs(e))).join('')||'<div class="card empty">Nenhum exercício encontrado.</div>')+more(l.length);return}
  if(gxMode==='goal'){
    const g=gxVal('gxGoal'),l0=L.filter(e=>e.g.includes(g)).sort((a,b)=>a.lv-b.lv),l=stuSel&&gxHide?l0.filter(e=>gxCheck(e,gxPf).k!=='avoid'):l0;
    o.innerHTML=ban(l0)+`<div class="card"><b>${esc(GL[g])}</b><div class="sub">${l.length} exercícios · Aparelhos: ${esc(gxEqTxt([...new Set(l.flatMap(e=>e.a))]))}</div></div>`+l.slice(0,gxShown).map(e=>gxCard(e)).join('')+more(l.length);return}
  if(gxMode==='seq'){
    o.innerHTML=`<div class="row-acts" style="margin:8px 0"><button class="btn primary sm" data-act="gxSeqNew">+ Sequência</button></div>`+(S.map(q=>`<div class="card"><div class="head" style="margin:0 0 6px"><h2 style="margin:0">${esc(q.name)}</h2><span class="badge">${q.items.length}</span></div>${q.items.map((id,i)=>{const e=gxById(id);return e?`<div class="item"><div style="min-width:0"><b>${i+1}. ${esc(e.n)}</b><div class="sub">${esc(gxEqTxt(e.a))} · ${gxLv[e.lv]}</div></div><div class="row-acts"><button class="btn sm" data-act="gxSeqMv" data-id="${q.id}" data-i="${i}" data-d="-1" aria-label="Subir">↑</button><button class="btn sm" data-act="gxSeqMv" data-id="${q.id}" data-i="${i}" data-d="1" aria-label="Descer">↓</button><button class="btn sm bad" data-act="gxSeqRm" data-id="${q.id}" data-i="${i}" aria-label="Remover">✕</button></div></div>`:''}).join('')||'<div class="sub">Sequência vazia. Adicione pela Biblioteca (botão Sequência).</div>'}<div class="row-acts" style="margin-top:8px"><button class="btn sm bad" data-act="gxSeqDel" data-id="${q.id}">Excluir sequência</button></div></div>`).join('')||'<div class="card empty">Nenhuma sequência criada.</div>');return}
  const s=gxStuSel&&studentById(gxStuSel);
  if(!s){o.innerHTML='<div class="card empty">Selecione um aluno para ver as sugestões.</div>';return}
  const p=gxPlan(s),mob=(MOBS.find(m=>m[0]===String(s.mobility))||MOBS[1])[1].split(' (')[0],lvl=(LEVELS.find(m=>m[0]===String(s.level))||LEVELS[0])[1],pl=s.exercises||[];
  const head=`<div class="card"><div class="head" style="margin:0 0 6px"><h2 style="margin:0">${esc(s.name)}</h2><button class="btn sm" data-act="editStudent" data-id="${s.id}">Editar cadastro</button></div><div class="sub" style="color:var(--ink);line-height:1.7">Objetivo${goalsP(s).length>1?'s':''}: ${esc(goalsP(s).map(k=>GL[k]).join('; ')||s.goal||'—')}${(s.goalKeys2||[]).length?' · também: '+esc(s.goalKeys2.map(k=>GL[k]||k).join(', ')):''}<br>Diagnóstico: ${esc(s.clinical?.diagnosis||'—')} · Dor (EVA): ${s.clinical?.painScore!==undefined&&s.clinical?.painScore!==''?esc(s.clinical.painScore)+'/10':'—'} · Liberação médica: ${esc(s.medClear||'—')}<br>Queixa: ${esc(s.complaint||s.clinical?.complaint||'—')}<br>Idade: ${p.age!==''?p.age+' anos':'—'} · Mobilidade: ${esc(mob)} · Nível: ${esc(lvl)}<br>Condições: ${p.cond.length?esc(p.cond.map(c=>CL[c]).join(', ')):'nenhuma informada'}${s.injuries?'<br>Lesões/cirurgias: '+esc(s.injuries):''}</div></div>`
   +`<div class="card"><h2>Plano do aluno (${pl.length})</h2>${pl.map(x=>{const e=gxById(x.id);return e?`<div class="item"><div style="min-width:0"><b>${esc(e.n)}</b><div class="sub">${esc(gxEqTxt(e.a))}${x.note?' · '+esc(x.note):''} · <a href="${esc(gxVid(e))}" target="_blank" rel="noopener noreferrer">▶ vídeo</a></div></div><div class="row-acts"><button class="btn sm" data-act="gxPlNote" data-id="${x.id}">Nota</button><button class="btn sm bad" data-act="gxPlRm" data-id="${x.id}" aria-label="Remover">✕</button></div></div>`:''}).join('')||'<div class="sub">Nenhum exercício associado. Use "Aluno" na Biblioteca ou "Adicionar ao plano" abaixo.</div>'}</div>`;
  if(!GL[s.goalKey]){o.innerHTML=head+'<div class="card empty">Defina o objetivo principal no cadastro do aluno para gerar sugestões.</div>';return}
  const eq=p.eq.map(k=>{const has=db.equipment.some(e=>e.active!==false&&GX_RX[k].test(e.name+' '+(e.category||'')));return `<span class="badge ${has?'ok':'warn'}">${GX_AP[k]}${has?'':' · não cadastrado'}</span>`}).join(' ');
  o.innerHTML=head+`<div class="card"><h2>Aparelhos sugeridos</h2><div style="display:flex;gap:6px;flex-wrap:wrap">${eq||'<span class="sub">Trabalho de solo recomendado.</span>'}</div>${p.tips.length?`<div class="sub" style="margin-top:10px;color:var(--ink);line-height:1.6">${p.tips.map(t=>'• '+esc(t)).join('<br>')}</div>`:''}</div>`
   +(p.ok.length?p.ok.map(e=>gxCard(e,`<div class="row-acts" style="margin-top:8px"><button class="btn sm" data-act="gxPlAdd" data-id="${e.id}"${pl.some(x=>x.id===e.id)?' disabled':''}>Adicionar ao plano</button></div>`)).join(''):'<div class="card empty">Nenhum exercício liberado para este perfil. Revise o cadastro.</div>')
   +(p.no.length?`<details class="card sec"><summary><b>Evitados para este aluno (${p.no.length})</b></summary>${p.no.map(([e,r])=>`<div class="item"><b>${esc(e.n)}</b><span class="sub">${esc(r)}</span></div>`).join('')}</details>`:'')
   +'<div class="sub" style="margin-top:8px">Apoio à decisão: a conduta final depende da avaliação presencial e, havendo condição clínica, da liberação médica. Condicionamento físico não substitui tratamento de patologias.</div>';
}
['gxQ','gxEq','gxLvS','gxGrp','gxGoal'].forEach(i=>$('#'+i).addEventListener('input',()=>{gxShown=40;rGuide()}));
$('#gSeg').addEventListener('click',e=>{const b=e.target.closest('button');if(!b)return;gxMode=b.dataset.m;gxShown=40;rGuide()});
$('#gxStu').addEventListener('change',e=>{gxStuSel=e.target.value;rGuide()});
const gxSeq=id=>gxSeqs().find(q=>q.id===id),gxSt=()=>studentById(gxStuSel);
Object.assign(ACT,{
  gStu:e=>{gxMode='stu';gxStuSel=e.dataset.id;go('guide')},gxMore:()=>{gxShown+=40;rGuide()},gxHide:()=>{gxHide=!gxHide;gxShown=40;rGuide()},gxFavF:()=>{gxFav=!gxFav;gxShown=40;rGuide()},
  gxNew:()=>gxModal(),gxEdit:e=>gxModal(e.dataset.id),gxSave,
  gxFavT:e=>{const x=gxById(e.dataset.id);if(x){x.fav=!x.fav;save();rGuide()}},
  gxDel:e=>{const x=gxById(e.dataset.id);if(!x||!confirm(`Excluir "${x.n}" da biblioteca? Ele sai também dos planos e sequências.`))return;
    db.exLib=gxLib().filter(y=>y!==x);db.students.forEach(s=>{if(s.exercises)s.exercises=s.exercises.filter(p=>p.id!==x.id)});gxSeqs().forEach(q=>q.items=q.items.filter(i=>i!==x.id));save();rGuide();toast('Exercício excluído.')},
  gxAssign:e=>{gxCur=e.dataset.id;gxPick('Associar ao aluno',`<div class="field full"><label for="gx_stu">Aluno</label><select id="gx_stu">${db.students.filter(s=>(s.status||'Ativo')==='Ativo').map(s=>`<option value="${s.id}"${s.id===gxStuSel?' selected':''}>${esc(s.name)}</option>`).join('')}</select></div><div class="field full"><label for="gx_note">Observação para este aluno</label><textarea id="gx_note" rows="3"></textarea></div>`,'gxAssignSave')},
  gxAssignSave:()=>{const s=studentById($('#gx_stu').value);if(!s)return toast('Selecione um aluno.');const x0=gxById(gxCur),k0=x0&&gxCheck(x0,gxProfile(s));if(k0&&k0.k==='avoid'&&!confirm(`${k0.t}. Associar mesmo assim a ${s.name}?`))return;if(!Array.isArray(s.exercises))s.exercises=[];
    const n=$('#gx_note').value.trim(),x=s.exercises.find(p=>p.id===gxCur);if(x)x.note=n||x.note;else s.exercises.push({id:gxCur,note:n});s.updatedAt=new Date().toISOString();if(!save())return;closeModal();toast('Exercício associado ao aluno.')},
  gxPlAdd:e=>{const s=gxSt();if(!s)return;if(!Array.isArray(s.exercises))s.exercises=[];s.exercises.push({id:e.dataset.id,note:''});save();rGuide();toast('Adicionado ao plano.')},
  gxPlRm:e=>{const s=gxSt();if(!s)return;s.exercises=(s.exercises||[]).filter(p=>p.id!==e.dataset.id);save();rGuide()},
  gxPlNote:e=>{const s=gxSt(),x=s&&(s.exercises||[]).find(p=>p.id===e.dataset.id);if(!x)return;const n=prompt('Observação para este aluno:',x.note||'');if(n!==null){x.note=n.trim().slice(0,500);save();rGuide()}},
  gxSeqAdd:e=>{gxCur=e.dataset.id;gxPick('Adicionar à sequência',`<div class="field full"><label for="gx_sq">Sequência</label><select id="gx_sq"><option value="">+ Nova sequência</option>${gxSeqs().map(q=>`<option value="${q.id}">${esc(q.name)}</option>`).join('')}</select></div><div class="field full"><label for="gx_sqn">Nome da nova sequência</label><input id="gx_sqn" maxlength="60"></div>`,'gxSeqAddSave')},
  gxSeqAddSave:()=>{let q=gxSeq($('#gx_sq').value);if(!q){const n=$('#gx_sqn').value.trim();if(!n){$('#gx_sqn').focus();return toast('Informe o nome da sequência.')}q={id:uid('seq'),name:n,items:[]};gxSeqs().push(q)}
    q.items.push(gxCur);if(!save())return;closeModal();toast('Adicionado à sequência.')},
  gxSeqNew:()=>{const n=prompt('Nome da sequência:');if(n&&n.trim()){gxSeqs().push({id:uid('seq'),name:n.trim().slice(0,60),items:[]});save();rGuide()}},
  gxSeqRm:e=>{const q=gxSeq(e.dataset.id);if(q){q.items.splice(+e.dataset.i,1);save();rGuide()}},
  gxSeqMv:e=>{const q=gxSeq(e.dataset.id),i=+e.dataset.i,j=i+ +e.dataset.d;if(q&&j>=0&&j<q.items.length){[q.items[i],q.items[j]]=[q.items[j],q.items[i]];save();rGuide()}},
  gxSeqDel:e=>{const q=gxSeq(e.dataset.id);if(q&&confirm(`Excluir a sequência "${q.name}"?`)){db.exSeq=gxSeqs().filter(x=>x!==q);save();rGuide()}}
});

const gxKey=e=>nz(e.en||e.n).replace(/^the /,'').replace(/s$/,'')+'|'+[...new Set(e.a.map(fam))].sort().join(',');
const gxClean=r=>{
  if(!r||typeof r.n!=='string'||!r.n.trim())return null;
  const a=(Array.isArray(r.a)?r.a:[]).filter(k=>GX_AP[k]);if(!a.length)return null;
  const s=(v,m=400)=>typeof v==='string'?v.trim().slice(0,m):'',u=v=>typeof v==='string'&&/^https:\/\/[^\s]+$/i.test(v.trim())?v.trim().slice(0,500):'',ar=(v,M)=>(Array.isArray(v)?v:[]).filter(k=>M[k]);
  return{id:uid('exe'),n:s(r.nome_pt||r.n,120),en:s(r.nome_original||r.en,120),a,lv:[0,1,2,3].includes(+r.lv)?+r.lv:0,o:s(r.o),g:ar(r.g,GL),av:ar(r.av,CL),b:s(r.b),t:s(r.t),grp:GXGRS.includes(r.grp)?r.grp:'Corpo todo',sup:!!r.sup,fav:false,media:u(r.media),thumb:u(r.thumb||r.miniatura),pos:s(r.pos),ex:s(r.ex,1200),resp:s(r.resp),rep:s(r.rep),care:s(r.care),err:s(r.err),prog:s(r.prog),musc:s(r.musc),ind:s(r.ind,600),dos:s(r.dos),fonte:s(r.fonte,80),fonte_url:u(r.fonte_url)};
};
function gxImport(file){
  const rd=new FileReader();rd.onerror=()=>toast('Não foi possível ler o arquivo.');
  rd.onload=()=>{try{
    const d=JSON.parse(rd.result),arr=Array.isArray(d)?d:(d.exercicios||d.exercises);if(!Array.isArray(arr))throw 0;
    const L=gxLib(),idx=new Map(L.map(e=>[gxKey(e),e]));let add=0,dup=0,bad=0,upd=0;
    arr.slice(0,2000).forEach(r=>{const c=gxClean(r);if(!c){bad++;return}const k=gxKey(c),ex=idx.get(k);
      if(ex){dup++;if(!ex.fonte_url&&c.fonte_url){ex.fonte=c.fonte;ex.fonte_url=c.fonte_url;upd++}return}
      L.push(c);idx.set(k,c);add++});
    if(!save())return;rGuide();toast(`${add} novos · ${dup} já existiam${upd?` (${upd} receberam fonte)`:''}${bad?` · ${bad} ignorados`:''}`);
  }catch{toast('Arquivo JSON inválido.')}};
  rd.readAsText(file);
}
function gxExport(){
  const b=new Blob([JSON.stringify({versao:1,gerado_em:iso(new Date()),exercicios:gxLib()},null,1)],{type:'application/json'}),a=document.createElement('a');
  a.href=URL.createObjectURL(b);a.download='biblioteca_pilates_louise_karla.json';document.body.appendChild(a);a.click();a.remove();setTimeout(()=>URL.revokeObjectURL(a.href),1000);
}
Object.assign(ACT,{gxImp:()=>$('#gxFile').click(),gxExp:gxExport});
$('#gxFile').addEventListener('change',e=>{const f=e.target.files[0];e.target.value='';if(f&&f.size<5e6)gxImport(f);else if(f)toast('Arquivo grande demais (máx. 5 MB).')});



/* ========== OBJETIVO PRINCIPAL (seletor dinâmico) + SAÍDA DO ALUNO ========== */
const GP_COND={hernia:'hernia',osteo:'osteo',gest:'gest',diast:'diast',cerv:'cervical',lomb:'lombar',esco:'escoli',fibro:'fibro',ombro:'ombro',joelho:'joelho',quadril:'quadril',resp:'resp',cardio:'cardio',obes:'cond',diab:'cardio',pos:'pos',artrose:'mq'};
let gpS={p:[],s:[],m:'p'};
const goalsP=s=>{const a=(s?.goalKeys1||[]).filter(k=>GL[k]);return a.length?a:(s?.goalKey&&GL[s.goalKey]?[s.goalKey]:[])},gpLabels=()=>gpS.p.map(k=>GL[k]).filter(Boolean).join('; ');
const goalPicker=s=>{const p=goalsP(s);gpS={p,s:(s?.goalKeys2||[]).filter(k=>GL[k]&&!p.includes(k)),m:'p'};return `<div class="field full"><label for="fGoalQ">Objetivos do aluno (geram as sugestões de exercícios)</label><input type="hidden" id="fGoalKey" value="${esc(p[0])}"><div class="gpm" id="gpMode" role="group" aria-label="Marcar como"></div><div id="gpSel"></div><input id="fGoalQ" type="search" placeholder="Buscar objetivo (ex.: lombar, ombro, gestante)" autocomplete="off"><div id="gpList"></div></div>`};
function gpRender(){if(!$('#gpSel'))return;
  const q=norm($('#fGoalQ').value),L=gxLib(),all=[...gpS.p,...gpS.s],ex=[...new Map(L.filter(e=>all.some(g=>(e.g||[]).includes(g))).map(e=>[e.id,e])).values()],
    sug=[...new Set($$('.fCond:checked').map(c=>GP_COND[c.value]).filter(Boolean))].filter(g=>!all.includes(g));
  $('#fGoalKey').value=gpS.p[0]||'';
  $('#gpMode').innerHTML=[['p','Principal',gpS.p.length],['s','Secundário',gpS.s.length]].map(([m,t,n])=>`<button type="button" class="gpc${gpS.m===m?(m==='p'?' on':' on2'):''}" data-act="gpMode" data-m="${m}" aria-pressed="${gpS.m===m}">Marcar como ${t}${n?' · '+n:''}</button>`).join('');
  const row=(t,a,c)=>`<div class="gpg" style="margin-top:0">${t}</div><div class="gpw">${a.length?a.map(k=>`<button type="button" class="gpc ${c}" data-act="gpDel" data-k="${k}" aria-label="Remover ${esc(GL[k])}">${esc(GL[k].split(' (')[0])} ✕</button>`).join(''):'<span class="sub">Nenhum</span>'}</div>`;
  $('#gpSel').innerHTML=`<div class="gpbox" style="align-items:stretch">${row('Principais',gpS.p,'on')}${row('Secundários',gpS.s,'on2')}<div class="sub">${all.length?`${ex.length} exercícios sugeridos · ${esc(gxEqTxt([...new Set(ex.flatMap(e=>e.a))])||'—')}`:'Escolha abaixo. Você pode marcar mais de um em cada grupo; toque de novo para desmarcar.'}</div>${all.length?'<button type="button" class="btn sm" data-act="gpClear" style="align-self:flex-start">Limpar tudo</button>':''}</div>`+(sug.length?`<div class="sub">Sugerido pelas condições marcadas:</div><div class="gpw" style="margin-bottom:6px">${sug.map(g=>`<button type="button" class="gpc" data-act="gpPick" data-k="${g}">${esc(GL[g])}</button>`).join('')}</div>`:'');
  $('#gpList').innerHTML=GOAL_GROUPS.map(([t,ks])=>{const r=ks.filter(g=>!q||norm(GL[g]).includes(q));return r.length?`<div class="gpg">${esc(t)}</div><div class="gpw">${r.map(g=>{const a=gpS.p.includes(g),b=gpS.s.includes(g);return `<button type="button" class="gpc${a?' on':b?' on2':''}" data-act="gpPick" data-k="${g}" aria-pressed="${a||b}">${a?'★ ':b?'✓ ':''}${esc(GL[g])}</button>`}).join('')}</div>`:''}).join('')||'<div class="sub">Nenhum objetivo encontrado.</div>'}
const goalSec=()=>'';
const PF_RS=['Mudança de cidade','Questão financeira','Saúde / afastamento médico','Horário incompatível','Objetivo alcançado / alta','Insatisfação','Sem retorno / abandono','Outro'];
const exitFields=s=>`<div class="field" id="fExD"><label for="fExitDate">Data da saída / trancamento</label><input id="fExitDate" type="date" value="${esc(s?.exitDate)}"></div><div class="field" id="fExR"><label for="fExitReason">Motivo</label><select id="fExitReason"><option value="">—</option>${opts(PF_RS,s?.exitReason)}</select></div><div class="field full" id="fExN"><label for="fExitNote">Observações da saída</label><textarea id="fExitNote" rows="2">${esc(s?.exitNote)}</textarea></div>`;
function exitSync(ch){const st=$('#fStatus').value,on=st==='Inativo'||st==='Trancado';['fExD','fExR','fExN'].forEach(i=>$('#'+i).style.display=on?'':'none');if(on&&ch&&!$('#fExitDate').value)$('#fExitDate').value=iso(new Date())}
const exitVals=v=>{const on=['Inativo','Trancado'].includes(v('fStatus'));return{exitDate:on?v('fExitDate'):'',exitReason:on?v('fExitReason'):'',exitNote:on?v('fExitNote'):''}};
Object.assign(ACT,{gpPick:e=>{const k=e.dataset.k,m=gpS.m,o=m==='p'?'s':'p';if(!GL[k])return;if(gpS[m].includes(k))gpS[m]=gpS[m].filter(x=>x!==k);else{gpS[o]=gpS[o].filter(x=>x!==k);gpS[m].push(k)}gpRender()},
  gpDel:e=>{const k=e.dataset.k;gpS.p=gpS.p.filter(x=>x!==k);gpS.s=gpS.s.filter(x=>x!==k);gpRender()},
  gpMode:e=>{gpS.m=e.dataset.m==='s'?'s':'p';gpRender()},gpClear:()=>{gpS.p=[];gpS.s=[];gpRender()},stuPdf:e=>pfOpen(e.dataset.id)});

/* ========== FICHA COMPLETA DO ALUNO (impressão / PDF) ========== */
const pv=x=>x===undefined||x===null||x===''?'—':String(x);
const pfR=a=>`<tr>${a.map(x=>`<td>${esc(pv(x))}</td>`).join('')}</tr>`;
const pfT=(hd,rows)=>`<table class="pft"><thead><tr>${hd.map(x=>`<th>${esc(x)}</th>`).join('')}</tr></thead><tbody>${rows.join('')||`<tr><td colspan="${hd.length}">Nenhum registro.</td></tr>`}</tbody></table>`;
const pfK=a=>`<table class="pft kv"><tbody>${a.map(([k,v])=>`<tr><th>${esc(k)}</th><td>${esc(pv(v))}</td></tr>`).join('')}</tbody></table>`;
const pfS=(t,b)=>`<section class="pfs"><h2>${esc(t)}</h2>${b}</section>`;
function fichaHTML(s,O){
  O=O||{};const since=O.months?(()=>{const d=new Date();d.setMonth(d.getMonth()-O.months);return iso(d)})():'',inP=d=>!since||String(d||'')>=since,inc=k=>!O.sec||O.sec.includes(k);let secN=0;
  const today=iso(new Date()),cl=db.classes.filter(c=>c.studentId===s.id&&inP(c.date)).sort(sortCls),fin=db.finance.filter(f=>f.studentId===s.id&&inP(f.dueDate)).sort((a,b)=>String(a.dueDate).localeCompare(String(b.dueDate))),mk=db.makeups.filter(m=>m.studentId===s.id&&inP(m.originalDate)),
  evAll=[...(s.evolution||[])].sort((a,b)=>String(a.date).localeCompare(String(b.date))),ev=evAll.filter(e=>inP(e.date)),c=s.clinical||{},it=s.intake,I=it||{},ev0=evAll[0]||{},n=k=>cl.filter(x=>x.status===k).length,done=n('Realizada'),miss=n('Falta'),canc=n('Cancelada'),
  fut=cl.filter(x=>x.date>=today&&['Agendada','Confirmada'].includes(x.status)).length,st=s.status||'Ativo',out=st==='Inativo'||st==='Trancado',start=s.startDate||String(s.createdAt||'').slice(0,10),end=out&&s.exitDate?s.exitDate:today,
  meses=start?Math.max(0,Math.round((new Date(end+'T12:00')-new Date(start+'T12:00'))/2629800000)):'',cn=a=>(a||[]).map(k=>CL[k]).filter(Boolean).join(', '),
  mob=m=>((MOBS.find(x=>x[0]===String(m))||[0,''])[1]).split(' (')[0],lvl=m=>(LEVELS.find(x=>x[0]===String(m))||[0,''])[1],EL=Object.fromEntries(EF.map(x=>[x[0],x[1]])),sc=['painBefore','painAfter','functionalScore','mobilityScore','strengthScore','balanceScore','controlScore'],
  M={},eqc={},finS=f=>f.status==='Pago'?'Pago':lateOf(f)?'Vencido':'A vencer',sum=a=>a.reduce((t,f)=>t+Number(f.value||0),0);
  cl.forEach(x=>{const k=x.date.slice(0,7),o=M[k]=M[k]||{t:0,r:0,f:0,c:0};o.t++;if(x.status==='Realizada')o.r++;else if(x.status==='Falta')o.f++;else if(x.status==='Cancelada')o.c++});
  cl.filter(x=>x.equipmentId&&x.status!=='Cancelada').forEach(x=>{const o=eqc[x.equipmentId]=eqc[x.equipmentId]||{q:0,d:''};o.q++;if(x.date<=today&&x.date>o.d)o.d=x.date});const tq=Object.values(eqc).reduce((t,o)=>t+o.q,0);
  const pago=fin.filter(f=>f.status==='Pago'),aber=fin.filter(f=>f.status!=='Pago'),venc=aber.filter(lateOf);
  const fullDoc=!O.sec||O.sec.length>=12;
  let h=`<div class="pf">${O.head===false?'':lhHTML()}<div class="pftt"><h1>${fullDoc?'Ficha completa do aluno':'Ficha do aluno'}</h1><div class="pfm">Gerada em ${esc(new Date().toLocaleString('pt-BR'))}<br>Situação: <b>${esc(st)}</b>${since?`<br>Período: desde ${esc(fmtDate(since))}`:''}</div></div><div style="border-bottom:1px solid #999;margin:4px 0 10px"></div>`;
  const S=(k,t,b)=>{if(!inc(k))return;secN++;h+=pfS(secN+'. '+t,b)};
  S('ident','Identificação',pfK([['Aluno',s.name],['Nascimento / idade',s.birth?fmtDate(s.birth)+' · '+ageOf(s.birth)+' anos':''],['WhatsApp',s.whatsapp],['Plano',`${s.plan||'—'} · ${money(s.monthly)}/mês · vence dia ${s.due||'—'}`],['Professor(a) e horário',`${s.teacher||'—'}${tpReg(s.teacher)?' ('+tpReg(s.teacher)+')':''} · ${(s.days||[]).map(d=>DAY[d]).join(', ')} ${s.time||''}`],['Início no estúdio',start?fmtDate(start):''],['Tempo de estúdio',meses!==''?meses+' mês(es)'+(out?' (até a saída)':''):''],['Situação',st]]));
  if(out)S('saida',st==='Inativo'?'Saída definitiva do estúdio':'Matrícula trancada',pfK([['Data',s.exitDate?fmtDate(s.exitDate):'Não registrada'+(s.updatedAt?' (última atualização: '+fmtDate(String(s.updatedAt).slice(0,10))+')':'')],['Motivo',s.exitReason],['Observações',s.exitNote],['Aulas realizadas no total',done],['Saldo em aberto',money(sum(aber))]]));
  S('chegada','Condições na chegada × situação atual',(it?'':'<p class="pfn" style="margin:0 0 4px">Registro de chegada não disponível (aluno cadastrado antes deste recurso). Usada a primeira evolução, quando existir.</p>')+pfT(['Item',it?'Na chegada ('+fmtDate(I.date)+')':'Na chegada','Situação atual'],[['Condições de saúde',cn(I.conditions),cn(s.conditions)],['Lesões e cirurgias',I.injuries,s.injuries],['Queixa principal',it?I.complaint:ev0.complaint,s.complaint||c.complaint],['Diagnóstico / CID',I.diagnosis,c.diagnosis],['Dor EVA (0–10)',it?I.pain:ev0.painBefore,c.painScore],['Mobilidade',it?mob(I.mobility):'',mob(s.mobility)],['Experiência com Pilates',it?lvl(I.level):'',lvl(s.level)],['Liberação médica',I.medClear,s.medClear],['Objetivo',I.goal,s.goal||GL[s.goalKey]]].map(pfR)));
  S('obj','Objetivos',pfK([[goalsP(s).length>1?'Principais':'Principal',goalsP(s).map(k=>GL[k]).join('; ')||s.goal],['Secundários',(s.goalKeys2||[]).map(k=>GL[k]).join('; ')],['Detalhes',s.goal],['Observações gerais',s.notes]]));
  S('freq','Frequência',pfK([['Aulas registradas',cl.length],['Realizadas',done],['Faltas',miss],['Canceladas',canc],['Agendadas daqui para frente',fut],['Frequência (realizadas ÷ realizadas + faltas)',done+miss?Math.round(done/(done+miss)*100)+'%':''],['Primeira / última aula',cl.length?fmtDate(cl[0].date)+' / '+fmtDate(cl[cl.length-1].date):'']])+'<div style="height:6px"></div>'+pfT(['Mês','Aulas','Realizadas','Faltas','Canceladas'],Object.keys(M).sort().reverse().map(k=>pfR([k.slice(5)+'/'+k.slice(0,4),M[k].t,M[k].r,M[k].f,M[k].c]))));
  S('evo','Evolução clínica ('+ev.length+' registro(s))',pfT(['Data','Título','Dor antes','Dor depois','Funcional','Mobilid.','Força','Equilíbrio','Controle'],ev.map(e=>pfR([fmtDate(e.date),e.title,e.painBefore,e.painAfter,e.functionalScore,e.mobilityScore,e.strengthScore,e.balanceScore,e.controlScore])))+ev.map(e=>`<div class="pfe"><h3>${esc(fmtDate(e.date))} · ${esc(pv(e.title))}</h3>${pfK(EF.filter(([k])=>!['title','date',...sc].includes(k)&&e[k]!==undefined&&e[k]!=='').map(([k,l])=>[l,k==='nextReview'?fmtDate(e[k]):k==='professional'&&tpReg(e[k])?e[k]+' — '+tpReg(e[k]):e[k]]))}</div>`).join(''));
  const pl=(s.exercises||[]).map(x=>({x,e:gxById(x.id)})).filter(r=>r.e);
  S('plano','Plano de exercícios do aluno',pfT(['Exercício','Aparelho','Observação'],pl.map(r=>pfR([r.e.n,gxEqTxt(r.e.a),r.x.note]))));
  S('rod','Rodízio de aparelhos',pfT(['Aparelho','Aulas','%','Último uso'],Object.entries(eqc).sort((a,b)=>b[1].q-a[1].q).map(([id,o])=>pfR([eqById(id)?.name||'Aparelho removido',o.q,tq?Math.round(o.q/tq*100)+'%':'',o.d?fmtDate(o.d):'']))));
  S('aulas','Histórico de aulas ('+cl.length+')',pfT(['Data','Dia','Hora','Professor(a)','Aparelho','Situação','Observações'],[...cl].reverse().map(x=>pfR([fmtDate(x.date),DAY[new Date(x.date+'T12:00').getDay()],x.time,x.teacher,eqById(x.equipmentId)?.name,x.status,x.notes]))));
  S('fin','Financeiro',pfK([['Total pago',money(sum(pago))+' ('+pago.length+' lançamento(s))'],['Em aberto',money(sum(aber))+' ('+aber.length+')'],['Vencido',money(sum(venc))+' ('+venc.length+')']])+'<div style="height:6px"></div>'+pfT(['Vencimento','Descrição','Valor','Situação','Pago em','Forma'],fin.map(f=>pfR([fmtDate(f.dueDate),f.description,money(f.value),finS(f),f.paidAt?fmtDate(f.paidAt):'',f.paymentMethod]))));
  S('rep','Reposições',pfT(['Aula original','Nova aula','Situação','Observações'],mk.map(m=>pfR([fmtDate(m.originalDate),m.newDate?fmtDate(m.newDate)+' '+(m.newTime||''):'',m.status,m.notes]))));
  S('hist','Histórico de situação do cadastro',pfT(['Data','De','Para','Motivo'],[...(s.statusLog||[])].reverse().map(l=>pfR([fmtDate(l.date),l.from||'Cadastro',l.to,l.reason]))||[])+`<p class="pfn">Cadastro criado em ${esc(s.createdAt?fmtDate(String(s.createdAt).slice(0,10)):'—')} · última atualização em ${esc(s.updatedAt?fmtDate(String(s.updatedAt).slice(0,10)):'—')}.</p>`);
  return h+(O.sign===false?'':`<div class="pfsig"><div>Responsável do estúdio${(()=>{const l=lhGet(),a=[l.resp,l.reg].filter(Boolean);return a.length?`<small>${a.map(esc).join(' · ')}</small>`:''})()}</div><div>Aluno(a) / responsável</div></div>`)+`<p class="pfn">Documento confidencial: contém dados pessoais e de saúde (LGPD, Lei 13.709/2018). Uso restrito ao estúdio e ao próprio aluno.${lhGet().note?' '+esc(lhGet().note):''}</p></div>`}
function fichaPrint(sid,O){const s=studentById(sid);if(!s)return;closeModal();let a=$('#printArea');if(!a){a=document.createElement('div');a.id='printArea';document.body.appendChild(a)}
  a.innerHTML=fichaHTML(s,O);const t=document.title,done=()=>{document.title=t;a.innerHTML='';window.removeEventListener('afterprint',done)};document.title='Ficha - '+s.name+' - '+iso(new Date());window.addEventListener('afterprint',done);toast('Na tela de impressão, escolha “Salvar como PDF”.');setTimeout(()=>window.print(),400)}
const PF_SECS=[['ident','Identificação'],['saida','Saída / trancamento'],['chegada','Chegada × atual'],['obj','Objetivos'],['freq','Frequência'],['evo','Evolução clínica'],['plano','Plano de exercícios'],['rod','Rodízio de aparelhos'],['aulas','Histórico de aulas'],['fin','Financeiro'],['rep','Reposições'],['hist','Histórico do cadastro']];
const PF_PRE={full:['Completa',PF_SECS.map(x=>x[0])],resumo:['Resumida',['ident','saida','obj','freq','plano']],clinica:['Clínica',['ident','chegada','obj','evo','plano']],fin:['Financeira',['ident','freq','fin','rep']]};
let pfSid='';
const pfPrefs=()=>{const p=db.settings.pdfPrefs||{};return{sec:Array.isArray(p.sec)?p.sec.filter(k=>PF_SECS.some(x=>x[0]===k)):PF_SECS.map(x=>x[0]),months:[0,3,6,12].includes(p.months)?p.months:0,head:p.head!==false,sign:p.sign!==false}};
const pfRead=()=>({sec:$$('.pfSec:checked').map(x=>x.value),months:Number($('#pfPer').value)||0,head:$('#pfHead').checked,sign:$('#pfSign').checked});
function pfPrev(){
  const s=studentById(pfSid);if(!s||!$('#pfPrev'))return;const O=pfRead();
  $('#pfCount').textContent='· '+O.sec.length+' de '+PF_SECS.length;
  $$('[data-act=pfPre]').forEach(b=>{const a=PF_PRE[b.dataset.p][1],on=a.length===O.sec.length&&a.every(k=>O.sec.includes(k));b.classList.toggle('on',on);b.setAttribute('aria-pressed',on)});
  $('#pfPrev').innerHTML=O.sec.length?fichaHTML(s,O):'<div class="sub" style="color:#444">Marque ao menos uma seção.</div>';
  $('#pfGo').disabled=!O.sec.length;
}
function pfOpen(id){
  const s=studentById(id);if(!s)return;pfSid=id;const P=pfPrefs();
  openModal(`<h2>Ficha PDF — ${esc(s.name)}</h2><div id="pfBox">
    <div class="gpg" style="margin-top:0">Modelo</div><div class="gpw">${Object.entries(PF_PRE).map(([k,[t]])=>`<button type="button" class="gpc" data-act="pfPre" data-p="${k}">${t}</button>`).join('')}</div>
    <div class="gpg">Seções <span id="pfCount" style="text-transform:none;letter-spacing:0;font-weight:400"></span></div>
    <div class="days cg">${PF_SECS.map(([k,t])=>`<label><input type="checkbox" class="pfSec" value="${k}"${P.sec.includes(k)?' checked':''}>${esc(t)}</label>`).join('')}</div>
    <div class="form" style="margin-top:10px"><div class="field"><label for="pfPer">Período (aulas, evolução, financeiro)</label><select id="pfPer">${[[0,'Todo o histórico'],[3,'Últimos 3 meses'],[6,'Últimos 6 meses'],[12,'Últimos 12 meses']].map(([v,t])=>`<option value="${v}"${v===P.months?' selected':''}>${t}</option>`).join('')}</select></div>
    <div class="field"><label>Opções</label><div class="days cg"><label><input type="checkbox" id="pfHead"${P.head?' checked':''}>Cabeçalho do studio</label><label><input type="checkbox" id="pfSign"${P.sign?' checked':''}>Linhas de assinatura</label></div></div></div>
    <details class="wmx" open><summary>Prévia ao vivo</summary><div class="pvbox" id="pfPrev"></div></details></div>
    <div class="foot"><button class="btn" data-act="closeModal">Cancelar</button><button class="btn primary" id="pfGo" data-act="pfGen">Gerar PDF</button></div>`);
  pfPrev();
}
Object.assign(ACT,{
  pfPre:e=>{const a=PF_PRE[e.dataset.p][1];$$('.pfSec').forEach(x=>x.checked=a.includes(x.value));pfPrev()},
  pfGen:()=>{const O=pfRead();if(!O.sec.length)return toast('Marque ao menos uma seção.');db.settings.pdfPrefs=O;save();fichaPrint(pfSid,O)}});
document.addEventListener('change',e=>{if(e.target.closest('#pfBox'))pfPrev()});


/* ========== PERFIL PROFISSIONAL DOS PROFESSORES ========== */
let tpCur='';
const TP_REG=['CREFITO','CREF','Outro','Sem registro'],TP_FORM=['Fisioterapia','Educação Física','Outra'];
const tpDB=()=>{if(!db.teacherProfiles||typeof db.teacherProfiles!=='object'||Array.isArray(db.teacherProfiles))db.teacherProfiles={};return db.teacherProfiles};
const tpP=n=>tpDB()[n]||{};
const tpReg=n=>{const p=tpP(n);return p.regTipo&&p.regTipo!=='Sem registro'&&p.regNum?`${p.regTipo} ${p.regNum}${p.regRegiao?' · '+p.regRegiao:''}`:''};
const tpAnos=ym=>{if(!/^\d{4}-\d{2}$/.test(ym||''))return '';const d=new Date(ym+'-01T12:00'),n=new Date(),m=(n.getFullYear()-d.getFullYear())*12+n.getMonth()-d.getMonth();if(m<0)return '';const y=Math.floor(m/12),r=m%12;return (y?y+(y===1?' ano':' anos'):'')+(y&&r?' e ':'')+(r||!y?r+(r===1?' mês':' meses'):'')};
const tpVal=p=>{if(!p.validade)return null;const d=Math.round((new Date(p.validade+'T12:00')-new Date(iso(new Date())+'T12:00'))/864e5);return d<0?{t:'Registro vencido',c:'bad'}:d<=30?{t:`Vence em ${d} dia(s)`,c:'warn'}:{t:'Registro em dia',c:'ok'}};
const tpPct=p=>{const k=[p.regNum,p.formacao,p.pilates,p.certificacoes,(p.areas||[]).length,p.whatsapp,p.bio,p.validade];return Math.round(k.filter(Boolean).length/k.length*100)};
const tpDet=n=>{const p=tpP(n);return [['Registro profissional',esc(tpReg(n)||'—')],['Formação',esc([p.formacao,p.instituicao,p.anoFormacao].filter(Boolean).join(' · ')||'—')],['Experiência em Pilates',esc(tpAnos(p.pilates)||'—')],['Certificações',esc(p.certificacoes||'—')]]};
function tpCard(n){const p=tpP(n),v=tpVal(p),pct=tpPct(p);
  return `<div class="card" style="padding:12px"><div class="head" style="margin:0 0 8px"><div style="display:flex;gap:10px;align-items:center;min-width:0"><div class="av sm">${esc(initials(n))}</div><div style="min-width:0"><h2 style="margin:0">${esc(n)}</h2><div class="sub">${esc([p.formacao,p.instituicao].filter(Boolean).join(' · ')||'Formação não informada')}</div></div></div>${v?`<span class="badge ${v.c}">${esc(v.t)}</span>`:`<span class="badge ${tpReg(n)?'info':'warn'}">${tpReg(n)?'Sem validade':'Sem registro'}</span>`}</div>
  <div class="mini"><div><small>REGISTRO</small><b>${esc(tpReg(n)||'—')}</b></div><div><small>PILATES HÁ</small><b>${esc(tpAnos(p.pilates)||'—')}</b></div><div><small>NA PROFISSÃO HÁ</small><b>${esc(tpAnos(p.carreira)||'—')}</b></div></div>
  ${p.certificacoes?`<div class="sub" style="color:var(--ink);margin-top:8px;white-space:pre-wrap"><b>Certificações:</b> ${esc(p.certificacoes)}</div>`:''}${p.especializacoes?`<div class="sub" style="color:var(--ink);white-space:pre-wrap"><b>Especializações:</b> ${esc(p.especializacoes)}</div>`:''}
  ${(p.areas||[]).length?`<div class="tchips">${p.areas.map(a=>`<span>${esc(a)}</span>`).join('')}</div>`:''}${(p.aparelhos||[]).length?`<div class="tchips">${p.aparelhos.map(a=>`<span>${esc(GX_AP[a]||a)}</span>`).join('')}</div>`:''}
  ${p.bio?`<div class="sub" style="margin-top:8px;white-space:pre-wrap">${esc(p.bio)}</div>`:''}
  <div class="tubar" role="progressbar" aria-valuenow="${pct}" aria-valuemin="0" aria-valuemax="100"><i style="width:${pct}%"></i></div><div class="sub">Perfil ${pct}% completo</div>
  <div class="row-acts" style="margin-top:8px;flex-wrap:wrap"><button class="btn sm primary" data-act="tpEdit" data-t="${esc(n)}">Editar perfil</button>${p.whatsapp?`<a class="btn sm wa" href="https://wa.me/${esc(String(p.whatsapp).replace(/\D/g,''))}" target="_blank" rel="noopener noreferrer">WhatsApp</a>`:''}</div></div>`}
function tpTeam(){const N=db.teachers,P=N.map(tpP),sr=N.filter(n=>tpReg(n)).length,al=P.filter(p=>{const v=tpVal(p);return v&&v.c!=='ok'}).length;
  $('#tuBody').innerHTML=`<div class="card" style="padding:12px"><div class="mini"><div><small>PROFESSORES</small><b>${N.length}</b></div><div><small>COM REGISTRO</small><b class="${sr<N.length?'neg':''}">${sr}/${N.length}</b></div><div><small>VALIDADE A REVISAR</small><b class="${al?'neg':''}">${al}</b></div></div><div class="sub" style="margin-top:6px">Registro no conselho (CREFITO ou CREF), formação, experiência e certificações de cada profissional. Aparecem também em Professores e na ficha PDF do aluno.</div></div>`+(N.map(tpCard).join('')||'<div class="card empty">Nenhum professor cadastrado. Cadastre em Configurações.</div>')}
function tpModal(n){const p=tpP(n);tpCur=n;
  const f=(i,l,x,full)=>`<div class="field${full?' full':''}"><label for="tp_${i}">${l}</label>${x}</div>`,inp=(i,t,ex)=>`<input id="tp_${i}" type="${t||'text'}" value="${esc(p[i])}" ${ex||''}>`,ta=i=>`<textarea id="tp_${i}" rows="3">${esc(p[i])}</textarea>`,hd=t=>`<div class="field full"><div class="dk" style="margin:6px 0 0">${t}</div></div>`;
  openModal(`<h2>Perfil profissional · ${esc(n)}</h2><div class="form">${hd('REGISTRO NO CONSELHO')}${f('regTipo','Conselho',`<select id="tp_regTipo">${opts(TP_REG,p.regTipo||'CREFITO')}</select>`)}${f('regNum','Número do registro',inp('regNum','text','maxlength="30"'))}${f('regRegiao','Região / UF',inp('regRegiao','text','maxlength="40"'))}${f('validade','Registro / anuidade válido até',inp('validade','date'))}
  ${hd('FORMAÇÃO')}${f('formacao','Formação',`<select id="tp_formacao"><option value="">—</option>${opts(TP_FORM,p.formacao)}</select>`)}${f('instituicao','Instituição',inp('instituicao','text','maxlength="80"'))}${f('anoFormacao','Ano de conclusão',inp('anoFormacao','number','min="1950" max="2100" inputmode="numeric"'))}
  ${hd('TEMPO DE EXPERIÊNCIA')}${f('carreira','Atua na profissão desde',inp('carreira','month'))}${f('pilates','Atua com Pilates desde',inp('pilates','month'))}${f('studioSince','No estúdio desde',inp('studioSince','month'))}
  ${hd('CERTIFICAÇÕES E CURSOS')}${f('certificacoes','Certificações em Pilates (escola/método, carga horária, ano)',ta('certificacoes'),1)}${f('especializacoes','Especializações, pós-graduações e cursos',ta('especializacoes'),1)}
  ${hd('ATUAÇÃO')}<div class="field full"><label>Áreas de atuação</label>${gxChk('tpAr',GOAL_GROUPS.map(([t])=>[t,t]),p.areas)}</div><div class="field full"><label>Aparelhos que domina</label>${gxChk('tpAp',Object.entries(GX_AP),p.aparelhos)}</div>
  ${hd('CONTATO E APRESENTAÇÃO')}${f('whatsapp','WhatsApp profissional',inp('whatsapp','tel','inputmode="tel"'))}${f('email','E-mail',inp('email','email','inputmode="email"'))}${f('bio','Apresentação (aparece no perfil)',ta('bio'),1)}${f('obs','Observações internas',ta('obs'),1)}</div>
  <div class="foot"><button class="btn" data-act="closeModal">Cancelar</button><button class="btn primary" data-act="tpSave">Salvar</button></div>`)}
function tpSave(){const v=i=>String($('#tp_'+i).value||'').trim(),n=tpCur;if(!n)return;
  const tipo=v('regTipo'),num=v('regNum'),ano=v('anoFormacao'),em=v('email');
  if(tipo!=='Sem registro'&&!num){$('#tp_regNum').focus();return toast('Informe o número do registro ou escolha "Sem registro".')}
  if(ano&&!(Number(ano)>=1950&&Number(ano)<=new Date().getFullYear()+1)){$('#tp_anoFormacao').focus();return toast('Ano de conclusão inválido.')}
  if(em&&!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(em)){$('#tp_email').focus();return toast('E-mail inválido.')}
  tpDB()[n]={regTipo:tipo,regNum:num,regRegiao:v('regRegiao'),validade:v('validade'),formacao:v('formacao'),instituicao:v('instituicao'),anoFormacao:ano,carreira:v('carreira'),pilates:v('pilates'),studioSince:v('studioSince'),certificacoes:v('certificacoes'),especializacoes:v('especializacoes'),areas:$$('.tpAr:checked').map(x=>x.value),aparelhos:$$('.tpAp:checked').map(x=>x.value),whatsapp:v('whatsapp'),email:em,bio:v('bio'),obs:v('obs'),updatedAt:new Date().toISOString()};
  if(!save())return;closeModal();render();toast('Perfil profissional salvo.')}
Object.assign(ACT,{tpEdit:e=>tpModal(e.dataset.t),tpSave});

/* ========== ÁREA DO PROFESSOR: estudo + ficha clínica ========== */
const TU_POSE={d:{h:[14,40],p:'M20 42H60M60 42L76 26L92 42M24 45H44M6 50H114'},v:{h:[14,40],p:'M20 42H70M70 42H100M22 46H8M6 50H114'},l:{h:[16,34],p:'M22 38L62 42M62 42L98 46M62 42L98 30M22 40L12 46M6 50H114'},q:{h:[22,22],p:'M28 26H70M32 26V50M70 26V50M70 50H82M6 52H114'},s:{h:[40,12],p:'M40 18V44M40 44H92M40 24L68 28M6 46H114'},k:{h:[50,10],p:'M50 16V36M50 36L66 50M66 50H38M50 22H74M6 52H114'},p:{h:[60,10],p:'M60 16V38M60 38L52 56M60 38L68 56M60 22L46 34M60 22L74 34M30 57H90'}};
const TU_PI={d:'Decúbito dorsal (deitado de barriga para cima), coluna em posição neutra, pés apoiados ou pernas conforme a variação.',v:'Decúbito ventral, testa apoiada ou cabeça alinhada à coluna, pelve estável.',l:'Decúbito lateral, quadris empilhados, coluna e cabeça alinhadas.',q:'Quatro apoios: mãos sob os ombros, joelhos sob o quadril, coluna neutra.',s:'Sentado com os ísquios apoiados, coluna alongada e ombros relaxados.',k:'Ajoelhado, tronco alto, pelve neutra e abdome ativo.',p:'Em pé, pés paralelos na largura do quadril, peso distribuído e coluna neutra.'};
const TU_GRP={'Abdômen / core':{m:'Transverso do abdome, reto e oblíquos do abdome, assoalho pélvico, multífidos',err:'Elevar demais cabeça e pescoço; perder a neutralidade lombar (arquear ou achatar); prender a respiração; usar impulso.',care:'Evitar flexão cervical forçada e projeção do abdome; reduzir a alavanca (joelhos flexionados, pernas mais altas) se a lombar perder o controle.'},
'Coluna':{m:'Eretores da espinha, multífidos, abdominais, glúteos',err:'Mover a coluna em bloco; compensar com ombros e pescoço; ultrapassar a amplitude controlada.',care:'Respeitar a amplitude indolor; dor ou formigamento = reduzir ou interromper; restringir flexão, rotação ou extensão conforme a condição do aluno.'},
'Quadril e pernas':{m:'Glúteos, isquiotibiais, quadríceps, adutores e abdutores',err:'Rotacionar ou inclinar a pelve; deixar o joelho colapsar para dentro; travar o joelho em extensão.',care:'Alinhar quadril, joelho e pé; evitar hiperextensão de joelho; atenção a prótese, bursite e dor patelofemoral.'},
'Ombros e braços':{m:'Serrátil anterior, trapézio inferior, romboides, manguito rotador, tríceps e bíceps',err:'Elevar os ombros em direção às orelhas; projetar a cabeça; perder a estabilidade escapular.',care:'Manter escápulas estáveis; evitar amplitude dolorosa e cargas altas em lesões do manguito.'},
'Corpo todo':{m:'Cadeia global: core, glúteos, escápulas e membros em coordenação',err:'Perder a fluidez; acelerar; compensar com a região mais forte do corpo.',care:'Dividir o exercício em partes e progredir só quando cada parte estiver controlada.'}};
const TU_EQ={M:'Colchonete firme e antiderrapante, com espaço livre ao redor.',R:'Conferir molas, ganchos, cordas, apoios de ombro e batentes; carro livre; carga de molas ajustada ao controle do aluno e ao objetivo do exercício.',C:'Verificar fixação de barras, molas e alças; ajustar altura da barra e posição do aluno; supervisão próxima.',H:'Conferir pedal, molas e estabilidade da Chair; mãos e pés bem apoiados; carga ajustada ao controle do aluno.',B:'Ajustar apoio e posição do Barrel à altura do aluno; garantir base estável e supervisão.',S:'Posicionar o Spine Corrector em apoio estável; evitar extensão forçada de coluna.',A:'Escolher resistência e tamanho do acessório adequados à força do aluno.',F:'Superfície estável e calçado ou pés adequados.',P:'Conferir molas e fixação do Ped-O-Pul; iniciar com resistência leve.'};
const TU_DOS={1:'1 a 2 séries de 5 a 8 repetições, ritmo lento e controlado (ajustar à avaliação individual).',2:'2 séries de 6 a 10 repetições, com foco em qualidade (ajustar à avaliação individual).',3:'2 a 3 séries de 8 a 10 repetições, apenas com domínio comprovado da técnica.'};
const TU_STOP='Interromper se houver dor aguda ou em pontada, formigamento ou dormência, tontura, falta de ar, náusea, dor no peito ou perda de controle da pelve e da coluna. Reavaliar e registrar em Evolução.';
const tuSite=(d,q)=>'https://www.google.com/search?q='+encodeURIComponent('site:'+d+' '+q);
const TU_SRC=[['Balanced Body (YouTube)',q=>'https://www.youtube.com/results?search_query='+encodeURIComponent('Balanced Body Pilates '+q)],['Pilatesology',q=>tuSite('pilatesology.com',q)],['Merrithew / STOTT',q=>tuSite('merrithew.com',q)],['Polestar',q=>tuSite('polestarpilates.com',q)],['Pilates Method Alliance',q=>tuSite('pilatesmethodalliance.org',q)]];
const TU_REFS=[['Cochrane — Pilates for low back pain (Yamato et al., 2015)','https://doi.org/10.1002/14651858.CD010265.pub2','Evidência de qualidade baixa a moderada: reduz dor e incapacidade frente à intervenção mínima; sem superioridade conclusiva sobre outros exercícios.'],
['AAFP — resumo clínico da revisão Cochrane (2016)','https://www.aafp.org/pubs/afp/issues/2016/0401/p556.html','Efeitos adversos raros e leves; exercício supervisionado por instrutores certificados.'],
['PEDro — base de evidências em fisioterapia','https://pedro.org.au/','Busque ensaios e revisões sobre Pilates por condição clínica.'],
['Balanced Body — guias técnicos','https://www.pilates.com/','Fabricante e escola de formação; guias de exercícios e aparelhos.'],
['Balanced Body Video — biblioteca de vídeos','https://video.pilates.com/','Aulas e exercícios em vídeo (assinatura).'],
['Pilatesology — biblioteca de exercícios','https://pilatesology.com/','Enciclopédia de exercícios com vídeo e variações.'],
['Pilates Method Alliance (PMA)','https://www.pilatesmethodalliance.org/','Entidade profissional internacional: padrões e certificação.'],
['Merrithew / STOTT PILATES','https://www.merrithew.com/','Método contemporâneo com base em reabilitação.'],
['Polestar Pilates','https://polestarpilates.com/','Educação voltada à reabilitação e ao movimento clínico.'],
['OMS — atividade física','https://www.who.int/news-room/fact-sheets/detail/physical-activity','Diretrizes gerais de atividade física por faixa etária.']];
const TU_PRIN=[['Avaliação inicial','Anamnese (queixa, histórico, cirurgias, medicamentos), liberação médica quando indicada, dor em escala 0–10, teste funcional simples e objetivo do aluno. Registre na ficha do aluno e em Evolução.'],
['Sinais de alerta (encaminhar)','Dor noturna ou em repouso que não alivia; febre ou perda de peso sem causa; fraqueza ou perda de sensibilidade progressiva; alteração de bexiga ou intestino; trauma recente; dor no peito ou falta de ar ao esforço; inchaço, calor e vermelhidão unilateral na panturrilha. Suspenda o exercício e encaminhe para avaliação médica.'],
['Dosagem e progressão','Progrida uma variável por vez: amplitude, depois carga das molas, depois complexidade, depois velocidade. Monitore a dor durante e nas 24 h seguintes (referência usual: até 3–4/10, sem piora no dia seguinte); ajuste ao caso e à orientação do profissional responsável.'],
['Princípios do método','Respiração, centralização, controle, precisão, concentração e fluidez. Qualidade acima de quantidade.'],
['Escopo e liberação','Conteúdo educacional de apoio ao professor; não substitui avaliação, diagnóstico ou conduta de profissional de saúde. Em gestação, pós-operatório, osteoporose, cardiopatia e hipertensão não controlada, exigir liberação médica.']];
const TU_L={ind:'Indicações clínicas',musc:'Músculos-alvo',pos:'Posição inicial',resp:'Respiração',dos:'Dosagem sugerida',care:'Cuidados e precauções',prec:'Evitar em (cadastro de condições)',err:'Erros comuns',reg:'Regressão (mais fácil)',prog:'Progressão (mais difícil)'};
let tuMode='lib',tuQ='',tuEq='',tuSt='',tuStu='',tuShown=30,tuGoal='lombar';
const tuDB=()=>{if(!db.tutor||typeof db.tutor!=='object')db.tutor={};const t=db.tutor;if(!t.st)t.st={};if(!t.nt)t.nt={};return t};
const tuPose=e=>{const t=norm([e.pos,e.n,e.en].join(' '));return /quadrup|quatro apoio|bird|cat stretch|gato/.test(t)?'q':/lateral|side/.test(t)?'l':/ventral|prono|brucos|swim|swan|cobra|superman/.test(t)?'v':/ajoelh|kneel/.test(t)?'k':/sentad|seated|saw|spine stretch|mermaid/.test(t)?'s':/em pe|standing|ortostat/.test(t)?'p':'d'};
const tuFig=(e,w)=>{const P=TU_POSE[tuPose(e)];return `<svg class="tufig" viewBox="0 0 120 60" width="${w}" height="${w/2}" role="img" aria-label="Posição inicial (ilustração esquemática)"><circle cx="${P.h[0]}" cy="${P.h[1]}" r="5" fill="none" stroke="currentColor" stroke-width="2.5"/><path d="${P.p}" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"/></svg>`};
const tuF=e=>{const G=TU_GRP[e.grp]||TU_GRP['Corpo todo'],lv=e.lv||1,av=(e.av||[]).map(c=>CL[c]||c);
  return{musc:[e.musc||G.m,!e.musc],ind:[e.ind||(e.g||[]).slice(0,5).map(g=>GL[g]).filter(Boolean).join('; '),!e.ind],pos:[e.pos||TU_PI[tuPose(e)],!e.pos],
  resp:[e.resp||'Inspirar para preparar e expirar no esforço, mantendo o abdome ativo; nunca prender a respiração.',!e.resp],dos:[e.dos||e.rep||TU_DOS[lv]||TU_DOS[1],!(e.dos||e.rep)],
  care:[e.care||G.care,!e.care],prec:[av.length?av.join(', ')+(e.sup?'. Exige supervisão direta.':''):(e.sup?'Exige supervisão direta.':'Sem restrições cadastradas; seguir a triagem do aluno.'),false],err:[e.err||G.err,!e.err],
  reg:[e.t||'Reduzir amplitude, alavanca ou resistência; usar apoios (almofada, rolo) preservando a técnica.',!e.t],prog:[e.prog||'Aumentar amplitude, velocidade controlada ou resistência só quando 2 séries saírem limpas, sem dor e sem compensações.',!e.prog]}};
const tuRows=(f,ks)=>ks.map(k=>f[k]&&f[k][0]?`<div class="tur"><b>${TU_L[k]}${f[k][1]?' <span class="badge">base</span>':''}</b><div>${esc(f[k][0])}</div></div>`:'').join('');
const tuLink=(l,u,c='')=>`<a class="btn sm ${c}" href="${esc(u)}" target="_blank" rel="noopener noreferrer">${l}</a>`;
function tuCard(e){const T=tuDB(),v=T.st[e.id]||0,f=tuF(e),s=tuStu&&studentById(tuStu),c=s&&gxCheck(e,gxProfile(s)),th=e.thumb&&/^https:\/\//i.test(e.thumb);
  return `<div class="card tuc" style="padding:12px"><div class="head" style="margin:0 0 6px"><div style="display:flex;gap:10px;align-items:center;min-width:0">${th?`<img src="${esc(e.thumb)}" alt="" width="56" height="40" style="object-fit:cover;border-radius:10px" loading="lazy" referrerpolicy="no-referrer" onerror="this.remove()">`:tuFig(e,56)}<div style="min-width:0"><h2 style="margin:0">${e.fav?'★ ':''}${esc(e.n)}</h2><div class="sub">${esc(gxEqTxt(e.a))} · ${esc(e.grp||'')} · ${gxLv[e.lv]}</div></div></div><span class="badge ${v===2?'ok':v===1?'info':''}">${['Novo','Estudando','Dominado'][v]}</span></div>${c?`<div class="gxck ${c.k}">${esc(s.name)}: ${esc(c.t)}</div>`:''}<div class="sub" style="color:var(--ink)">${esc((f.ind[0]||e.o||'').slice(0,150))}</div><div class="row-acts" style="margin-top:8px;flex-wrap:wrap"><button class="btn sm primary" data-act="tuOpen" data-id="${e.id}">Abrir ficha</button><button class="btn sm${v===1?' primary':''}" data-act="tuSet" data-id="${e.id}" data-v="1">Estudando</button><button class="btn sm${v===2?' primary':''}" data-act="tuSet" data-id="${e.id}" data-v="2">Dominado</button></div></div>`}
function tuSheet(id){const e=gxById(id);if(!e)return;const f=tuF(e),T=tuDB(),v=T.st[id]||0,q=(e.en||e.n)+' '+gxQ(e),s=tuStu&&studentById(tuStu),c=s&&gxCheck(e,gxProfile(s)),own=gxOwn(e),th=e.thumb&&/^https:\/\//i.test(e.thumb);
  const eq=[...new Set(e.a.map(k=>TU_EQ[k]).filter(Boolean))].join(' ');
  const ex=e.ex?`<ol class="tuol">${e.ex.split(/;\s*/).filter(Boolean).map(x=>`<li>${esc(x)}</li>`).join('')}</ol>`:`<div>${esc(e.b||e.o||'—')}</div><div class="sub">Passo a passo ainda não cadastrado: siga o vídeo oficial e complete em “Editar ficha”.</div>`;
  openModal(`<h2>${esc(e.n)}</h2><div style="text-align:center">${th?`<img src="${esc(e.thumb)}" alt="Imagem: ${esc(e.n)}" style="max-width:100%;max-height:200px;border-radius:12px" referrerpolicy="no-referrer" onerror="this.remove()">`:tuFig(e,170)}<div class="sub">${th?'Imagem cadastrada':'Posição inicial (ilustração esquemática)'}</div></div>
  <div style="display:flex;gap:6px;flex-wrap:wrap;margin:8px 0">${e.a.map(a=>`<span class="badge info">${esc(GX_AP[a])}</span>`).join('')}<span class="badge">${gxLv[e.lv]}</span>${e.grp?`<span class="badge">${esc(e.grp)}</span>`:''}${e.sup?'<span class="badge warn">Exige supervisão</span>':''}<span class="badge ${v===2?'ok':v===1?'info':''}">${['Novo','Estudando','Dominado'][v]}</span></div>
  ${c?`<div class="gxck ${c.k}">${esc(s.name)}: ${esc(c.t)}</div>`:''}
  <div class="tur"><b>Objetivo</b><div>${esc(e.o||e.b||'—')}</div></div>${tuRows(f,['ind','musc','pos'])}<div class="tur"><b>Execução${e.ex?'':' <span class="badge">base</span>'}</b>${ex}${gxPh(e)}${gxPhBtn(e)}</div>${tuRows(f,['resp','dos','care','prec','err','reg','prog'])}
  <div class="tur"><b>Alunos</b>${gxStuSum(e,true)}</div><div class="tur"><b>Indicações e perfil</b>${gxRecHtml(e)}</div><div class="tur"><b>Quando evitar e como adaptar</b>${gxAvHtml(e)}</div>
  <div class="tur"><b>Preparação do aparelho</b><div>${esc(eq)}</div></div><div class="tur"><b>Sinais de parada</b><div>${TU_STOP}</div></div>
  ${own&&gxImg(e.media)?`<img src="${esc(e.media)}" alt="Demonstração: ${esc(e.n)}" loading="lazy" style="max-width:100%;border-radius:12px;margin-top:6px">`:''}
  <div class="dk">VÍDEOS E FOTOS EM FONTES OFICIAIS</div><div class="row-acts" style="flex-wrap:wrap">${own&&!gxImg(e.media)?tuLink('▶ Vídeo cadastrado',e.media,'primary'):''}${TU_SRC.map(([l,u])=>tuLink(l,u(q))).join('')}${tuLink('Fotos (sites oficiais)','https://www.google.com/search?tbm=isch&q='+encodeURIComponent('site:pilates.com OR site:pilatesology.com OR site:merrithew.com '+q))}</div>
  ${e.fonte_url&&/^https:\/\//i.test(e.fonte_url)?`<div class="sub" style="margin-top:6px">Fonte da ficha: ${tuLink(esc(e.fonte||'link original'),e.fonte_url)}</div>`:''}
  <div class="field full" style="margin-top:10px"><label for="tuNote">Minhas anotações de estudo</label><textarea id="tuNote" rows="3">${esc(T.nt[id])}</textarea></div>
  <div class="row-acts" style="flex-wrap:wrap;margin-top:8px"><button class="btn sm" data-act="tuNoteSave" data-id="${id}">Salvar anotação</button><button class="btn sm${v===1?' primary':''}" data-act="tuSet" data-id="${id}" data-v="1">Estudando</button><button class="btn sm${v===2?' primary':''}" data-act="tuSet" data-id="${id}" data-v="2">Dominado</button></div>
  <div class="row-acts" style="flex-wrap:wrap;margin-top:8px"><button class="btn sm" data-act="gxAssign" data-id="${id}">Aplicar a aluno</button><button class="btn sm" data-act="gxSeqAdd" data-id="${id}">Sequência</button><button class="btn sm" data-act="gxEdit" data-id="${id}">Editar ficha</button></div>
  <div class="sub" style="margin-top:8px">Itens marcados “base” são gerados automaticamente a partir do grupo muscular, do aparelho e do nível: revise e personalize em “Editar ficha”. Conteúdo educacional; não substitui avaliação profissional.</div>
  <div class="foot"><button class="btn" data-act="closeModal">Fechar</button></div>`)}
function tuQuiz(){const L=gxLib(),T=tuDB(),p=L.filter(x=>T.st[x.id]!==2),b=p.length?p:L,e=b[Math.floor(Math.random()*b.length)];if(!e)return;const f=tuF(e);
  openModal(`<h2>Treino rápido</h2><div style="text-align:center">${tuFig(e,150)}<h3 style="margin:6px 0">${esc(e.n)}</h3><div class="sub">${esc(gxEqTxt(e.a))}</div></div><p>Antes de abrir a resposta, cite a posição inicial, os principais cuidados e os erros mais comuns.</p><details class="wmx"><summary>Ver resposta</summary>${tuRows(f,['pos','care','err'])}</details><div class="foot"><button class="btn" data-act="tuSet" data-id="${e.id}" data-v="1" data-q="1">Revisar depois</button><button class="btn primary" data-act="tuSet" data-id="${e.id}" data-v="2" data-q="1">Acertei</button></div>`)}
function tuKpi(){const L=gxLib(),T=tuDB(),pool=L.filter(e=>T.st[e.id]!==2),ed=pool.length?pool[Math.floor(Date.now()/864e5)%pool.length]:null,dn=L.length-pool.length,pct=L.length?Math.round(dn/L.length*100):0,nf=L.filter(e=>!(e.pos&&e.ex)).length;
  $('#tuKpi').innerHTML=`<div class="card" style="padding:12px"><div class="dk" style="margin:0 0 6px">EXERCÍCIO DO DIA</div>${ed?`<div style="display:flex;gap:10px;align-items:center">${tuFig(ed,64)}<div style="flex:1;min-width:0"><b>${esc(ed.n)}</b><div class="sub">${esc(gxEqTxt(ed.a))}</div></div><button class="btn sm primary" data-act="tuOpen" data-id="${ed.id}">Estudar</button></div>`:'<div class="sub">Todos os exercícios dominados. Excelente!</div>'}<div class="tubar" role="progressbar" aria-valuenow="${pct}" aria-valuemin="0" aria-valuemax="100"><i style="width:${pct}%"></i></div><div class="sub">${pct}% dominado · ${nf} sem passo a passo completo · <button class="btn sm" data-act="tuQuiz">Treino rápido</button></div></div>`}
function tuList(){const L=gxLib(),T=tuDB(),q=norm(tuQ),l=L.filter(e=>(!tuEq||e.a.includes(tuEq))&&(!q||norm([e.n,e.en,e.grp,e.o,e.b,...(e.g||[]).map(g=>GL[g])].join(' ')).includes(q))&&(tuSt===''||(tuSt==='nf'?!(e.pos&&e.ex):(T.st[e.id]||0)===+tuSt)));
  $('#tuList').innerHTML=`<div class="sub" style="margin:8px 0">${l.length} exercício(s)</div>`+(l.slice(0,tuShown).map(tuCard).join('')||'<div class="card empty">Nenhum exercício encontrado.</div>')+(l.length>tuShown?`<button class="btn" data-act="tuMore" style="width:100%">Mostrar mais (${l.length-tuShown})</button>`:'')}
function tuClinica(){const B=$('#tuBody');
  B.innerHTML=`<div class="card" style="padding:12px"><h2 style="margin:0 0 8px">Exercícios por objetivo clínico</h2><div class="field"><label for="tuGoal">Objetivo / condição</label><select id="tuGoal">${goalOpts(tuGoal)}</select></div><div id="tuGoalL"></div></div>`+TU_PRIN.map(([t,x])=>`<details class="card sec" style="padding:12px"><summary><b>${t}</b></summary><div class="sub" style="color:var(--ink);line-height:1.6;margin-top:6px">${esc(x)}</div></details>`).join('')+`<div class="row-acts" style="flex-wrap:wrap"><button class="btn" data-act="goPage" data-p="evolution">Abrir Evolução</button><button class="btn" data-act="goPage" data-p="students">Abrir Alunos</button></div>`;
  const l=gxLib().filter(e=>(e.g||[]).includes(tuGoal)).sort((a,b)=>a.lv-b.lv);
  $('#tuGoalL').innerHTML=`<div class="sub" style="margin:6px 0">${l.length} exercício(s), do mais básico ao mais avançado. Em quadros clínicos comece pelo nível básico e progrida conforme a resposta e a liberação profissional.</div>`+l.slice(0,15).map(e=>`<div class="item"><div style="min-width:0"><b>${esc(e.n)}</b><div class="sub">${esc(gxEqTxt(e.a))} · ${gxLv[e.lv]}</div></div><button class="btn sm" data-act="tuOpen" data-id="${e.id}">Ficha</button></div>`).join('')+(l.length>15?`<div class="sub">Mostrando 15 de ${l.length}. Veja todos em Guia → Por objetivo.</div>`:'')}
function tuRefs(){$('#tuBody').innerHTML=`<div class="card" style="padding:12px"><h2 style="margin:0 0 6px">Fontes oficiais e evidência</h2><div class="sub" style="color:var(--ink);line-height:1.6">Cada ficha traz botões de vídeo e foto restritos a sites oficiais de escolas e entidades (Balanced Body, Pilatesology, Merrithew/STOTT, Polestar e PMA). As fotos e vídeos ficam nos sites de origem, respeitando os direitos autorais; para ter imagem dentro da ficha, cadastre um link seu em “Editar ficha”.</div></div>`+TU_REFS.map(([t,u,d])=>`<div class="card" style="padding:12px"><b>${esc(t)}</b><div class="sub">${esc(d)}</div><div style="margin-top:6px">${tuLink('Abrir fonte',u)}</div></div>`).join('')}
function rTutor(){const L=gxLib(),T=tuDB(),B=$('#tuBody');$$('#tuSeg button').forEach(b=>b.classList.toggle('on',b.dataset.m===tuMode));
  $('#tuCnt').textContent=`${L.length} exercícios · ${L.filter(e=>T.st[e.id]===1).length} estudando · ${L.filter(e=>T.st[e.id]===2).length} dominados`;
  if(tuMode==='cl')return tuClinica();if(tuMode==='pf')return tpTeam();if(tuMode==='ref')return tuRefs();
  if(!$('#tuQ'))B.innerHTML=`<div id="tuKpi"></div><div class="tools" style="flex-wrap:wrap"><input id="tuQ" type="search" value="${esc(tuQ)}" placeholder="Buscar exercício, músculo ou objetivo..." aria-label="Buscar exercício"><select id="tuEq" aria-label="Aparelho"><option value="">Aparelho</option>${Object.entries(GX_AP).map(([k,l])=>`<option value="${k}"${k===tuEq?' selected':''}>${l}</option>`).join('')}</select><select id="tuSt" aria-label="Estudo">${[['','Todos'],['0','Para estudar'],['1','Estudando'],['2','Dominados'],['nf','Sem passo a passo']].map(([k,l])=>`<option value="${k}"${k===tuSt?' selected':''}>${l}</option>`).join('')}</select><select id="tuStu" aria-label="Aluno"><option value="">Aluno: sem filtro</option>${db.students.filter(x=>(x.status||'Ativo')==='Ativo').sort((a,b)=>a.name.localeCompare(b.name,'pt-BR')).map(x=>`<option value="${x.id}"${x.id===tuStu?' selected':''}>${esc(x.name)}</option>`).join('')}</select></div><div id="tuList"></div>`;
  tuKpi();tuList()}
$('#tuSeg').addEventListener('click',e=>{const b=e.target.closest('button');if(b){tuMode=b.dataset.m;tuShown=30;rTutor()}});
$('#tuBody').addEventListener('input',e=>{if(e.target.id==='tuQ'){tuQ=e.target.value;tuShown=30;tuList()}});
$('#tuBody').addEventListener('change',e=>{const t=e.target,m={tuEq:v=>tuEq=v,tuSt:v=>tuSt=v,tuStu:v=>tuStu=v,tuGoal:v=>tuGoal=v};if(m[t.id]){m[t.id](t.value);tuShown=30;rTutor()}});
Object.assign(ACT,{tuOpen:e=>tuSheet(e.dataset.id),tuMore:()=>{tuShown+=30;tuList()},tuQuiz:()=>tuQuiz(),
  tuSet:e=>{const T=tuDB(),id=e.dataset.id,v=+e.dataset.v;T.st[id]=(T.st[id]===v&&!e.dataset.q)?0:v;if(!save())return;if(e.dataset.q)return tuQuiz();rTutor();if($('#tuNote'))tuSheet(id)},
  tuNoteSave:e=>{const t=$('#tuNote');if(!t)return;tuDB().nt[e.dataset.id]=t.value.trim().slice(0,1000);if(save())toast('Anotação salva.')}});

/* ========== GUIA DE APRENDIZADO + PESQUISA ========== */
var srQ='',srCat='all',srShown=30;
const SRK='sp_rsearch_v1',srHist=()=>{try{return JSON.parse(localStorage.getItem(SRK))||[]}catch{return[]}};
function srPush(q){q=q.trim();if(q.length<2)return;const l=[q,...srHist().filter(x=>x!==q)].slice(0,6);try{localStorage.setItem(SRK,JSON.stringify(l))}catch{}}
const LN_PRIN=[['Respiração','Inspire pelo nariz e expire pela boca, coordenando com o movimento.'],['Centralização','O “centro de força”: abdômen, lombar e quadris ativos.'],['Concentração','Atenção plena em cada movimento e em como o corpo responde.'],['Controle','Qualidade antes de quantidade: nada de impulso.'],['Precisão','Posição, alinhamento e trajetória corretos.'],['Fluidez','Movimentos contínuos, com ritmo e transições suaves.']];
const LN_STEPS=[
 ['fund','Fundamentos do método','Os 6 princípios que sustentam toda aula de Pilates.'],
 ['apar','Conheça os aparelhos','Toque em um aparelho para estudar só os exercícios dele.'],
 ['basic','Comece pelo nível básico','Domine os exercícios básicos antes de avançar.'],
 ['clin','Segurança e raciocínio clínico','Condições, contraindicações e quando parar.'],
 ['quiz','Treino rápido','Teste a memória: posição, cuidados e erros comuns.'],
 ['prat','Prática com alunos','Aplique exercícios e sequências ao perfil de cada aluno.']];
const lnDB=()=>{const t=tuDB();if(!t.lg)t.lg={};return t.lg};
function rLearn(){
  const L=gxLib(),T=tuDB(),lg=lnDB(),done=L.filter(e=>T.st[e.id]===2).length,pct=L.length?Math.round(done/L.length*100):0,stDone=LN_STEPS.filter(x=>lg[x[0]]).length;
  $('#lnSub').textContent=`${stDone} de ${LN_STEPS.length} etapas · ${done} exercícios dominados`;
  const lv=[1,2,3].map(n=>{const a=L.filter(e=>e.lv===n);return`<div><b>${a.filter(e=>T.st[e.id]===2).length}/${a.length}</b><small>${gxLv[n]}</small></div>`}).join('');
  const basic=L.filter(e=>e.lv===1&&T.st[e.id]!==2).slice(0,4);
  const eqs=Object.entries(GX_AP).map(([k,l])=>[k,l,L.filter(e=>e.a.includes(k)).length]).filter(x=>x[2]);
  const body={
   fund:`<div class="lnprin">${LN_PRIN.map(([a,b])=>`<div><b>${a}</b>${b}</div>`).join('')}</div>`,
   apar:`<div class="lneq">${eqs.map(([k,l,n])=>`<button type="button" data-act="lnEq" data-k="${k}">${esc(l)}<small>${n}</small></button>`).join('')}</div>`,
   basic:`<div class="mres" style="margin-top:8px">${basic.length?basic.map(exRow).join(''):'<div class="sub">Todos os exercícios básicos foram dominados. 🎉</div>'}</div><div class="row-acts" style="margin-top:8px"><button type="button" class="btn sm" data-act="lnLv" data-v="1">Ver todos os básicos</button></div>`,
   clin:`<div class="row-acts" style="margin-top:8px"><button type="button" class="btn sm primary" data-act="lnGo" data-m="cl">Abrir raciocínio clínico</button><button type="button" class="btn sm" data-act="lnGo" data-m="ref">Fontes oficiais</button></div>`,
   quiz:`<div class="row-acts" style="margin-top:8px"><button type="button" class="btn sm primary" data-act="tuQuiz">Começar treino rápido</button></div>`,
   prat:`<div class="row-acts" style="margin-top:8px"><button type="button" class="btn sm primary" data-act="lnGuide" data-m="stu">Guia por aluno</button><button type="button" class="btn sm" data-act="lnGuide" data-m="seq">Sequências</button><button type="button" class="btn sm" data-act="lnGuide" data-m="goal">Por objetivo</button></div>`};
  $('#lnBody').innerHTML=`<div class="lnhero"><div class="row"><div><div class="sub" style="font-weight:700">SEU PROGRESSO</div><div class="big">${pct}%</div></div><button type="button" class="btn sm primary" data-act="tuQuiz">Treino rápido</button></div><div class="mbar" style="height:9px;margin-top:10px"><i style="width:${pct}%"></i></div><div class="lnlv">${lv}</div></div>`
   +LN_STEPS.map(([k,t,d],i)=>`<div class="card lnstep${lg[k]?' done':''}" style="--i:${i}"><span class="num">${lg[k]?ico('check'):i+1}</span><div class="bd"><h2>${t}</h2><div class="sub">${d}</div>${body[k]}<div class="row-acts" style="margin-top:8px"><button type="button" class="btn sm${lg[k]?'':' primary'}" data-act="lnDone" data-k="${k}">${lg[k]?'Desmarcar etapa':'Marcar como concluída'}</button></div></div></div>`).join('')
   +`<div class="card" style="padding:12px"><div class="sub">Conteúdo educacional: não substitui avaliação profissional nem formação certificada.</div></div>`;
}
function srSeg(c){return[['all','Tudo'],['ex','Exercícios'],['scr','Telas'],['stu','Alunos'],['tea','Professores']].map(([k,l])=>`<button type="button" data-c="${k}"${k===c?' class="on"':''}>${l}</button>`).join('')}
function rSearch(){
  const inp=$('#srQ');if(inp&&inp.value!==srQ)inp.value=srQ;
  $('#srSeg').innerHTML=srSeg(srCat);const B=$('#srBody'),q=srQ.trim();
  if(!q){
    const h=srHist(),sug=['Reformer','Lombar','Básico','Core','Gestante','Equilíbrio','Cadillac','Postura'];
    const L=gxLib(),T=tuDB(),pool=L.filter(e=>T.st[e.id]!==2),ed=pool.length?pool[Math.floor(Date.now()/864e5)%pool.length]:null;
    B.innerHTML=(h.length?`<div class="dk" style="margin-top:0">RECENTES</div><div class="pill">${h.map(x=>`<button type="button" data-act="srSet" data-q="${esc(x)}">${ico('clock')} ${esc(x)}</button>`).join('')}<button type="button" data-act="srClr">Limpar</button></div>`:'')
      +`<div class="dk"${h.length?'':' style="margin-top:0"'}>SUGESTÕES</div><div class="pill">${sug.map(x=>`<button type="button" data-act="srSet" data-q="${x}">${x}</button>`).join('')}</div>`
      +(ed?`<div class="dk">EXERCÍCIO PARA ESTUDAR HOJE</div><div class="mres">${exRow(ed)}</div>`:'');
    $('#srSub').textContent=`${L.length} exercícios na biblioteca`;return}
  const O=srEx2(q),sc=srScr(q),nq=norm(q),ex=[...O.exact,...O.related];
  const stu=srStus(q),tea=(db.teachers||[]).filter(x=>norm(typeof x==='string'?x:x.name).includes(nq));
  $('#srSub').textContent=`${ex.length} exercício(s) · ${sc.length} tela(s) · ${stu.length} aluno(s) · ${tea.length} professor(es)`;
  const sec=(k,t,h)=>h&&(srCat==='all'||srCat===k)?`<div class="dk"${k==='ex'||srCat!=='all'?' style="margin-top:6px"':''}>${t}</div>${h}`:'';
  const all=[...O.exact.map(e=>[e,0]),...O.related.map(e=>[e,1])],shown=all.slice(0,srShown),a0=shown.filter(x=>!x[1]).map(x=>x[0]),a1=shown.filter(x=>x[1]).map(x=>x[0]);
  const rw=(l,o)=>`<div class="mres">${l.map((e,i)=>exRow(e,Math.min(i+o,10))).join('')}</div>`,only=!a0.length&&a1.length;
  const exHtml=(a0.length?rw(a0,0):'')+(a1.length?(only?'<div class="sub" style="margin:2px 0 6px">Sem resultado exato. Estes são os mais próximos.</div>':`<div class="dk">RELACIONADOS · ${O.related.length}</div>`)+rw(a1,a0.length):'')+(all.length>srShown?`<button type="button" class="btn" data-act="srMore" style="width:100%;justify-content:center;margin-top:8px">Mostrar mais (${all.length-srShown})</button>`:'');
  const did=srDid(q,O),chips=[...O.rel.slice(0,8)];
  const cnt=(f)=>{const m={};O.exact.concat(O.related).slice(0,30).forEach(e=>f(e).forEach(k=>{if(k)m[k]=(m[k]||0)+1}));return Object.entries(m).sort((x,y)=>y[1]-x[1]).slice(0,2).map(x=>x[0])};
  [...cnt(e=>e.a.map(k=>GX_AP[k])),...cnt(e=>[e.grp])].forEach(t=>{if(!chips.some(c=>norm(c)===norm(t))&&norm(t)!==nq)chips.push(t)});
  const head=(srCat==='all'||srCat==='ex')?(did?`<div class="sub" style="margin:0 0 8px">Você quis dizer <button type="button" class="btn sm" data-act="srSet" data-q="${esc(did)}">${esc(did)}</button>?</div>`:'')+(chips.length?`<div class="dk" style="margin-top:6px">TERMOS RELACIONADOS</div><div class="pill">${chips.map(x=>`<button type="button" data-act="srSet" data-q="${esc(x)}">${esc(x)}</button>`).join('')}</div>`:''):'';
  const out=sec('ex',only?'RELACIONADOS · '+O.related.length:'EXERCÍCIOS · '+O.exact.length,exHtml)
   +sec('scr','TELAS',sc.length?`<div class="tiles">${sc.map(([p,i,l],n)=>`<button class="tile" style="--i:${n}" data-act="goPage" data-p="${p}"><i aria-hidden="true">${ico(i)}</i>${l}</button>`).join('')}</div>`:'')
   +sec('stu','ALUNOS',stu.length?`<div class="mres">${stu.map(([,x,why])=>`<button type="button" class="srr" data-act="srStu" data-n="${esc(x.name)}"><span class="srf">${ico('users')}</span><span class="srt"><b>${esc(x.name)}</b><small>${esc(x.status||'Ativo')}${x.plan?' · '+esc(x.plan):''}${why?' · '+esc(why):''}</small></span></button>`).join('')}</div>`:'')
   +sec('tea','PROFESSORES',tea.length?`<div class="mres">${tea.map(x=>{const n=typeof x==='string'?x:x.name;return`<button type="button" class="srr" data-act="goPage" data-p="teachers"><span class="srf">${ico('teacher')}</span><span class="srt"><b>${esc(n)}</b><small>Ver em Professores</small></span></button>`}).join('')}</div>`:'');
  B.innerHTML=head+(out||`<div class="empty">Nada encontrado para “${esc(q)}”.</div>`);
}
$('#srQ').addEventListener('input',e=>{srQ=e.target.value;srShown=30;rSearch()});
$('#srQ').addEventListener('change',e=>srPush(e.target.value));
$('#srQ').addEventListener('keydown',e=>{if(e.key==='Enter'){srPush(e.target.value);e.target.blur()}});
$('#srSeg').addEventListener('click',e=>{const b=e.target.closest('button[data-c]');if(b){srCat=b.dataset.c;srShown=30;rSearch()}});
Object.assign(ACT,{
  srAll:()=>{const v=($('#moreQ')||{}).value||'';srQ=v;srCat='all';srShown=30;srPush(v);closeModal();go('search')},
  srSet:e=>{srQ=e.dataset.q;srPush(srQ);rSearch()},srClr:()=>{try{localStorage.removeItem(SRK)}catch{}rSearch()},srMore:()=>{srShown+=30;rSearch()},
  srStu:e=>{go('students');const i=$('#stSearch');if(i){i.value=e.dataset.n;i.dispatchEvent(new Event('input',{bubbles:true}))}},
  lnDone:e=>{const lg=lnDB(),k=e.dataset.k;lg[k]=lg[k]?0:1;if(save())rLearn()},
  lnEq:e=>{tuMode='lib';tuEq=e.dataset.k;tuQ='';tuSt='';tuShown=30;go('tutor');const i=$('#tuQ');if(i)i.value='';[['#tuEq',tuEq],['#tuSt','']].forEach(([a,v])=>{const x=$(a);if(x)x.value=v});tuList()},
  lnLv:e=>{gxMode='ex';go('guide');const x=$('#gxLvS');if(x){x.value=e.dataset.v;x.dispatchEvent(new Event('change',{bubbles:true}))}},
  lnGo:e=>{tuMode=e.dataset.m;tuShown=30;go('tutor')},
  lnGuide:e=>{gxMode=e.dataset.m;go('guide')}});

/* ========== GRADIENTES ========== */
const GD_PRE=[['Aurora','#7c3aed','#06b6d4'],['Pôr do sol','#f97316','#ec4899'],['Oceano','#38bdf8','#2563eb'],['Neon','#22d3ee','#84cc16'],['Rosé','#fb7185','#a855f7'],['Esmeralda','#34d399','#047857']];
function gdCur(){const t=db.settings.theme||{},pal=PALETTES[t.preset]||PALETTES.marfim;return gdNorm(t.grad)||{on:false,c1:pal.p2,c2:pal.p,c3:'',ang:135}}
function gdSet(g,persist){db.settings.theme={...(db.settings.theme||{}),grad:g};applyTheme();if(persist)save();rGrad()}
function rGrad(){
  const g=gdCur(),cur=(db.settings.theme||{}).preset||'marfim',pn=(PALETTES[cur]||PALETTES.marfim).n;
  $('#gdBox').hidden=!g.on;$('#gdC1').value=g.c1;$('#gdC2').value=g.c2;$('#gdAng').value=g.ang;$('#gdAngV').textContent=g.ang+'°';
  const pre=GD_PRE.find(x=>x[1]===g.c1&&x[2]===g.c2);
  $('#palName').textContent=g.on?'—':pn;$('#gdName').textContent=g.on?(pre?pre[0]:'Personalizado'):'—';
  $('#gdPresets').innerHTML=GD_PRE.map(([n,a,b])=>`<button type="button" class="dot" title="${n}" aria-label="${n}" data-act="gdPre" data-n="${n}" aria-pressed="${g.on&&g.c1===a&&g.c2===b}" style="background:${gdCss({ang:135,c1:a,c2:b,c3:''})}"></button>`).join('');
  $$('#palGrid .dot').forEach(x=>x.setAttribute('aria-pressed',!g.on&&x.dataset.k===(PALETTES[cur]?cur:'marfim')));
}
function gdRead(persist){gdSet({on:true,c1:$('#gdC1').value,c2:$('#gdC2').value,c3:'',ang:+$('#gdAng').value},persist)}
$('#gdCard').addEventListener('input',e=>{if(e.target.matches('#gdC1,#gdC2,#gdAng'))gdRead(false)});
$('#gdCard').addEventListener('change',e=>{if(e.target.matches('#gdC1,#gdC2,#gdAng'))gdRead(true)});
Object.assign(ACT,{gdPre:e=>{const p=GD_PRE.find(x=>x[0]===e.dataset.n);gdSet({on:true,c1:p[1],c2:p[2],c3:'',ang:gdCur().ang},true)}});

/* ========== RELATÓRIOS ========== */
const WEEKS=4.33,dec=(n,d=1)=>Number(n).toFixed(d).replace('.',',');
function econ(x){
  const weekly=Math.max(1,Math.min(7,Number(db.plans.find(q=>q.name===x.plan)?.weekly||x.weekly||1)));
  const classes=weekly*WEEKS,monthly=Math.max(0,Number(x.monthly||0)),perClass=monthly/classes;
  const hours=Math.max(.25,(Number(db.settings.duration)||60)/60),rate=Number(db.settings.teacherRates[x.teacher||'Sem professor']||0);
  const cost=monthly*rate/100;
  return{weekly,classes,monthly,perClass,perHour:perClass/hours,rate,cost,margin:monthly-cost};
}
function rpRows(){
  const st=$('#rpStatus').value,t=$('#rpTeacher').value,pl=$('#rpPlan').value;
  return db.students.filter(x=>(!st||(x.status||'Ativo')===st)&&(!t||(x.teacher||'Sem professor')===t)&&(!pl||x.plan===pl))
    .map(x=>({x,e:econ(x)})).sort((a,b)=>a.x.name.localeCompare(b.x.name,'pt-BR'));
}
function rpFillFilters(){
  const set=(id,first,vals)=>{const el=$(id),cur=el.value;el.innerHTML=`<option value="">${first}</option>`+vals.map(v=>`<option>${esc(v)}</option>`).join('');if(vals.includes(cur))el.value=cur};
  set('#rpTeacher','Todos',[...new Set([...db.teachers,...db.students.map(x=>x.teacher).filter(Boolean),...(db.students.some(x=>!x.teacher)?['Sem professor']:[])])].sort((a,b)=>a.localeCompare(b,'pt-BR')));
  set('#rpPlan','Todos',[...new Set([...db.plans.map(q=>q.name),...db.students.map(x=>x.plan).filter(Boolean)])]);
}
function rReports(){
  rpFillFilters();
  const rows=rpRows(),sum=(a,f)=>a.reduce((t,r)=>t+f(r),0),rev=sum(rows,r=>r.e.monthly),cost=sum(rows,r=>r.e.cost),cls=sum(rows,r=>r.e.classes),mg=rev-cost;
  $('#rpRev').textContent=money(rev);$('#rpCost').textContent=money(cost);$('#rpMargin').textContent=money(mg);
  $('#rpMarginPct').textContent=rev?dec(mg/rev*100)+'% da receita':'';
  $('#rpClasses').textContent=dec(cls);$('#rpTicket').textContent=money(rows.length?rev/rows.length:0);
  const k=ym(new Date()),mrec=db.finance.filter(f=>!isExp(f)&&String(f.dueDate).startsWith(k)),billed=sum(mrec,f=>Number(f.value||0)),late=sum(mrec.filter(lateOf),f=>Number(f.value||0));
  $('#rpDefault').textContent=billed?dec(late/billed*100)+'%':'0%';
  const byPlan={};rows.forEach(r=>{const p=r.x.plan||'Sem plano';(byPlan[p]=byPlan[p]||{n:0,rev:0})&&(byPlan[p].n++,byPlan[p].rev+=r.e.monthly)});
  const maxP=Math.max(1,...Object.values(byPlan).map(v=>v.rev));
  $('#rpPlans').innerHTML=Object.keys(byPlan).length?Object.entries(byPlan).sort((a,b)=>b[1].rev-a[1].rev).map(([n,v])=>`<div class="item"><div style="min-width:120px;flex:1"><b>${esc(n)}</b><div class="sub">${v.n} aluno${v.n===1?'':'s'} · ticket ${money(v.rev/v.n)}</div></div><div class="bar" style="flex:1"><i style="width:${v.rev/maxP*100}%"></i></div><b style="min-width:90px;text-align:right">${money(v.rev)}</b></div>`).join(''):'<div class="empty">Sem dados para os filtros.</div>';
  const byT={};rows.forEach(r=>{const t=r.x.teacher||'Sem professor',o=byT[t]=byT[t]||{n:0,cls:0,rev:0,cost:0};o.n++;o.cls+=r.e.classes;o.rev+=r.e.monthly;o.cost+=r.e.cost});
  $('#rpTeachersList').innerHTML=Object.keys(byT).length?Object.entries(byT).map(([t,o])=>scard({key:'rt:'+t,name:t,badge:o.n+' aluno(s)',sub:`${dec(o.cls)} aulas/mês`,tone:o.rev-o.cost<0?'bad':'',
    mini:[['RECEITA',money(o.rev)],['REPASSE',money(o.cost)],['MARGEM',`<span class="${o.rev-o.cost<0?'neg':''}">${money(o.rev-o.cost)}</span>`]],
    det:[['Repasse por aula',money(o.cls?o.cost/o.cls:0)],['Margem por aula',money(o.cls?(o.rev-o.cost)/o.cls:0)]]})).join(''):'<div class="card empty">Sem dados.</div>';
  $('#rpStudentsList').innerHTML=rows.length?rows.map(({x,e})=>scard({key:'rp:'+x.id,name:x.name,badge:e.weekly+'x/sem',sub:`${esc(x.plan||'—')} · ${esc(x.teacher||'—')}`,
    mini:[['MENSALIDADE',money(e.monthly)],['R$/AULA',money(e.perClass)],['MARGEM',`<span class="${e.margin<0?'neg':''}">${money(e.margin)}</span>`]],
    det:[['R$/hora',money(e.perHour)],['Aulas/mês',dec(e.classes)],['Repasse',`${dec(e.rate)}% · ${money(e.cost)}`]],dim:(x.status||'Ativo')!=='Ativo',acts:`<button class="btn sm" data-act="editStudent" data-id="${x.id}">Editar aluno</button>`})).join(''):'<div class="card empty">Nenhum aluno para os filtros.</div>';
}
function rpCsv(){
  const rows=rpRows();if(!rows.length)return toast('Nada para exportar com estes filtros.');
  const cell=v=>{v=String(v??'');if(/^[=+\-@\t\r]/.test(v))v="'"+v;return `"${v.replace(/"/g,'""')}"`}; // evita injeção de fórmula no Excel
  const n=v=>dec(v,2);
  const lines=[['Aluno','Status','Plano','Professor','Freq. semanal','Mensalidade','Aulas/mês','R$/aula','R$/hora','Repasse %','Repasse','Margem']].concat(rows.map(({x,e})=>[x.name,x.status||'Ativo',x.plan,x.teacher,e.weekly,n(e.monthly),n(e.classes),n(e.perClass),n(e.perHour),n(e.rate),n(e.cost),n(e.margin)]));
  const blob=new Blob(['\ufeff'+lines.map(l=>l.map(cell).join(';')).join('\r\n')],{type:'text/csv;charset=utf-8'});
  const a=document.createElement('a');a.href=URL.createObjectURL(blob);a.download=`relatorio-rentabilidade-${iso(new Date())}.csv`;document.body.appendChild(a);a.click();a.remove();setTimeout(()=>URL.revokeObjectURL(a.href),4000);toast('CSV exportado.');
}
Object.assign(ACT,{rpCsv});
$('#rpFilters').addEventListener('change',rReports);


/* ========== EQUIPAMENTOS ========== */
const activeEq=()=>db.equipment.filter(e=>e.active!==false&&e.name);
const eqById=id=>db.equipment.find(e=>e.id===id);
const eqName=c=>c.equipmentId?(eqById(c.equipmentId)?.name||'Aparelho removido'):'';
const tmin=v=>{const m=String(v||'').match(/^(\d{1,2}):(\d{2})$/);return m&&m[1]<24&&m[2]<60?m[1]*60+ +m[2]:null};
const eqUsage=id=>db.classes.filter(c=>c.equipmentId===id&&c.status!=='Cancelada').length;
function eqAvailable(e,date,time,ignoreId,dur){
  const a=tmin(time);if(!e||!date||a==null)return false;
  const d=Math.max(1,Number(dur||db.settings.duration)||60),b=a+d;
  const n=db.classes.filter(c=>c.date===date&&c.status!=='Cancelada'&&c.equipmentId===e.id&&c.id!==ignoreId).filter(c=>{
    const s=tmin(c.time);return s!=null&&a<s+Math.max(1,Number(c.duration||db.settings.duration)||60)&&s<b}).length;
  return n<Math.max(1,Number(e.quantity)||1);
}
function lastEqOf(studentId,date,time,ignoreId){
  const r=lastEqRec(studentId,date,time,ignoreId);if(r)return r;
  const m=(db.settings.eqLast||{})[studentId],e=m&&eqById(m.id);return e?{equipmentId:e.id,date:m.date||'',time:'',manual:true}:null;
}
function lastEqRec(studentId,date,time,ignoreId){
  const t=`${date}T${time||'23:59'}`;
  return db.classes.filter(c=>c.studentId===studentId&&c.equipmentId&&c.status!=='Cancelada'&&c.id!==ignoreId&&`${c.date}T${c.time||'00:00'}`<t).sort((a,b)=>(`${b.date}T${b.time}`).localeCompare(`${a.date}T${a.time}`))[0]||null;
}
function eqCandBal(studentId,date,time,ignoreId){
  const last=lastEqOf(studentId,date,time,ignoreId),mine={},all={};
  db.classes.forEach(c=>{if(!c.equipmentId||c.status==='Cancelada'||c.id===ignoreId)return;all[c.equipmentId]=(all[c.equipmentId]||0)+1;if(c.studentId===studentId)mine[c.equipmentId]=(mine[c.equipmentId]||0)+1});
  return activeEq().filter(e=>eqAvailable(e,date,time,ignoreId)).sort((a,b)=>((last?.equipmentId===a.id)-(last?.equipmentId===b.id))||((mine[a.id]||0)-(mine[b.id]||0))||((all[a.id]||0)-(all[b.id]||0))||a.name.localeCompare(b.name,'pt-BR'));
}
const eqPick=(studentId,date,time,ignoreId)=>eqCandidates(studentId,date,time,ignoreId)[0]?.id||'';
function eqOptions(studentId,date,time,sel,ignoreId){
  const cand=eqCandidates(studentId,date,time,ignoreId),ok=new Set(cand.map(e=>e.id)),last=lastEqOf(studentId,date,time,ignoreId),
    list=[...cand,...activeEq().filter(e=>!ok.has(e.id))];
  if(sel&&!list.some(e=>e.id===sel)&&eqById(sel))list.push(eqById(sel));
  return '<option value="">Automático — rodízio</option>'+list.map(e=>{
    const free=ok.has(e.id)||e.id===sel;
    return `<option value="${e.id}"${e.id===sel?' selected':''}${free?'':' disabled'}>${esc(e.name)}${free?'':' (ocupado)'}${last?.equipmentId===e.id?' · usou na última':''}</option>`}).join('');
}
function fillEq(first){
  const sel=first?(classById(editing)?.equipmentId||''):$('#cEquip').value;
  $('#cEquip').innerHTML=eqOptions($('#cStudent').value,$('#cDate').value,$('#cTime').value,sel,editing);
}
const EQ_IC={reformer:'<rect x="2" y="13" width="20" height="3.5" rx="1.5"/><rect x="5" y="9.5" width="7" height="3.5" rx="1"/><path d="M13 11h5M20 13V6M17.5 6h5M5 16.5V20M19 16.5V20"/>',
cadillac:'<rect x="3" y="4" width="18" height="16" rx="1.5"/><path d="M3 8h18M3 15h18M7 15v-4M17 15v-4"/>',
chair:'<rect x="5" y="9" width="11" height="4.5" rx="1"/><path d="M5 9V4h4M16 12h4v8M7 13.5V20M14 13.5V20"/>',
barrel:'<path d="M3 19h18M5 19c0-6 3-10 7-10s7 4 7 10M12 9v10M8 19v-5M16 19v-5"/>',
spine:'<path d="M3 19h18M5 19c0-5 3-8 7-8h2c4 0 5 3 5 8M9 19v-4M14 19v-5"/>',
ball:'<circle cx="12" cy="12" r="8.5"/><path d="M4 9.5c4.5 2.5 11.5 2.5 16 0"/>',
circle:'<circle cx="12" cy="12" r="8.5"/><circle cx="12" cy="12" r="4.5"/>',
band:'<path d="M2.5 12c3-7 6 7 9.5 0s6.5 7 9.5 0"/>',
mat:'<rect x="3" y="8" width="18" height="8" rx="3"/><circle cx="7.5" cy="12" r="1.6"/>',
dumb:'<path d="M6 7.5v9M3 10v4M18 7.5v9M21 10v4M6 12h12"/>'};
function eqKind(e){const t=((e.name||'')+' '+(e.category||'')).toLowerCase();
  return /reformer/.test(t)?'reformer':/cadillac|trap[eé]zio|tower/.test(t)?'cadillac':/chair|cadeira/.test(t)?'chair':/barrel|barril|ladder/.test(t)?'barrel':/spine|corrector|coluna/.test(t)?'spine':/bola|ball/.test(t)?'ball':/c[ií]rculo|circle|\bring\b|anel/.test(t)?'circle':/faixa|band|el[aá]stic/.test(t)?'band':/\bmat\b|colchonete|tapete/.test(t)?'mat':'dumb'}
const eqIcon=(e,z=22)=>`<svg width="${z}" height="${z}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">${EQ_IC[eqKind(e)]}</svg>`;
function eqMode(){return db.settings.eqMode==='sequence'?'sequence':'balanced'}
function eqAdd(s,n){const x=new Date(s+'T12:00');x.setDate(x.getDate()+n);return iso(x)}
function eqCandidates(studentId,date,time,ignoreId){
  if(eqMode()!=='sequence')return eqCandBal(studentId,date,time,ignoreId);
  const ae=activeEq(),n=ae.length||1,last=lastEqOf(studentId,date,time,ignoreId),li=last?ae.findIndex(e=>e.id===last.equipmentId):-1,pos=e=>(ae.indexOf(e)-li-1+n)%n;
  return ae.filter(e=>eqAvailable(e,date,time,ignoreId)).sort((a,b)=>pos(a)-pos(b));
}
const eqSeqOf=(sid,d,n)=>db.classes.filter(c=>c.studentId===sid&&c.equipmentId&&c.status!=='Cancelada'&&c.date<=d).sort(sortCls).slice(-n);
function eqCard(e,i,d,cls,slots){
  const q=Number(e.quantity)||1,now=new Date(),today=iso(now),nm=now.getHours()*60+now.getMinutes(),live=c=>c.equipmentId===e.id&&c.status!=='Cancelada',dur=c=>Math.max(1,Number(c.duration||db.settings.duration)||60);
  const u=cls.filter(c=>c.equipmentId===e.id).length,cap=q*slots,p=cap?Math.min(100,Math.round(u/cap*100)):0,tone=p>=90?'bad':p>=60?'warn':'ok';
  const inUse=d===today?cls.filter(c=>live(c)&&tmin(c.time)!=null&&tmin(c.time)<=nm&&nm<tmin(c.time)+dur(c)).length:0;
  const st=e.active===false?['Inativo','']:inUse>=q?['Em uso agora','bad']:inUse?[`Em uso ${inUse}/${q}`,'warn']:['Livre','ok'];
  const nk=`${today}T${pad(now.getHours())}:${pad(now.getMinutes())}`,nx=db.classes.filter(c=>live(c)&&!['Realizada','Falta'].includes(c.status)&&`${c.date}T${c.time||'00:00'}`>=nk).sort(sortCls)[0];
  const lu=db.classes.filter(c=>live(c)&&c.date<=today).sort(sortCls).pop(),wk=db.classes.filter(c=>live(c)&&c.date>=d&&c.date<=eqAdd(d,6)).length;
  const wd=String(new Date(d+'T12:00').getDay()),strip=db.hours.filter(h=>hourDays(h).includes(wd)).map(h=>{const n=cls.filter(c=>c.equipmentId===e.id&&c.time===h).length;return `<i class="${n>=q?'f':n?'p':''}" title="${h} · ${n}/${q}"></i>`}).join('');
  const mt=e.maint?Math.round((new Date(e.maint+'T12:00')-new Date(today+'T12:00'))/864e5):null,mb=mt==null?'':mt<0?'<span class="badge bad">revisão vencida</span>':mt<=15?`<span class="badge warn">revisão em ${mt}d</span>`:'';
  const ae=activeEq(),pos=ae.indexOf(e),mvb=(d,ic,lb,off)=>`<button type="button" class="eqmb" data-act="eqMove" data-id="${e.id}" data-d="${d}" aria-label="Mover ${esc(e.name)} ${lb}"${off?' disabled':''}>${ico(ic)}</button>`,
    mv=`<span class="eqmv">${mvb(-1,'chev-u','para cima',pos<=0)}${mvb(1,'chev-d','para baixo',pos<0||pos===ae.length-1)}</span>`;
  const row=(l,v)=>`<div class="eqm"><span>${l}</span><b>${v}</b></div>`;
  return `<div class="eqt${e.active===false?' off':''}" style="--i:${i}">
    <div class="eqtop"><span class="eqc lg">${eqIcon(e,28)}</span><div style="min-width:0"><b>${esc(e.name)}</b><div class="sub">${esc(e.category||'—')}${e.model?' · '+esc(e.model):''} · ${q} unid.</div></div></div>
    <div class="eqb"><span class="badge ${st[1]}">${st[0]}</span>${mb}${eqMode()==='sequence'&&pos>=0?`<span class="badge info">ordem ${pos+1}</span>`:''}</div>
    <div class="eqs" role="img" aria-label="Ocupação por horário no dia">${strip}</div><div class="bar ${tone}"><i style="width:${p}%"></i></div><div class="sub">${u} de ${cap||'—'} vagas no dia · ${p}%</div>
    ${row('Próxima aula',nx?`${nx.date===today?'Hoje':fmtDate(nx.date).slice(0,5)} ${esc(nx.time)} · ${esc(String(nx.studentName||'').split(' ')[0])}`:'—')}${row('Próximos 7 dias',`${wk} aula${wk===1?'':'s'}`)}${row('Último uso',lu?fmtDate(lu.date):'—')}${row('Total',`${eqUsage(e.id)} aulas`)}
    ${e.notes?`<div class="sub">${esc(e.notes)}</div>`:''}
    <div class="eqa"><button type="button" class="eqmb" data-act="editEq" data-id="${e.id}" aria-label="Editar ${esc(e.name)}">${ico('edit')}</button>${mv}<button type="button" class="eqmb bad" data-act="delEq" data-id="${e.id}" aria-label="Excluir ${esc(e.name)}">${ico('trash')}</button></div></div>`;
}
function eqRotation(d){
  const md=eqMode();$('#eqModeSeg').querySelectorAll('button').forEach(b=>b.classList.toggle('on',b.dataset.m===md));
  $('#eqModeSub').textContent=md==='sequence'?'Cada aluno avança para o próximo aparelho da ordem abaixo, pulando os ocupados. Mude a ordem com as setas nos cartões.':'Evita repetir o último aparelho do aluno e prioriza os que ele e o studio menos usaram.';
  const ae=activeEq(),from=eqAdd(d,-29),cs=db.classes.filter(c=>c.equipmentId&&c.status!=='Cancelada'&&c.date>=from&&c.date<=d),tot=cs.length;
  $('#eqShare').innerHTML=ae.length?ae.map(e=>{const n=cs.filter(c=>c.equipmentId===e.id).length,p=tot?Math.round(n/tot*100):0;return `<div class="eqsh"><span class="eqc">${eqIcon(e,18)}</span><b>${esc(e.name)}</b><div class="bar ok"><i style="width:${p}%"></i></div><span class="sub">${n} · ${p}%</span></div>`}).join(''):'<div class="empty">Cadastre aparelhos para acompanhar o rodízio.</div>';
  const f=eqRotation.f||'all',base=db.students.filter(s=>(s.status||'Ativo')==='Ativo').map(s=>{const lu=eqLastUsed(s.id),sq=eqSeqOf(s.id,d,5),rp=sq.length>1&&sq[sq.length-1].equipmentId===sq[sq.length-2].equipmentId,nx=eqById(eqPick(s.id,eqAdd(d,1),s.time,''));return{s,lu,rp,nx}});
  const key=r=>r.lu?r.lu.eq.id:'none',cnt={};base.forEach(r=>cnt[key(r)]=(cnt[key(r)]||0)+1);
  const chip=(k,l,n)=>`<button type="button" data-act="eqLF" data-f="${k}" class="${f===k?'on':''}" aria-pressed="${f===k}">${l}<small>${n}</small></button>`;
  $('#eqLastF').innerHTML=chip('all','Todos',base.length)+ae.map(e=>chip(e.id,eqIcon(e,14)+esc(e.name),cnt[e.id]||0)).join('')+(cnt.none?chip('none','Sem histórico',cnt.none):'');
  const rows=base.filter(r=>f==='all'||key(r)===f).sort((a,b)=>b.rp-a.rp||a.s.name.localeCompare(b.s.name,'pt-BR'));
  const line=r=>`<div class="eqs-r" data-act="eqHist" data-id="${r.s.id}" role="button" tabindex="0" aria-label="Histórico de rodízio de ${esc(r.s.name)}">${stuAv(r.s,r.s.name,'sm')}<div class="eqs-m"><b>${esc(r.s.name)}</b><div class="eqs-l">${r.lu?`<span class="eqc sm">${eqIcon(r.lu.eq,14)}</span>${esc(r.lu.eq.name)}${r.lu.date?' · '+eqSince(r.lu.date):''}${r.lu.manual?' · manual':''}`:'Sem histórico'}</div></div>${r.rp?'<span class="badge warn">repetiu</span>':''}${r.nx?`<span class="eqs-n" title="Sugestão para a próxima aula">${ico('chev-r')}${esc(r.nx.name)}</span>`:''}</div>`;
  const rn=base.filter(r=>r.rp).length;$('#eqRepN').textContent=base.length?`· ${rn?rn+' repetiram o último':'sem repetições'}`:'';
  $('#eqStu').innerHTML=rows.length?rows.slice(0,8).map(line).join('')+(rows.length>8?`<details class="eqmore"><summary>Ver mais ${rows.length-8} aluno(s)</summary>${rows.slice(8).map(line).join('')}</details>`:''):'<div class="empty">Nenhum aluno neste filtro.</div>';
}
function eqAssign(days){
  const d=$('#eqDate').value;let n=0,miss=0;
  for(let k=0;k<days;k++)db.classes.filter(c=>c.date===eqAdd(d,k)&&!c.equipmentId&&c.status!=='Cancelada').sort(sortCls).forEach(c=>{const id=eqPick(c.studentId,c.date,c.time,c.id);if(id){c.equipmentId=id;n++}else miss++});
  if(n)save();render();toast(n?`${n} aula(s) atribuídas${miss?`; ${miss} sem aparelho livre`:''}.`:miss?'Sem aparelho livre para as aulas restantes.':'Todas as aulas já têm aparelho.');
}
function eqClear(){
  const d=$('#eqDate').value,l=db.classes.filter(c=>c.date===d&&c.equipmentId&&!['Realizada','Cancelada'].includes(c.status));
  if(!l.length)return toast('Nenhum aparelho para limpar neste dia.');
  const snap=l.map(c=>[c,c.equipmentId]);l.forEach(c=>c.equipmentId='');
  if(save()){render();undoBar(`Aparelho removido de ${l.length} aula(s).`,()=>{snap.forEach(([c,q])=>c.equipmentId=q);if(save()){render();toast('Aparelhos restaurados.')}})}
}
function eqMove(id,dir){
  const L=db.equipment,i=L.findIndex(x=>x.id===id);if(i<0)return;let j=i+dir;const on=L[i].active!==false;
  while(j>=0&&j<L.length&&on&&L[j].active===false)j+=dir;
  if(j<0||j>=L.length)return;[L[i],L[j]]=[L[j],L[i]];save();render();toast('Ordem do rodízio atualizada.');
}
function eqSince(dt){const n=Math.round((new Date(iso(new Date())+'T12:00')-new Date(dt+'T12:00'))/864e5);return n<=0?'hoje':n===1?'ontem':`há ${n} d`}
function eqLastUsed(sid){
  const n=new Date(),k=`${iso(n)}T${pad(n.getHours())}:${pad(n.getMinutes())}`,c=db.classes.filter(c=>c.studentId===sid&&c.equipmentId&&!['Cancelada','Falta'].includes(c.status)&&`${c.date}T${c.time||'00:00'}`<=k&&eqById(c.equipmentId)).sort(sortCls).pop();
  if(c)return{eq:eqById(c.equipmentId),date:c.date,time:c.time};
  const m=(db.settings.eqLast||{})[sid],e=m&&eqById(m.id);return e?{eq:e,date:m.date||'',manual:true}:null;
}
function eqHistModal(sid){
  const s=studentById(sid);if(!s)return;
  const n=new Date(),today=iso(n),nk=`${today}T${pad(n.getHours())}:${pad(n.getMinutes())}`,ae=activeEq(),all=db.classes.filter(c=>c.studentId===sid&&c.equipmentId&&c.status!=='Cancelada').sort(sortCls).reverse(),cnt={};
  all.forEach(c=>cnt[c.equipmentId]=(cnt[c.equipmentId]||0)+1);
  const lu=eqLastUsed(sid),nx=eqById(eqPick(sid,eqAdd(today,1),s.time,'')),tot=all.length,m=(db.settings.eqLast||{})[sid];
  const bars=ae.map(e=>{const q=cnt[e.id]||0,p=tot?Math.round(q/tot*100):0;return `<div class="eqsh"><span class="eqc">${eqIcon(e,18)}</span><b>${esc(e.name)}</b><div class="bar ok"><i style="width:${p}%"></i></div><span class="sub">${q} · ${p}%</span></div>`}).join('');
  const tl=all.slice(0,30).map((c,i)=>{const e=eqById(c.equipmentId),o=all[i+1],rp=o&&o.equipmentId===c.equipmentId,fut=`${c.date}T${c.time||'00:00'}`>nk;
    return `<div class="tl-i${fut?' fut':''}${rp?' rp':''}" style="--i:${Math.min(i,10)}"><i class="tl-d"></i><span class="eqc sm">${e?eqIcon(e,14):'?'}</span><div style="flex:1;min-width:0"><b>${esc(e?e.name:'Aparelho removido')}</b><div class="sub">${esc(fmtDate(c.date).slice(0,5))} · ${esc(c.time||'—')} · ${esc(c.teacher||'—')}</div></div>${rp?'<span class="badge warn">repetiu</span>':''}${fut?'<span class="badge info">agendada</span>':''}</div>`}).join('');
  openModal(`<h2>Rodízio · ${esc(s.name)}</h2>
    <div class="mini"><div><small>ÚLTIMO USADO</small><b>${lu?esc(lu.eq.name):'—'}</b><small>${lu&&lu.date?eqSince(lu.date)+(lu.manual?' · manual':''):''}</small></div><div><small>PRÓXIMO SUGERIDO</small><b>${nx?esc(nx.name):'—'}</b></div><div><small>AULAS COM APARELHO</small><b>${tot}</b></div></div>
    <div class="dk">USO POR APARELHO</div>${bars||'<div class="sub">Sem aparelhos ativos.</div>'}
    <div class="dk">LINHA DO TEMPO</div>${tl?`<div class="tl">${tl}</div>`:'<div class="empty">Nenhuma aula com aparelho registrada.</div>'}
    <div class="dk">ÚLTIMO APARELHO (MANUAL)</div>
    <div class="row-acts"><select id="eqLastSel" aria-label="Último aparelho usado" style="flex:1"><option value="">Nenhum</option>${ae.map(e=>`<option value="${e.id}"${m&&m.id===e.id?' selected':''}>${esc(e.name)}</option>`).join('')}</select><button class="btn sm" data-act="eqLastSave" data-id="${sid}">Definir</button></div>
    <div class="sub" style="margin-top:6px">Ponto de partida do rodízio enquanto não houver aula com aparelho registrada.</div>
    <div class="row-acts" style="margin-top:12px"><button class="btn" data-act="closeModal">Fechar</button></div>`);
}
function rEquip(){
  const d=$('#eqDate').value||(($('#eqDate').value=iso(new Date())),iso(new Date())),f=$('#eqFilter').value;
  const cls=db.classes.filter(c=>c.date===d&&(c.status!=='Cancelada')).sort(sortCls),no=cls.filter(c=>!c.equipmentId).length,ae=activeEq();
  cu('eqK1',ae.length);cu('eqK2',ae.reduce((t,e)=>t+(Number(e.quantity)||1),0));cu('eqK3',cls.length);cu('eqK4',no);
  const ok=cls.length-no;$('#eqBarI').style.width=(cls.length?ok/cls.length*100:0)+'%';$('#eqBarT').textContent=cls.length?`${ok}/${cls.length} com aparelho`:'sem aulas';
  const shown=cls.filter(c=>f==='all'||(f==='with')===!!c.equipmentId),groups={};shown.forEach(c=>(groups[c.time]=groups[c.time]||[]).push(c));
  $('#eqDay').innerHTML=Object.keys(groups).length?Object.entries(groups).map(([t,l])=>`<div class="eqh">${esc(t)}</div>`+l.map(c=>{const e=eqById(c.equipmentId),lc=e&&lastEqOf(c.studentId,c.date,c.time,c.id),rp=lc&&lc.equipmentId===c.equipmentId;
    return `<div class="item eqr"><span class="eqc${e?'':' none'}">${e?eqIcon(e,20):'?'}</span><div style="flex:1;min-width:0"><b>${esc(c.studentName)}</b><div class="sub">${esc(c.teacher||'—')}${rp?' <span class="badge warn">repetiu</span>':''}</div></div>
    <select class="eqsel" data-act="eqSet" data-id="${c.id}" aria-label="Aparelho">${eqOptions(c.studentId,c.date,c.time,c.equipmentId||'',c.id)}</select></div>`}).join('')).join(''):'<div class="empty">Nenhuma aula neste filtro.</div>';
  const wd=String(new Date(d+'T12:00').getDay()),slots=db.hours.filter(h=>hourDays(h).includes(wd)).length;
  $('#eqList').innerHTML=db.equipment.length?db.equipment.map((e,i)=>eqCard(e,i,d,cls,slots)).join(''):'<div class="empty">Nenhum aparelho cadastrado.</div>';eqRotation(d);
}
function eqModal(id){
  const e=id?eqById(id):null;editing=id||null;
  openModal(`<h2>${e?'Editar aparelho':'Novo aparelho'}</h2><div class="form">
    <div class="field full"><label for="eqName">Nome *</label><input id="eqName" value="${esc(e?.name)}"></div>
    <div class="field"><label for="eqCat">Categoria</label><input id="eqCat" value="${esc(e?.category)}"></div>
    <div class="field"><label for="eqQty">Quantidade *</label><input id="eqQty" type="number" min="1" max="99" value="${esc(e?.quantity??1)}"></div>
    <div class="field"><label for="eqAct">Status</label><select id="eqAct"><option value="1">Ativo</option><option value="0"${e?.active===false?' selected':''}>Inativo</option></select></div>
    <div class="field"><label for="eqModel">Marca / modelo</label><input id="eqModel" value="${esc(e?.model)}"></div>
    <div class="field"><label for="eqMaint">Próxima revisão</label><input id="eqMaint" type="date" value="${esc(e?.maint)}"></div>
    <div class="field full"><label for="eqNotes">Observações</label><input id="eqNotes" value="${esc(e?.notes)}"></div>
  </div><div class="foot"><button class="btn" data-act="closeModal">Cancelar</button><button class="btn primary" data-act="saveEq">Salvar</button></div>`);
}
function saveEq(){
  const name=$('#eqName').value.trim(),q=Number($('#eqQty').value);
  if(!name)return toast('Informe o nome do aparelho.');
  if(!Number.isInteger(q)||q<1)return toast('A quantidade deve ser 1 ou mais.');
  if(db.equipment.some(x=>x.id!==editing&&x.name.toLowerCase()===name.toLowerCase()))return toast('Já existe um aparelho com esse nome.');
  const old=editing?eqById(editing):null,o={...(old||{}),id:old?.id||uid('eq'),name,category:$('#eqCat').value.trim(),quantity:q,active:$('#eqAct').value==='1',notes:$('#eqNotes').value.trim(),model:$('#eqModel').value.trim(),maint:$('#eqMaint').value};
  if(old)db.equipment[db.equipment.indexOf(old)]=o;else db.equipment.push(o);
  if(!save())return;closeModal();render();toast('Aparelho salvo.');
}
function delEq(id){
  const e=eqById(id);if(!e)return;const today=iso(new Date()),fut=db.classes.filter(c=>c.equipmentId===id&&c.date>=today&&c.status!=='Cancelada').length;
  if(fut)return toast(`${fut} aula(s) futuras usam ${e.name}. Desative-o ou troque o aparelho nelas.`);
  if(!confirm(`Excluir ${e.name}? O histórico de aulas passadas será mantido.`))return;
  db.equipment=db.equipment.filter(x=>x.id!==id);save();render();toast('Aparelho excluído.');
}
function eqAuto(){
  const d=$('#eqDate').value;let n=0,miss=0;
  db.classes.filter(c=>c.date===d&&!c.equipmentId&&c.status!=='Cancelada').sort(sortCls).forEach(c=>{const id=eqPick(c.studentId,c.date,c.time,c.id);if(id){c.equipmentId=id;n++}else miss++});
  if(n)save();render();toast(n?`${n} aula(s) atribuídas${miss?`; ${miss} sem aparelho livre`:''}.`:miss?'Sem aparelho livre para as aulas restantes.':'Todas as aulas já têm aparelho.');
}
Object.assign(ACT,{newEq:()=>eqModal(),editEq:e=>eqModal(e.dataset.id),saveEq,delEq:e=>delEq(e.dataset.id),eqAuto,eqWeek:()=>eqAssign(7),eqClear,eqMove:e=>eqMove(e.dataset.id,+e.dataset.d),eqHist:e=>eqHistModal(e.dataset.id),
  eqLF:e=>{eqRotation.f=e.dataset.f;eqRotation($('#eqDate').value||iso(new Date()))},
  eqLastSave:e=>{const v=$('#eqLastSel').value,L=db.settings.eqLast=db.settings.eqLast||{};if(v)L[e.dataset.id]={id:v,date:iso(new Date())};else delete L[e.dataset.id];
    if(save()){toast(v?'Último aparelho definido.':'Definição manual removida.');eqHistModal(e.dataset.id);render()}},
  eqMode:e=>{db.settings.eqMode=e.dataset.m==='sequence'?'sequence':'balanced';save();render();toast(eqMode()==='sequence'?'Rodízio em sequência.':'Rodízio equilibrado.')}});
document.addEventListener('change',e=>{
  const t=e.target;
  if(t.dataset.act==='eqSet'){const c=classById(t.dataset.id),eq=eqById(t.value);
    if(c&&(!t.value||eqAvailable(eq,c.date,c.time,c.id))){c.equipmentId=t.value;save();toast('Aparelho atualizado.')}else toast('Aparelho ocupado nesse horário.');render()}
  if(['cStudent','cDate','cTime'].includes(t.id)&&$('#cEquip'))fillEq(false);
});
$('#eqDate').addEventListener('change',rEquip);$('#eqFilter').addEventListener('change',rEquip);


/* ========== PAINEL: PIPELINE + APARELHOS ========== */
let pipeMode='classes';
function rPipe(){
  const t=iso(new Date()),k=t.slice(0,7),st=(l,v,pc,sub)=>`<div style="padding:8px 0"><div style="display:flex;justify-content:space-between"><b>${l}</b><b>${v}</b></div><div class="bar" style="margin:4px 0"><i style="width:${Math.max(0,Math.min(100,pc))}%"></i></div><div class="sub">${sub}</div></div>`;
  $$('#pipeSeg button').forEach(b=>b.classList.toggle('on',b.dataset.m===pipeMode));
  if(pipeMode==='classes'){
    const l=db.classes.filter(c=>c.date===t&&c.status!=='Cancelada'),ready=l.filter(c=>c.equipmentId),done=l.filter(c=>c.status==='Realizada'),n=l.length;
    $('#pipeSub').textContent='Fluxo das aulas de hoje';
    $('#pipeTrack').innerHTML=st('Agendadas',n,n?100:0,'aulas no dia')+st('Preparadas',ready.length,n?ready.length/n*100:0,`${n-ready.length} sem aparelho`)+st('Realizadas',done.length,n?done.length/n*100:0,n?Math.round(done.length/n*100)+'% concluído':'sem aulas hoje');
  }else{
    const f=db.finance.filter(x=>!isExp(x)&&String(x.dueDate).startsWith(k)),sum=a=>a.reduce((q,x)=>q+Number(x.value||0),0),tot=sum(f),pend=f.filter(x=>x.status!=='Pago'),paid=f.filter(x=>x.status==='Pago');
    $('#pipeSub').textContent='Fluxo financeiro do mês';
    $('#pipeTrack').innerHTML=st('Previsto',money(tot),tot?100:0,`${f.length} lançamentos`)+st('Pendente',money(sum(pend)),tot?sum(pend)/tot*100:0,`${pend.length} em aberto`)+st('Recebido',money(sum(paid)),tot?sum(paid)/tot*100:0,tot?Math.round(sum(paid)/tot*100)+'% do previsto':'sem lançamentos');
  }
}
function rDashEq(){
  const t=iso(new Date()),l=db.classes.filter(c=>c.date===t&&c.status!=='Cancelada').sort(sortCls),g={};
  l.forEach(c=>(g[c.time]=g[c.time]||[]).push(c));
  $('#dashEq').innerHTML=l.length?Object.entries(g).map(([h,cs])=>`<div class="item" style="align-items:flex-start"><b style="min-width:54px">${esc(h)}</b><div class="pill" style="margin:0;flex:1">${cs.map(c=>{const e=db.equipment.find(x=>x.id===c.equipmentId);return `<span class="badge ${e?'info':'warn'}">${esc(String(c.studentName).split(' ')[0])} · ${e?esc(e.name):'sem aparelho'}</span>`}).join('')}</div></div>`).join(''):'<div class="empty">Nenhuma aula hoje.</div>';
}
Object.assign(ACT,{pipe:e=>{pipeMode=e.dataset.m;rPipe()}});
function undoBar(msg,fn){
  let b=$('#undoBar');if(!b){b=document.createElement('div');b.id='undoBar';b.setAttribute('role','status');document.body.appendChild(b)}
  b.innerHTML=`<span>${esc(msg)}</span><button type="button" data-act="undoDo">Desfazer</button>`;undoBar.fn=fn;b.classList.add('on');
  clearTimeout(undoBar.t);undoBar.t=setTimeout(()=>{b.classList.remove('on');undoBar.fn=null},6000);
}
function fabSet(o){const f=$('#fab');f.classList.toggle('open',o);$('#fabMenu').inert=!o;$('#fabBtn').setAttribute('aria-expanded',o)}
function fabSync(){const f=$('#fab');if(!f)return;const h=!!$('#app').hidden||!$('#modal').hidden;if(f.hidden!==h)f.hidden=h;if(h&&f.classList.contains('open'))fabSet(false)}
document.addEventListener('keydown',e=>{if(e.key==='Escape'&&$('#fab')?.classList.contains('open'))fabSet(false)});
Object.assign(ACT,{
  todayF:e=>{rDash.tf=e.dataset.f;render()},nextMore:()=>{rDashLive.n=(rDashLive.n||4)+4;rDashLive()},nextLess:()=>{rDashLive.n=4;rDashLive()},
  undoDo:()=>{const f=undoBar.fn;undoBar.fn=null;$('#undoBar')?.classList.remove('on');if(f)f()},
  fabToggle:()=>fabSet(!$('#fab').classList.contains('open')),fabDo:e=>{fabSet(false);const a=ACT[e.dataset.a];if(a)a(e)}
});
Object.assign(ACT,{
  nowSet:e=>{const c=classById(e.dataset.id);if(!c)return;const pv=c.status,pu=c.updatedAt;c.status=e.dataset.s;c.updatedAt=new Date().toISOString();if(save()){render();undoBar(c.status==='Falta'?'Falta registrada.':'Aula marcada como realizada.',()=>{c.status=pv;c.updatedAt=pu;if(save()){render();toast('Alteração desfeita.')}})}},
  nowWa:e=>waCompose({k:'classNow',cid:e.dataset.id})
});



/* ========== CARDS POR ALUNO (dados do aluno + financeiro do aluno) ========== */
const detOpen={};document.addEventListener('toggle',e=>{if(e.target.dataset?.k){detOpen[e.target.dataset.k]=e.target.open;e.target.closest('.sc')?.querySelector('.sc-main')?.setAttribute('aria-expanded',e.target.open)}},true);
document.addEventListener('keydown',e=>{const h=e.target.closest?.('.sc-main[data-act=cardToggle]');if(h&&(e.key==='Enter'||e.key===' ')){e.preventDefault();ACT.cardToggle(h)}});
const detail=(k,html)=>`<details class="det" data-k="${k}"${detOpen[k]?' open':''}><summary>Ver detalhes</summary>${html}</details>`;
const initials=n=>String(n).split(' ').filter(Boolean).slice(0,2).map(x=>x[0]).join('').toUpperCase();

/* ========== AVATAR DO ALUNO — foto do WhatsApp / galeria, ou iniciais em cor própria ========== */
const PH_KEY='studio_pilates_louise_karla_photos_v1',PH_OK=/^data:image\/(?:jpeg|png|webp);base64,[A-Za-z0-9+/=]+$/;
let PHOTOS={};try{const p=JSON.parse(localStorage.getItem(PH_KEY));if(p&&typeof p==='object'&&!Array.isArray(p))PHOTOS=p}catch{}
function savePhotos(){try{localStorage.setItem(PH_KEY,JSON.stringify(PHOTOS));return true}catch{toast('Sem espaço para guardar as fotos neste aparelho.');return false}}
const photoOf=id=>{const p=PHOTOS[id];return typeof p==='string'&&PH_OK.test(p)?p:''};
const nameHue=n=>{let h=7;for(const c of String(n||'').trim().toLowerCase())h=(h*31+c.charCodeAt(0))%360;return h};
const stuByName=n=>{const l=db.students.filter(s=>s.name===n);return l.length===1?l[0]:null};
const avHtml=(name,photo,cls='',cfg=null)=>cfg?`<div class="av${cls?' '+cls:''} sv">${avatarSvg(cfg)}</div>`:photo?`<div class="av${cls?' '+cls:''} ph"><img src="${photo}" alt="" loading="lazy" decoding="async"></div>`:`<div class="av${cls?' '+cls:''} c" style="--h:${nameHue(name)}">${esc(initials(name||'?'))}</div>`;
const stuAv=(s,name,cls='')=>{s=s||stuByName(name);return s?avHtml(s.name,photoOf(s.id),cls,s.avUse&&s.avatar?s.avatar:null):`<div class="av${cls?' '+cls:''}">${esc(initials(name||'?'))}</div>`};
const scAv=o=>{const st=(o.sid&&studentById(o.sid))||(o.av||/^(tc|rt|g):/.test(o.key||'')?null:stuByName(o.name));
  return st?stuAv(st,st.name):`<div class="av">${avIco(o.av)?ico(avIco(o.av)):esc(o.av||initials(o.name))}</div>`};

/* ========== CONSTRUTOR DE AVATAR (SVG próprio, sem internet) ========== */
const AVP={
  skin:['#FDE3CF','#F7CDA8','#EDB98A','#D8996A','#B97A4B','#8D5A38','#6B4128','#4A2B1B'],
  hair:['#1B1A1F','#3A2418','#6B4226','#A9743A','#E2BC6A','#C4512A','#9A9A9F','#F1F1EE','#E85C9C','#4F7BE8','#8A5AD9'],
  eye:['#3B2A20','#7A4B24','#4F8A4F','#3E78C9','#7E8A94','#7B4BC9'],
  lip:[null,'#E8708F','#D0222F','#7A1F3D','#F0735A','#7B3FA0'],
  acc:['#1C1F26','#F08300','#3358F0','#2F9E6B','#E5388A','#6D4AE0','#D64545','#10B9BF','#C9A227','#F2F3F6'],
  cloth:['#F08300','#3358F0','#2F9E6B','#E5388A','#6D4AE0','#1C1F26','#F2F3F6','#D64545','#10B9BF','#C9A227'],
  bg:['#FDE8D7','#FFD6E0','#E3D5FF','#CFE8FF','#CDF3E4','#FFF3B0','#FFD0B5','#D5DBE8','#BFE3C0','#2E3A59']
};
const AVN={sx:3,sk:8,fc:4,hs:12,hc:11,ey:7,ec:6,br:6,ns:4,mt:7,lp:6,fh:6,gl:5,hd:7,er:4,xc:10,fr:2,bl:2,mo:2,cs:6,cc:10,bg:10};
const AVDEF={sx:2,sk:2,fc:0,hs:1,hc:1,ey:1,ec:0,br:1,ns:0,mt:0,lp:0,fh:0,gl:0,hd:0,er:0,xc:1,fr:0,bl:0,mo:0,cs:0,cc:1,bg:0};
const avMix=(h,t,a)=>{const p=x=>{if(x.length===4)x='#'+x[1]+x[1]+x[2]+x[2]+x[3]+x[3];return[1,3,5].map(i=>parseInt(x.slice(i,i+2),16))},A=p(h),B=p(t);return '#'+A.map((v,i)=>Math.round(v+(B[i]-v)*a).toString(16).padStart(2,'0')).join('')};
const avSym=s=>`${s}<g transform="translate(100 0) scale(-1 1)">${s}</g>`;
const avG=(c,k)=>{const v=Number(c&&c[k]);return Number.isInteger(v)&&v>=0&&v<AVN[k]?v:AVDEF[k]};
const AV_FACE=['M50 22C37 22 31 33 31 46C31 60 39 70 50 70C61 70 69 60 69 46C69 33 63 22 50 22Z','M50 24C36 24 30 35 30 47C30 60 38 69 50 69C62 69 70 60 70 47C70 35 64 24 50 24Z','M50 23C38 23 32 27 32 40L32 54C32 63 38 70 50 70C62 70 68 63 68 54L68 40C68 27 62 23 50 23Z','M50 22C38 22 31 31 31 42C31 54 40 72 50 72C60 72 69 54 69 42C69 31 62 22 50 22Z'];
function avHair(i,c){
  const d=avMix(c,'#000',.2),cap=`<path d="M30.5 46C28 27 38 17 50 17S72 27 69.5 46C68 37 64 31 50 31S32 37 30.5 46Z" fill="${c}"/>`;
  const lf=`<path d="M30 47C28 28 38 18 50 18S72 28 70 47C68 37 61 28 50 28S32 37 30 47Z" fill="${c}"/>`;
  switch(i){
    case 1:return['',cap];
    case 2:return['',`<path d="M30 47C27 25 38 12 53 13C67 14 74 26 70 47C69 38 65 31 56 30C50 29 42 29 38 33C34 36 31 41 30 47Z" fill="${c}"/><path d="M36 25C41 11 63 9 70 25C60 19 46 19 36 25Z" fill="${c}"/><path d="M43 17C52 13 61 15 66 21" stroke="${d}" stroke-width="1.4" fill="none" stroke-linecap="round"/>`];
    case 3:return['',`<path d="M30 47C28 27 38 16 52 16C66 16 72 27 70 47C69 38 65 32 54 29C44 27 36 30 33 38C31 41 30 44 30 47Z" fill="${c}"/><path d="M41 19C47 22 51 26 53 29" stroke="${d}" stroke-width="1.3" fill="none" stroke-linecap="round"/>`];
    case 4:return[`<g fill="${c}"><circle cx="31" cy="38" r="8"/><circle cx="69" cy="38" r="8"/><circle cx="35" cy="26" r="9"/><circle cx="50" cy="20" r="10"/><circle cx="65" cy="26" r="9"/></g>`,`<g fill="${c}"><circle cx="39" cy="30" r="5.5"/><circle cx="50" cy="28" r="5.5"/><circle cx="61" cy="30" r="5.5"/><circle cx="33" cy="36" r="4.5"/><circle cx="67" cy="36" r="4.5"/></g>`];
    case 5:return[`<circle cx="50" cy="36" r="30" fill="${c}"/>`,`<path d="M32 44C31 28 40 20.5 50 20.5S69 28 68 44C62 35.5 58 32.5 50 32.5S38 35.5 32 44Z" fill="${c}"/>`];
    case 6:return[`<path d="M27 46C24 22 37 13 50 13S76 22 73 46L75 80C75 88 68 90 63 88L37 88C32 90 25 88 25 80Z" fill="${c}"/>`,lf];
    case 7:return[`<path d="M28 44C24 20 38 13 50 13S76 20 72 44C76 56 70 62 74 72C78 82 70 90 63 85L37 85C30 90 22 82 26 72C30 62 24 56 28 44Z" fill="${c}"/>`,`<path d="M30 47C27 27 38 17 52 17C66 17 73 28 70 47C66 35 58 27 46 29C38 30 33 37 30 47Z" fill="${c}"/>`];
    case 8:return[`<path d="M60 20C80 14 86 36 78 52C75 60 80 66 72 72C71 64 70 56 68 46Z" fill="${c}"/><circle cx="63" cy="20.5" r="3" fill="${d}"/>`,cap];
    case 9:return[`<circle cx="50" cy="12" r="9.5" fill="${c}"/>`,`${cap}<ellipse cx="50" cy="19.5" rx="9" ry="2" fill="${d}"/>`];
    case 10:return[`<path d="M28 46C26 24 38 14 50 14S74 24 72 46Z" fill="${c}"/>`+[29,71].map(x=>[52,58.5,65,71.5,78].map(y=>`<circle cx="${x}" cy="${y}" r="4.5" fill="${c}"/>`).join('')+`<circle cx="${x}" cy="83" r="2.6" fill="${d}"/>`).join(''),lf];
    case 11:return[`<path d="M27 46C25 22 38 13 50 13S75 22 73 46L74 66C74 71 67 71 64 67L36 67C33 71 26 71 26 66Z" fill="${c}"/>`,`<path d="M29 47C27 26 38 17 50 17S73 26 71 47L71 38C62 33 38 33 29 38Z" fill="${c}"/>`];
  }
  return['',''];
}
function avEye(st,x,col){
  const y=47,dk='#22212a';
  switch(st){
    case 0:return `<circle cx="${x}" cy="${y}" r="2.1" fill="${dk}"/>`;
    case 1:return `<ellipse cx="${x}" cy="${y}" rx="4.3" ry="4.7" fill="#fff"/><circle cx="${x}" cy="${y+.3}" r="2.9" fill="${col}"/><circle cx="${x}" cy="${y+.3}" r="1.4" fill="#111"/><circle cx="${x-1}" cy="${y-1}" r=".9" fill="#fff"/>`;
    case 2:return `<path d="M${x-4} ${y+1.5}Q${x} ${y-4} ${x+4} ${y+1.5}" stroke="${dk}" stroke-width="1.9" stroke-linecap="round" fill="none"/>`;
    case 3:return `<ellipse cx="${x}" cy="${y}" rx="4" ry="3.4" fill="#fff"/><circle cx="${x}" cy="${y}" r="2.4" fill="${col}"/><circle cx="${x}" cy="${y}" r="1.1" fill="#111"/><path d="M${x-4.4} ${y-.5}Q${x} ${y-5.2} ${x+4.4} ${y-.5}" stroke="${dk}" stroke-width="1.5" fill="none" stroke-linecap="round"/><path d="M${x-4.2} ${y-1.6}l-2.2 -1.8M${x-3.6} ${y-2.4}l-1.2 -2.2" stroke="${dk}" stroke-width="1.1" stroke-linecap="round"/>`;
    case 4:return `<path d="M${x-4} ${y-.5}Q${x} ${y+3.6} ${x+4} ${y-.5}" stroke="${dk}" stroke-width="1.9" stroke-linecap="round" fill="none"/>`;
    case 5:return `<ellipse cx="${x}" cy="${y}" rx="4.4" ry="5" fill="#fff"/><circle cx="${x}" cy="${y+.2}" r="3.6" fill="${col}"/><circle cx="${x}" cy="${y+.2}" r="1.7" fill="#111"/><circle cx="${x-1.3}" cy="${y-1.5}" r="1.1" fill="#fff"/><circle cx="${x+1.2}" cy="${y+1.3}" r=".6" fill="#fff"/>`;
    default:return `<path d="M${x-4.6} ${y}Q${x} ${y-4.6} ${x+4.6} ${y}Q${x} ${y+3.8} ${x-4.6} ${y}Z" fill="#fff" stroke="${dk}" stroke-width=".8"/><circle cx="${x}" cy="${y}" r="2.2" fill="${col}"/><circle cx="${x}" cy="${y}" r="1" fill="#111"/>`;
  }
}
const AV_BROW=[null,'M36 40.5L46 40.5','M36 41Q41 36.5 46 39.5','M36 40.5L46 40.5','M36 42L46 38','M36 38L46 41.5'];
let avU=0;
function avatarSvg(cfg,vb='10 7 80 80'){
  const u=++avU;
  const G=k=>avG(cfg,k),sx=G('sx'),sk=AVP.skin[G('sk')],hc=AVP.hair[G('hc')],xc=AVP.acc[G('xc')],cl=AVP.cloth[G('cc')],bg=AVP.bg[G('bg')],ec=AVP.eye[G('ec')];
  const sd=avMix(sk,'#000',.2),line=avMix(sk,'#000',.38),lip=AVP.lip[G('lp')]||avMix(avMix(sk,'#C0505A',.55),'#000',.08),ink=avMix(lip,'#000',.25);
  let [hb,hf]=avHair(G('hs'),hc);const hg=`url(#hg${u})`;hb=hb.split(`fill="${hc}"`).join(`fill="${hg}"`);hf=hf.split(`fill="${hc}"`).join(`fill="${hg}"`);const nw=[12,15,13.5][sx],cs=G('cs'),dk=avMix(cl,'#000',.22);
  let o=`<svg xmlns="http://www.w3.org/2000/svg" viewBox="${vb}" preserveAspectRatio="xMidYMid slice" aria-hidden="true" focusable="false"><defs><radialGradient id="sg${u}" cx="46%" cy="38%" r="75%"><stop offset="0" stop-color="${avMix(sk,'#fff',.16)}"/><stop offset=".55" stop-color="${sk}"/><stop offset="1" stop-color="${avMix(sk,'#7a3a1c',.16)}"/></radialGradient><linearGradient id="hg${u}" x1="0" y1="0" x2="1" y2="1"><stop offset="0" stop-color="${avMix(hc,'#fff',.22)}"/><stop offset=".5" stop-color="${hc}"/><stop offset="1" stop-color="${avMix(hc,'#000',.28)}"/></linearGradient><radialGradient id="bg${u}" cx="50%" cy="35%" r="80%"><stop offset="0" stop-color="${avMix(bg,'#fff',.35)}"/><stop offset="1" stop-color="${avMix(bg,'#000',.14)}"/></radialGradient><linearGradient id="cg${u}" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="#000" stop-opacity=".18"/><stop offset=".45" stop-color="#000" stop-opacity="0"/><stop offset="1" stop-color="#000" stop-opacity=".28"/></linearGradient><filter id="bl${u}" x="-30%" y="-30%" width="160%" height="160%"><feGaussianBlur stdDeviation="1.6"/></filter><filter id="bs${u}" x="-30%" y="-30%" width="160%" height="160%"><feGaussianBlur stdDeviation=".7"/></filter><clipPath id="fc${u}"><path d="${AV_FACE[G('fc')]}"/></clipPath><clipPath id="nk${u}"><path d="M${50-nw/2} 58h${nw}v24h-${nw}Z"/></clipPath><radialGradient id="ig${u}" cx="50%" cy="50%" r="50%"><stop offset="0" stop-color="${avMix(ec,'#fff',.45)}" stop-opacity=".75"/><stop offset=".6" stop-color="${ec}" stop-opacity="0"/><stop offset="1" stop-color="#000" stop-opacity=".45"/></radialGradient><filter id="tx${u}" x="0" y="0" width="100%" height="100%"><feTurbulence type="fractalNoise" baseFrequency=".9" numOctaves="2" seed="4"/><feColorMatrix type="matrix" values="0 0 0 0 .25  0 0 0 0 .12  0 0 0 0 .05  0 0 0 1.1 -.42"/></filter><clipPath id="hr${u}">${hf}</clipPath></defs><rect x="-60" y="-60" width="220" height="220" fill="url(#bg${u})"/>${hb}`;
  /* pescoço */
  o+=`<path d="M${50-nw/2} 58h${nw}v24q-${nw/2} 4-${nw} 0Z" fill="url(#sg${u})"/><g clip-path="url(#nk${u})"><ellipse cx="50" cy="63" rx="${nw/2+1}" ry="8" fill="${avMix(sk,'#3a1a0c',.55)}" opacity=".5" filter="url(#bl${u})"/></g>`;
  o+=avSym(`<path d="M44.8 62Q44.4 71 43.4 79" stroke="${avMix(sk,'#3a1a0c',.5)}" stroke-width="1.1" fill="none" opacity=".22" filter="url(#bs${u})"/>`);
  /* corpo e roupa */
  const body=['M24 101C24 88 32 81 43 79L57 79C68 81 76 88 76 101Z','M17 101C17 87 28 80 42 78L58 78C72 80 83 87 83 101Z','M21 101C21 87 30 80 42 78.5L58 78.5C70 80 79 87 79 101Z'][sx];
  if(cs===2)o+=`<path d="${body}" fill="${sk}"/><path d="M33 101L37.5 80Q50 93 62.5 80L67 101Z" fill="${cl}"/>`;
  else{o+=`<path d="${body}" fill="${cl}"/>`;
    if(cs===0)o+=`<path d="M41.8 78Q50 86.5 58.2 78Z" fill="${sk}"/>`;
    if(cs===1)o+=`<path d="M42 78L50 91L58 78Z" fill="${sk}"/>`;
    if(cs===3)o+=`<path d="M42 78Q50 88 58 78Z" fill="${sk}"/><path d="M39.5 78Q50 91 60.5 78" stroke="${dk}" stroke-width="3.4" stroke-linecap="round" fill="none"/><path d="M46.5 86v9M53.5 86v9" stroke="#fff" stroke-width="1.2" stroke-linecap="round"/>`;
    if(cs===4)o+=`<path d="M43 78L50 93L57 78Z" fill="#fff"/><path d="M44.5 78L50 85.5L55.5 78Z" fill="${sk}"/><path d="M41.5 78L47.5 91L42 93L34 82ZM58.5 78L52.5 91L58 93L66 82Z" fill="${dk}"/>`;
    if(cs===5)o+=`<path d="M41.5 71h17v10q-8.5 3.5-17 0Z" fill="${dk}"/><path d="M41.5 75.5q8.5 3 17 0" stroke="#000" stroke-opacity=".15" fill="none"/>`;
  }
  o+=`<path d="${body}" fill="url(#cg${u})"/><ellipse cx="50" cy="80" rx="${nw/2+5}" ry="3.2" fill="#000" opacity=".22" filter="url(#bs${u})"/>`;
  /* orelhas e rosto */
  o+=`<circle cx="31.5" cy="47.5" r="4.2" fill="${sk}"/><circle cx="68.5" cy="47.5" r="4.2" fill="${sk}"/><circle cx="31.8" cy="48" r="2" fill="${sd}" opacity=".5"/><circle cx="68.2" cy="48" r="2" fill="${sd}" opacity=".5"/>`;
  o+=avSym(`<path d="M30.4 45.2Q28.7 48 30.8 51.4" stroke="${line}" stroke-width=".6" fill="none" opacity=".6" stroke-linecap="round"/>`);
  const er=G('er');if(er)o+=avSym(er===1?`<circle cx="31.6" cy="53" r="1.9" fill="${xc}"/>`:er===2?`<circle cx="31.4" cy="57" r="4" fill="none" stroke="${xc}" stroke-width="1.3"/>`:`<path d="M31.6 52.5l-1.9 3.6 1.9 3.6 1.9-3.6Z" fill="${xc}"/>`);
  o+=`<path d="${AV_FACE[G('fc')]}" fill="url(#sg${u})"/><g clip-path="url(#fc${u})"><ellipse cx="50" cy="26" rx="24" ry="8" fill="${avMix(sk,'#3a1a0c',.6)}" opacity=".38" filter="url(#bl${u})"/><ellipse cx="31" cy="58" rx="5" ry="14" fill="${avMix(sk,'#3a1a0c',.6)}" opacity=".3" filter="url(#bl${u})"/><ellipse cx="69" cy="58" rx="5" ry="14" fill="${avMix(sk,'#3a1a0c',.6)}" opacity=".3" filter="url(#bl${u})"/><ellipse cx="50" cy="69" rx="12" ry="3" fill="${avMix(sk,'#3a1a0c',.6)}" opacity=".28" filter="url(#bl${u})"/><ellipse cx="46" cy="39" rx="9" ry="6" fill="#fff" opacity=".2" filter="url(#bl${u})"/><ellipse cx="50" cy="66.5" rx="4" ry="1.6" fill="#fff" opacity=".16" filter="url(#bs${u})"/></g>${avSym(`<ellipse cx="41" cy="46.5" rx="7" ry="4.6" fill="${avMix(sk,'#4a2312',.55)}" opacity=".22" filter="url(#bl${u})"/>`)}`;
  o+=`<rect x="28" y="18" width="44" height="56" filter="url(#tx${u})" opacity=".22" clip-path="url(#fc${u})"/>`;
  if(G('bl'))o+=`<ellipse cx="37.5" cy="56" rx="4.6" ry="3" fill="#FF6F91" opacity=".32"/><ellipse cx="62.5" cy="56" rx="4.6" ry="3" fill="#FF6F91" opacity=".32"/>`;
  if(G('fr'))o+=`<g fill="${avMix(sk,'#5a2d12',.5)}" opacity=".7">${[[36,53.5],[39.5,55],[42,52.5],[38,57.5],[58,52.5],[60.5,55],[64,53.5],[62,57.5]].map(([x,y])=>`<circle cx="${x}" cy="${y}" r=".95"/>`).join('')}</g>`;
  if(G('mo'))o+=`<circle cx="57.5" cy="58" r="1.15" fill="${avMix(sk,'#3a1c0c',.7)}"/>`;
  /* barba / bigode */
  const fh=G('fh'),bc=avMix(hc,'#000',.05),must=`<path d="M41.5 58.5Q46 54.5 50 57.5Q54 54.5 58.5 58.5Q54 60.5 50 58.8Q46 60.5 41.5 58.5Z" fill="${bc}"/>`;
  if(fh===1)o+=must;
  if(fh===2)o+=`${must}<path d="M44.5 66Q50 64 55.5 66Q56 73 50 73Q44 73 44.5 66Z" fill="${bc}"/>`;
  if(fh===3)o+=`<path d="M31 48C31 61 38 71.5 50 71.5S69 61 69 48C67 56 63 59 58 58.5Q50 56 42 58.5C37 59 33 56 31 48Z" fill="${bc}"/>`;
  if(fh===4)o+=`<path d="M30 44C29 63 38 77 50 77S71 63 70 44C68 54 64 57 58 56Q50 53 42 56C36 57 32 54 30 44Z" fill="${bc}"/>${must}`;
  if(fh===5)o+=`<path d="M31 48C31 61 38 71.5 50 71.5S69 61 69 48C67 56 63 59 58 58.5Q50 56 42 58.5C37 59 33 56 31 48Z" fill="${bc}" opacity=".3"/>`;
  /* nariz */
  const ns=G('ns');
  o+=ns===0?`<path d="M48.2 54.5Q50 56.6 51.8 54.5" stroke="${line}" stroke-width="1.5" fill="none" stroke-linecap="round"/>`:ns===1?`<ellipse cx="50" cy="54.2" rx="2.6" ry="2.2" fill="${line}" opacity=".55"/>`:ns===2?`<path d="M50 46.5L47.4 54.6Q50 56.2 52.6 54.6" stroke="${line}" stroke-width="1.4" fill="none" stroke-linecap="round" stroke-linejoin="round"/>`:`<path d="M46.4 54Q50 58 53.6 54" stroke="${line}" stroke-width="1.5" fill="none" stroke-linecap="round"/><circle cx="47.8" cy="55" r=".9" fill="${line}"/><circle cx="52.2" cy="55" r=".9" fill="${line}"/>`;
  o+=`<path d="M52.6 47.5Q55.6 53 52.4 55.4" stroke="${avMix(sk,'#3a1a0c',.5)}" stroke-width="1.6" fill="none" stroke-linecap="round" opacity=".28" filter="url(#bs${u})"/><ellipse cx="49" cy="52.4" rx=".9" ry="2.2" fill="#fff" opacity=".28" filter="url(#bs${u})"/>`;
  o+=avSym(`<path d="M44.2 56.2Q42.6 60 44 63.4" stroke="${avMix(sk,'#3a1a0c',.5)}" stroke-width="1.2" fill="none" opacity=".16" filter="url(#bs${u})"/>`)+`<path d="M49.1 57.6v2.4M50.9 57.6v2.4" stroke="${avMix(sk,'#3a1a0c',.5)}" stroke-width=".5" opacity=".22"/>`;
  /* boca */
  const mt=G('mt');
  o+=[`<path d="M42.8 60.3Q46.6 58.4 50 59.6Q53.4 58.4 57.2 60.3Q50 61.9 42.8 60.3Z" fill="${avMix(lip,'#000',.14)}"/><path d="M43.2 60.8Q50 66.2 56.8 60.8Q50 62.2 43.2 60.8Z" fill="${lip}"/><path d="M42.6 60.4Q50 63.2 57.4 60.4" stroke="${ink}" stroke-width=".7" fill="none" stroke-linecap="round"/><ellipse cx="50" cy="63.3" rx="2.4" ry=".55" fill="#fff" opacity=".3"/>`,
    `<path d="M42.5 60Q50 72 57.5 60Z" fill="#6b1f2a"/><path d="M43.8 60.4Q50 63 56.2 60.4L56 62Q50 64.6 44 62Z" fill="#fff"/><path d="M42.5 60Q50 72 57.5 60Z" fill="none" stroke="${ink}" stroke-width="1.2" stroke-linejoin="round"/>`,
    `<path d="M44.2 61.8Q47 60.2 50 61Q53 60.2 55.8 61.8Q50 62.8 44.2 61.8Z" fill="${avMix(lip,'#000',.14)}"/><path d="M44.6 62.1Q50 66 55.4 62.1Q50 63.2 44.6 62.1Z" fill="${lip}"/><path d="M44.1 61.9Q50 63 55.9 61.9" stroke="${ink}" stroke-width=".7" fill="none" stroke-linecap="round"/><ellipse cx="50" cy="63.7" rx="2.2" ry=".5" fill="#fff" opacity=".28"/>`,
    `<path d="M43.6 62.6Q47 60.6 50 61.4Q53.4 60.2 57.2 59.4Q53 62 50 62.6Q46 62.8 43.6 62.6Z" fill="${avMix(lip,'#000',.14)}"/><path d="M44.4 62.8Q50 66.4 56 61.6Q50 63.4 44.4 62.8Z" fill="${lip}"/><path d="M43.6 62.6Q50 63.4 57.2 59.6" stroke="${ink}" stroke-width=".7" fill="none" stroke-linecap="round"/>`,
    `<path d="M46.2 61.9Q48 60.6 50 61.3Q52 60.6 53.8 61.9Q50 62.7 46.2 61.9Z" fill="${avMix(lip,'#000',.14)}"/><path d="M46.6 62.1Q50 65 53.4 62.1Q50 63 46.6 62.1Z" fill="${lip}"/><path d="M46.3 62Q50 62.9 53.7 62" stroke="${ink}" stroke-width=".6" fill="none" stroke-linecap="round"/>`,
    `<ellipse cx="50" cy="62.2" rx="2.3" ry="2.7" fill="${lip}"/><ellipse cx="50" cy="62.4" rx="1" ry="1.3" fill="${ink}" opacity=".6"/>`,
    `<path d="M43.5 61Q47 57.8 50 60Q53 57.8 56.5 61Q50 63 43.5 61Z" fill="${lip}"/><path d="M43.5 61Q50 68 56.5 61Q50 62.6 43.5 61Z" fill="${lip}"/><path d="M43.5 61Q50 63 56.5 61" stroke="${ink}" stroke-width=".7" fill="none"/>`][mt];
  {const mk=G('mt');if(false)o+=`<path d="M43.4 61Q50 66.6 56.6 61Q50 63.4 43.4 61Z" fill="${lip}" opacity=".6"/>`;if(mk===5||mk===6)o+=`<ellipse cx="50" cy="${mk===5?61.2:62.6}" rx="${mk===5?.9:2.4}" ry=".7" fill="#fff" opacity=".4" filter="url(#bs${u})"/>`;if(false)o+=`<ellipse cx="50" cy="63.6" rx="3" ry="1" fill="${lip}" opacity=".3" filter="url(#bs${u})"/>`}
  /* olhos e sobrancelhas */
  const eyk=G('ey'),nat=[1,3,5,6].includes(eyk),ks={1:1,3:.92,5:1.14,6:.95}[eyk]||1,lid=avMix(sk,'#2a1208',.72),skd=avMix(sk,'#4a2312',.55);
  if(nat){
    const ey0=47.2,top=ey0-4.2*ks,bot=ey0+3*ks,ep=`M36.2 47.7Q41 ${top.toFixed(1)} 45.8 47Q41.3 ${bot.toFixed(1)} 36.2 47.7Z`,ir=2.35*ks,cy=(ey0-.2).toFixed(1);
    o=o.replace('</defs>',`<clipPath id="ey${u}"><path d="${ep}"/></clipPath><linearGradient id="ew${u}" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="#cfc6c0"/><stop offset=".4" stop-color="#f6f1ec"/><stop offset="1" stop-color="#e9e0da"/></linearGradient></defs>`);
    const lash=eyk===3?`<path d="M36.6 47.2l-2 -1.1M37.2 46l-1.7 -1.6M38.4 45l-1 -2M39.8 44.4l-.5 -2" stroke="${lid}" stroke-width=".6" stroke-linecap="round"/>`:`<path d="M36.5 47.3l-1.7 -1M37.2 46l-1.2 -1.4" stroke="${lid}" stroke-width=".55" stroke-linecap="round"/>`;
    o+=avSym(`<ellipse cx="41" cy="${(bot+3).toFixed(1)}" rx="5.2" ry="1.4" fill="${skd}" opacity=".22" filter="url(#bs${u})"/><path d="${ep}" fill="url(#ew${u})"/><g clip-path="url(#ey${u})"><circle cx="41.1" cy="${cy}" r="${ir}" fill="${ec}"/><circle cx="41.1" cy="${cy}" r="${ir}" fill="url(#ig${u})"/><circle cx="41.1" cy="${cy}" r="${ir}" fill="none" stroke="#000" stroke-opacity=".4" stroke-width=".5"/><circle cx="41.1" cy="${cy}" r="${(ir*.45).toFixed(2)}" fill="#0a0a0c"/><circle cx="40.1" cy="${(ey0-1.1).toFixed(1)}" r=".6" fill="#fff"/><ellipse cx="41" cy="${(top+1.2).toFixed(1)}" rx="6" ry="2" fill="#000" opacity=".2" filter="url(#bs${u})"/></g><ellipse cx="45.3" cy="47.3" rx=".65" ry=".5" fill="#e59b94" opacity=".85"/><path d="M35.9 47.9Q41 ${(top-.4).toFixed(1)} 46 47" stroke="${lid}" stroke-width="1.35" fill="none" stroke-linecap="round"/>${lash}<path d="M37 ${(top-1.6).toFixed(1)}Q41 ${(top-3.4).toFixed(1)} 45.4 ${(top-1.3).toFixed(1)}" stroke="${skd}" stroke-width=".6" fill="none" stroke-linecap="round" opacity=".6"/><path d="M37 48.5Q41 ${(bot+.7).toFixed(1)} 45 47.7" stroke="${skd}" stroke-width=".4" fill="none" opacity=".4"/>`);
  }else o+=avSym(avEye(eyk,41,ec));
  const bp=AV_BROW[G('br')];
  if(bp&&G('br')!==0)o+=avSym(`<path d="${bp}" stroke="${avMix(hc,'#fff',.25)}" stroke-width=".55" stroke-linecap="round" stroke-dasharray="1.2 .7" fill="none" transform="translate(0 -.7)" opacity=".6"/>`);
  if(bp)o+=avSym(`<path d="${bp}" stroke="${avMix(hc,'#000',.35)}" stroke-width="${G('br')===3?3.4:2}" stroke-linecap="round" fill="none"/>`);
  o+=hf;
  if(G('hs')>0){const st=[...Array(16)].map((_,k)=>{const a=-170+k*(160/15),x1=50+Math.cos(a*Math.PI/180)*8,y1=40+Math.sin(a*Math.PI/180)*8,x2=50+Math.cos(a*Math.PI/180)*40,y2=40+Math.sin(a*Math.PI/180)*44,cx=(x1+x2)/2+(k%2?4:-4);return `<path d="M${x1.toFixed(1)} ${y1.toFixed(1)}Q${cx.toFixed(1)} ${((y1+y2)/2).toFixed(1)} ${x2.toFixed(1)} ${y2.toFixed(1)}" stroke="${k%3?'#000':'#fff'}" stroke-opacity="${k%3?.16:.14}" stroke-width=".7" fill="none"/>`}).join('');o+=`<g clip-path="url(#hr${u})">${st}</g>`}
  if(G('hs')>0&&G('hs')!==5)o+=`<path d="M37 25Q50 14.5 63 25" stroke="#fff" stroke-opacity=".3" stroke-width="2.6" fill="none" stroke-linecap="round" filter="url(#bs${u})"/>`;
  /* óculos */
  const gl=G('gl'),fr=`stroke="${xc}" stroke-width="1.7" fill="none" stroke-linejoin="round"`;
  if(gl===1)o+=avSym(`<circle cx="41" cy="47" r="6.6" ${fr}/><circle cx="41" cy="47" r="6.6" fill="#fff" opacity=".16"/><path d="M34.5 46L31 45"  ${fr} stroke-linecap="round"/>`)+`<path d="M47.6 46.5Q50 44.8 52.4 46.5" ${fr}/>`;
  if(gl===2)o+=avSym(`<rect x="34.4" y="42" width="13.2" height="10.6" rx="2.6" ${fr}/><rect x="34.4" y="42" width="13.2" height="10.6" rx="2.6" fill="#fff" opacity=".16"/><path d="M34.4 45L31 44.5" ${fr} stroke-linecap="round"/>`)+`<path d="M47.6 45.5Q50 44 52.4 45.5" ${fr}/>`;
  if(gl===3)o+=avSym(`<path d="M34 43.5Q36 42 41 42.4Q47.5 43 47.8 48.2Q47 53 42 52.6Q35.5 52 34 43.5Z" ${fr}/><path d="M34 43.5Q36 42 41 42.4Q47.5 43 47.8 48.2Q47 53 42 52.6Q35.5 52 34 43.5Z" fill="#fff" opacity=".16"/><path d="M34 43.5L31 42" ${fr} stroke-linecap="round"/>`)+`<path d="M47.8 45Q50 43.8 52.2 45" ${fr}/>`;
  if(gl===4)o+=avSym(`<path d="M34 43H47.4Q48 51.5 43 52.4Q36 53 34 43Z" fill="#17171d" stroke="${xc}" stroke-width="1.3" stroke-linejoin="round"/><path d="M36 44.5L40 44.5" stroke="#fff" stroke-opacity=".45" stroke-width="1.2" stroke-linecap="round"/><path d="M34 44L31 43" stroke="${xc}" stroke-width="1.5" stroke-linecap="round"/>`)+`<path d="M47.4 44.5Q50 43.4 52.6 44.5" stroke="${xc}" stroke-width="1.5" fill="none"/>`;
  /* acessórios de cabeça */
  const hd=G('hd'),xd=avMix(xc,'#000',.22),xl=avMix(xc,'#fff',.3);
  if(hd===1)o+=`<path d="M31.4 38C33 17 67 17 68.6 38" stroke="${xc}" stroke-width="3.8" stroke-linecap="round" fill="none"/>`;
  if(hd===2)o+=`<path d="M62 21L51 14.5V27.5ZM62 21L73 14.5V27.5Z" fill="${xc}"/><circle cx="62" cy="21" r="3.2" fill="${xd}"/>`;
  if(hd===3)o+=`<g transform="translate(36 24)">${[0,72,144,216,288].map(a=>`<circle cx="0" cy="-4.3" r="3.3" fill="${xc}" transform="rotate(${a})"/>`).join('')}<circle r="2.5" fill="#FFD84D"/></g>`;
  if(hd===4)o+=`<path d="M30.5 37C30 16 70 16 69.5 37Z" fill="${xc}"/><path d="M50 16.8V36" stroke="${xd}" stroke-width=".8" opacity=".6"/><path d="M28 36.5Q50 31 72 36.5Q72.5 41 50 40.5Q27.5 41 28 36.5Z" fill="${xd}"/>`;
  if(hd===5)o+=`<path d="M30 38C29 13 71 13 70 38Z" fill="${xc}"/><path d="M29 32.5H71V40H29Z" fill="${xl}"/><path d="M33 33v7M39 33v7M45 33v7M51 33v7M57 33v7M63 33v7" stroke="${xc}" stroke-width="1.2" opacity=".55"/><circle cx="50" cy="12.5" r="4.6" fill="${xl}"/>`;
  if(hd===6)o+=`<path d="M30.5 47C27.5 12 72.5 12 69.5 47" stroke="#2a2a33" stroke-width="3" stroke-linecap="round" fill="none"/><rect x="26" y="42" width="6.4" height="13" rx="3" fill="${xc}"/><rect x="67.6" y="42" width="6.4" height="13" rx="3" fill="${xc}"/>`;
  return o+'</svg>';
}
function avRandom(cfg,seed){
  let s=seed==null?0:seed;const r=n=>seed==null?Math.floor(Math.random()*n):((s=(s*1664525+1013904223)%4294967296)>>>8)%n;
  const sx=cfg&&cfg.sx!=null?avG(cfg,'sx'):r(3),c={sx};
  Object.keys(AVN).forEach(k=>{if(k!=='sx')c[k]=r(AVN[k])});
  const pool={0:[1,4,5,6,7,8,9,10,11],1:[0,1,2,3,4,5],2:[1,2,3,4,5,6,7,8,9,10,11]}[sx];
  c.hs=pool[r(pool.length)];c.fh=sx===1&&r(10)<4?1+r(5):0;c.er=sx===0&&r(10)<5?1+r(3):(r(10)<1?1:0);
  c.lp=sx===0&&r(10)<4?1+r(5):0;c.gl=r(10)<3?1+r(4):0;c.hd=r(10)<3?1+r(6):0;c.fr=r(10)<2?1:0;c.bl=r(10)<3?1:0;c.mo=r(10)<1?1:0;c.hc=c.hc>8?r(8):c.hc;c.cs=sx===0?r(4):r(6);
  if(c.bg===9)c.bg=r(9);
  return c;
}

/* ===== editor de avatar (abre dentro do modal do aluno) ===== */
let avSel={cfg:null,use:false},avEd=null;   // avSel: avatar do aluno neste cadastro · avEd: rascunho do editor
const avLipCols=c=>{const sk=AVP.skin[avG(c,'sk')];return AVP.lip.map((x,i)=>x||avMix(avMix(sk,'#C0505A',.55),'#000',.08))};
const avSeed=n=>{let h=17;for(const ch of String(n||''))h=(h*131+ch.charCodeAt(0))%4294967296;return h};
const AVTABS=[['perfil','Perfil'],['cabelo','Cabelo'],['olhos','Olhos'],['rosto','Rosto'],['barba','Barba'],['acess','Acessórios'],['roupa','Roupa e fundo']];
const AVSEC={
  perfil:[{l:'Sexo (corpo)',k:'sx',t:'txt',n:['Feminino','Masculino','Neutro']},{l:'Tom de pele',k:'sk',t:'col',c:AVP.skin},{l:'Formato do rosto',k:'fc',t:'svg',n:['Oval','Redondo','Quadrado','Coração']}],
  cabelo:[{l:'Estilo do cabelo',k:'hs',t:'svg',n:['Sem cabelo','Curto','Topete','Lado','Cacheado','Black power','Longo liso','Ondulado','Rabo de cavalo','Coque','Tranças','Chanel']},{l:'Cor do cabelo',k:'hc',t:'col',c:AVP.hair}],
  olhos:[{l:'Olhos',k:'ey',t:'svg',vb:'34 29 32 32',n:['Pontinhos','Grandes','Sorrindo','Cílios','Fechados','Brilhantes','Amendoados']},{l:'Cor dos olhos',k:'ec',t:'col',c:AVP.eye},{l:'Sobrancelhas',k:'br',t:'svg',vb:'34 26 32 32',n:['Sem','Retas','Arqueadas','Grossas','Inclinadas','Preocupadas']}],
  rosto:[{l:'Nariz',k:'ns',t:'svg',vb:'38 42 24 24',n:['Pequeno','Redondo','Fino','Largo']},{l:'Boca',k:'mt',t:'svg',vb:'35 46 30 30',n:['Sorriso','Sorriso aberto','Neutra','Meio sorriso','Pequena','Beijinho','Lábios cheios']},{l:'Cor dos lábios',k:'lp',t:'col',lip:1,n:['Natural','Rosa','Vermelho','Vinho','Coral','Roxo']},{l:'Sardas',k:'fr',t:'txt',n:['Não','Sim']},{l:'Bochechas rosadas',k:'bl',t:'txt',n:['Não','Sim']},{l:'Pinta',k:'mo',t:'txt',n:['Não','Sim']}],
  barba:[{l:'Barba e bigode (usa a cor do cabelo)',k:'fh',t:'svg',vb:'24 32 52 52',n:['Nenhuma','Bigode','Cavanhaque','Barba curta','Barba cheia','Barba rala']}],
  acess:[{l:'Óculos',k:'gl',t:'svg',vb:'27 24 46 46',n:['Sem óculos','Redondo','Quadrado','Gatinho','De sol']},{l:'Na cabeça',k:'hd',t:'svg',vb:'19 0 62 62',n:['Nenhum','Faixa','Laço','Flor','Boné','Gorro','Fone de ouvido']},{l:'Brincos',k:'er',t:'svg',vb:'25 27 50 50',n:['Sem brincos','Bolinha','Argola','Gota']},{l:'Cor dos acessórios',k:'xc',t:'col',c:AVP.acc}],
  roupa:[{l:'Roupa',k:'cs',t:'svg',vb:'25 55 50 50',n:['Camiseta','Gola V','Regata','Moletom','Social','Gola alta']},{l:'Cor da roupa',k:'cc',t:'col',c:AVP.cloth},{l:'Cor de fundo',k:'bg',t:'col',c:AVP.bg}]
};
function avEdRender(pop){
  const e=$('#avEd');if(!e||!avEd)return;
  const ob=e.querySelector('.avE-body'),ot=e.querySelector('.avE-tabs'),sy=ob?ob.scrollTop:0,sx=ot?ot.scrollLeft:0;
  const c=avEd.cfg,tile=(sc,i,inner,cls,st,label)=>{const on=avG(c,sc.k)===i;return `<button type="button" class="avT${cls?' '+cls:''}${on?' on':''}" data-act="avPick" data-k="${sc.k}" data-v="${i}" aria-label="${esc(label)}" aria-pressed="${on}" title="${esc(label)}"${st?` style="${st}"`:''}>${inner}</button>`};
  const secs=AVSEC[avEd.tab].map(sc=>{
    const cols=sc.lip?avLipCols(c):sc.c,cur=avG(c,sc.k),nm=sc.n?sc.n[cur]:'';
    const items=sc.t==='col'?cols.map((x,i)=>tile(sc,i,'','col',`background:${x}`,sc.n?sc.n[i]:'Cor '+(i+1))):sc.n.map((n,i)=>sc.t==='txt'?tile(sc,i,esc(n),'txt','',n):tile(sc,i,avatarSvg({...c,[sc.k]:i},sc.vb),'','',n));
    return `<div class="avE-l">${esc(sc.l)}${nm?`<em>${esc(nm)}</em>`:''}</div><div class="avE-g">${items.join('')}</div>`}).join('');
  e.innerHTML=`<h2>Criar avatar</h2><div class="avE-top"><div id="avEPrev">${avHtml('',null,'xxl'+(pop?' pop':''),c)}</div><div class="avE-side"><button type="button" data-act="avRand">${ico('undo')}Sortear tudo</button><button type="button" data-act="avRandTab">${ico('sliders')}Sortear esta aba</button><button type="button" data-act="avUndo"${avEd.hist&&avEd.hist.length?'':' disabled'}>${ico('chev-l')}Desfazer</button></div></div>
  <div class="avE-tabs" role="tablist">${AVTABS.map(([k,l])=>`<button type="button" role="tab" aria-selected="${k===avEd.tab}" class="${k===avEd.tab?'on':''}" data-act="avTab" data-t="${k}">${l}</button>`).join('')}</div>
  <div class="avE-body">${secs}</div>
  <div class="foot"><button type="button" class="btn" data-act="avCancel">Voltar</button><button type="button" class="btn primary" data-act="avUse">Usar este avatar</button></div>`;
  const nb=e.querySelector('.avE-body'),nt=e.querySelector('.avE-tabs');
  if(nb&&!avEd.fresh)nb.scrollTop=sy;if(nt){nt.scrollLeft=sx;nt.querySelector('.on')?.scrollIntoView({block:'nearest',inline:'nearest'})}
  avEd.fresh=false;
}
const avPush=()=>{(avEd.hist=avEd.hist||[]).push({...avEd.cfg});if(avEd.hist.length>40)avEd.hist.shift()};
function avShow(on){[...$('#sheet').children].forEach(c=>{c.hidden=on?c.id!=='avEd':c.id==='avEd'});if(on)avEdRender();else avEd=null}
Object.assign(ACT,{
  avOpen:()=>{avEd={cfg:avSel.cfg?{...avSel.cfg}:avRandom({},avSeed($('#fName')?.value.trim())),tab:'perfil',hist:[],fresh:true};avShow(true)},
  avTab:e=>{if(avEd){avEd.tab=e.dataset.t;avEd.fresh=true;avEdRender()}},
  avPick:e=>{if(!avEd)return;const k=e.dataset.k,v=Number(e.dataset.v);if(avG(avEd.cfg,k)===v)return;avPush();avEd.cfg[k]=v;avEdRender(true)},
  avRand:()=>{if(avEd){avPush();avEd.cfg=avRandom({sx:avEd.cfg.sx});avEdRender(true)}},
  avRandTab:()=>{if(!avEd)return;avPush();const r=avRandom({sx:avEd.cfg.sx});AVSEC[avEd.tab].forEach(x=>{avEd.cfg[x.k]=r[x.k]});avEdRender(true)},
  avUndo:()=>{if(avEd&&avEd.hist&&avEd.hist.length){avEd.cfg=avEd.hist.pop();avEdRender(true)}},
  avCancel:()=>avShow(false),
  avUse:()=>{if(!avEd)return;avSel={cfg:{...avEd.cfg},use:true};avShow(false);phPreview();phMsg('Avatar pronto. Toque em Salvar para guardar.')}
});

const waNum=n=>{const d=String(n||'').replace(/\D/g,'');return d?(d.length<=11?'55'+d:d):''};
/* edição da foto dentro do modal do aluno */
let phDraft,phTok=0;  // phDraft: undefined = sem mudança · null = remover · texto = nova foto
function phPreview(){
  const el=$('#fPhotoPrev');if(!el)return;
  const cur=phDraft===undefined?(editing?photoOf(editing):''):(phDraft||''),cfg=avSel.use&&avSel.cfg?avSel.cfg:null;
  el.innerHTML=avHtml($('#fName')?.value.trim()||'?',cur,'xl',cfg);$('#fPhotoDel').hidden=!(cur||cfg);
}
const phMsg=t=>{const m=$('#fPhotoMsg');if(m)m.textContent=t};
document.addEventListener('input',e=>{if(e.target.id==='fName')phPreview()});
Object.assign(ACT,{
  phDel:()=>{if(avSel.use&&avSel.cfg){avSel={cfg:null,use:false};phPreview();phMsg('Avatar removido. Toque em Salvar para confirmar.')}else{phDraft=null;phPreview();phMsg('A foto será removida ao salvar; voltam as iniciais.')}},
});
const ageOf=b=>{if(!b)return '';const d=new Date(b+'T12:00'),n=new Date();let a=n.getFullYear()-d.getFullYear();if(n<new Date(n.getFullYear(),d.getMonth(),d.getDate()))a--;return a>=0?a:''};
function idxBy(){const c={},f={};db.classes.forEach(x=>(c[x.studentId]=c[x.studentId]||[]).push(x));db.finance.forEach(x=>{if(!isExp(x))(f[x.studentId]=f[x.studentId]||[]).push(x)});return{c,f}}
const daysLate=f=>Math.max(0,Math.floor((Date.now()-new Date(f.dueDate+'T12:00'))/864e5));
function finState(rows){
  if(!rows.length)return{k:'none',label:'Sem lançamento',cls:''};
  if(rows.some(lateOf))return{k:'late',label:'Vencido',cls:'bad'};
  if(rows.some(f=>f.status!=='Pago'))return{k:'open',label:'A vencer',cls:'ok'};
  return{k:'paid',label:'Pago',cls:'ok'};
}
function sCard(s,ix){
  const t=iso(new Date()),from=iso(new Date(Date.now()-90*864e5)),cl=ix.c[s.id]||[],fin=(ix.f[s.id]||[]).sort((a,b)=>String(b.dueDate).localeCompare(String(a.dueDate)));
  const rec=cl.filter(c=>c.date>=from&&c.date<=t),done=rec.filter(c=>c.status==='Realizada').length,miss=rec.filter(c=>c.status==='Falta').length,base=done+miss;
  const next=cl.filter(c=>c.date>=t&&!['Cancelada','Realizada','Falta'].includes(c.status)).sort(sortCls)[0],eq=next&&db.equipment.find(e=>e.id===next.equipmentId)?.name;
  const pend=fin.filter(f=>f.status!=='Pago'),fs=finState(pend.length?pend:fin.slice(0,1)),owed=pend.reduce((a,f)=>a+Number(f.value||0),0);
  const ev=evoSorted(s)[0],c=s.clinical||{},wa=waLink(s.whatsapp,''),age=ageOf(s.birth);
  const active=(s.status||'Ativo')==='Ativo';
  const days=normDays(s.days).map(d=>DAY[d]).join(', ');
  const sd=normDays(s.days),tdw=String(new Date().getDay()),
    wk=`<div class="wk" role="img" aria-label="Dias de aula: ${esc(days||'nenhum')}">${ORDER.map(d=>`<span class="${sd.includes(d)?'on':''}${d===tdw?' today':''}">${DAY[d]}</span>`).join('')}</div>`,
    cell=(l,v,sub,neg)=>`<div class="stc${neg?' neg':''}"><small>${l}</small><b>${v}</b>${sub?`<em>${sub}</em>`:''}</div>`,
    nd=next?DAY[new Date(next.date+'T12:00').getDay()]:'',
    meta=wk+`<div class="stg">`+[
      cell('Próxima aula',next?esc(fmtDate(next.date).slice(0,5)+' · '+next.time):'—',next?esc(nd+(eq?' · '+eq:'')):'Sem aula agendada'),
      cell('Freq. 90 dias',base?Math.round(done/base*100)+'%':'—',base?`${done} aula${done===1?'':'s'} · ${miss} falta${miss===1?'':'s'}`:'Sem registros',base&&done/base<.6),
      cell('Professor(a)',esc(s.teacher||'—'),age!==''?age+' anos':''),
      owed?cell('Em aberto',money(owed),[s.due&&'dia '+esc(s.due),fs.label].filter(Boolean).join(' · '),true):cell('Mensalidade',money(s.monthly),[s.due&&'vence dia '+esc(s.due),fs.label].filter(Boolean).join(' · '))
    ].join('')+`</div>`;
  return scard({sid:s.id,meta:meta,key:'st:'+s.id,dim:!active,name:s.name,badge:s.status||'Ativo',cls:active?'ok':'',sub:`${esc(s.plan||'Sem plano')}${s.time?' · '+esc(s.time):''}`,val:'',
    det:(()=>{const chips=(t,w)=>{const a=String(t||'').split(/;\s*/).map(x=>x.trim()).filter(Boolean);return a.length?`<span class="chps">${a.map(x=>`<i class="chp${w?' w':''}">${esc(x)}</i>`).join('')}</span>`:'—'},mob=(MOBS.find(m=>m[0]===String(s.mobility))||[0,'—'])[1].split(' (')[0],cond=(s.conditions||[]).map(k=>CL[k]).join('; ');
      return [['#','Contato e plano'],['WhatsApp',esc(s.whatsapp||'—')],['Vencimento',s.due?'dia '+esc(s.due):'—'],['Nascimento',s.birth?fmtDate(s.birth)+(age!==''?' · '+age+' anos':''):'—'],['Início',s.startDate?fmtDate(s.startDate):'—'],
      ['#','Perfil clínico'],['Objetivo',chips(s.goal||c.objective),'s'],['Queixa',esc(s.complaint||c.complaint||'—'),'s'],['Mobilidade',esc(mob)],['Condições',chips(cond,1),'s'],...(s.notes?[['Observações',esc(s.notes),'s']]:[]),
      ['#','Acompanhamento'],['Aulas (90 dias)',`${done} realizadas · <span class="${miss?'neg':''}">${miss} faltas</span>`],['Último registro',ev?fmtDate(ev.date)+(ev.painAfter!==''&&ev.painAfter!=null?' · dor '+esc(ev.painAfter)+'/10':''):'—'],['Reavaliação',c.nextReview?fmtDate(c.nextReview):'—'],
      ...(DOCN[s.id]?[['Documentos',DOCN[s.id]+' anexo'+(DOCN[s.id]>1?'s':'')]]:[]),
      ...(fin.length?[['#','Financeiro'],...fin.slice(0,3).map(f=>[`${fmtDate(f.dueDate)} · ${esc(f.description||'')}`,`${money(f.value)} ${stBadge(f)}`])]:[])]})(),
    acts:(wa?`<button class="btn sm wa" data-act="waMsg" data-k="general" data-sid="${s.id}">WhatsApp</button>`:'')+`<button class="btn sm" data-act="evoOf" data-id="${s.id}">Evolução</button><button class="btn sm" data-act="docOpen" data-id="${s.id}">Documentos${DOCN[s.id]?' ('+DOCN[s.id]+')':''}</button><button class="btn sm" data-act="gStu" data-id="${s.id}">Sugestões</button><button class="btn sm" data-act="eqHist" data-id="${s.id}">Rodízio</button>${active&&s.time&&sd.length?`<button class="btn sm" data-act="occOf" data-id="${s.id}">Ocupação</button>`:''}<button class="btn sm" data-act="stuPdf" data-id="${s.id}">Ficha PDF</button><button class="btn sm" data-act="editStudent" data-id="${s.id}">Editar</button><button class="btn sm bad" data-act="delStudent" data-id="${s.id}">Excluir</button>`});
}


/* ========== CARD ÚNICO DE ALUNO (usado em todas as abas) ========== */
const splitActs=h=>{h=String(h||'');const m=[...h.matchAll(/<(button|a)\b[^>]*>[\s\S]*?<\/\1>/g)].map(x=>x[0]),p=m.find(x=>!/class="[^"]*\bbad\b/.test(x.slice(0,x.indexOf('>'))));return p?[p,h.replace(p,'')]:['',h]};
const scard=o=>{
  const [prim,rest]=o.prim!==undefined?[o.prim,o.acts||'']:splitActs(o.acts);
  const val=o.val!==undefined?o.val:(o.mini&&o.mini[0]?o.mini[0][1]:'');
  const inner=(o.head||'')+(o.mini?`<div class="mini">${o.mini.map(([l,v])=>`<div><small>${l}</small><b>${v}</b></div>`).join('')}</div>`:'')+(o.det?o.det.map(([l,v,k])=>l==='#'?`<div class="dsec">${v}</div>`:`<div class="item${k==='s'?' stk':''}"><span>${l}</span><b>${v}</b></div>`).join(''):'')+(rest.trim()?`<div class="row-acts">${rest}</div>`:'');
  const exp=!!(inner&&o.key);
  return `<div class="card sc${o.tone?' tone-'+o.tone:''}"${o.dim?' style="opacity:.8"':''}><div class="sc-h"><div class="sc-main"${exp?` data-act="cardToggle" role="button" tabindex="0" aria-expanded="${!!detOpen[o.key]}"`:''}>${scAv(o)}<div class="sc-t"><b>${esc(o.name)}</b><div class="sub">${o.badge?`<span class="badge ${o.cls||''}">${esc(o.badge)}</span>`:''}<span>${o.sub||''}</span></div></div>${val?`<div class="sc-v">${val}</div>`:''}</div>${prim?`<span class="sc-p">${prim}</span>`:''}${exp?'<button class="sc-c" data-act="cardToggle" aria-label="Mostrar mais ou menos" tabindex="-1">▾</button>':''}</div>${o.meta?`<div class="sc-m">${o.meta}</div>`:''}${exp?detail(o.key,inner):''}</div>`};
const rowStu=(name,sub,right)=>`<div class="item"><div style="display:flex;gap:10px;align-items:center;min-width:0">${stuAv(null,name,'sm')}<div style="min-width:0"><b>${esc(name)}</b><div class="sub">${sub}</div></div></div>${right||''}</div>`;
const stuLine=s=>[['Plano',esc(s?.plan||'—')],['Professor(a)',esc(s?.teacher||'—')],['WhatsApp',esc(s?.whatsapp||'—')]];
/* ========== DOCUMENTOS DO ALUNO (PDF/imagem) — guardados em IndexedDB neste aparelho ========== */
const DOCN={};
const DOCDB=(()=>{let pr;const open=()=>pr||(pr=new Promise((ok,no)=>{try{const r=indexedDB.open('sp_docs',1);r.onupgradeneeded=()=>{r.result.createObjectStore('docs',{keyPath:'id'}).createIndex('sid','sid')};r.onsuccess=()=>ok(r.result);r.onerror=()=>no(r.error)}catch(e){no(e)}}));
 const tx=(m,f)=>open().then(d=>new Promise((ok,no)=>{const t=d.transaction('docs',m);let q;try{q=f(t.objectStore('docs'))}catch(e){return no(e)}t.oncomplete=()=>ok(q&&q.result);t.onerror=t.onabort=()=>no(t.error)}));
 return{put:r=>tx('readwrite',o=>o.put(r)),del:id=>tx('readwrite',o=>o.delete(id)),byStu:sid=>tx('readonly',o=>o.index('sid').getAll(sid)),exAll:()=>tx('readonly',o=>o.index('sid').getAll(IDBKeyRange.bound('ex:','ex:\uffff'))),delStu:sid=>tx('readwrite',o=>o.index('sid').openKeyCursor(IDBKeyRange.only(sid))).then(()=>open()).then(d=>new Promise(ok=>{const t=d.transaction('docs','readwrite'),o=t.objectStore('docs'),q=o.index('sid').openKeyCursor(IDBKeyRange.only(sid));q.onsuccess=()=>{const c=q.result;if(c){o.delete(c.primaryKey);c.continue()}};t.oncomplete=ok;t.onerror=ok})),
  counts:()=>open().then(d=>new Promise(ok=>{const n={},q=d.transaction('docs').objectStore('docs').index('sid').openKeyCursor();q.onsuccess=()=>{const c=q.result;if(c){n[c.key]=(n[c.key]||0)+1;c.continue()}else ok(n)};q.onerror=()=>ok(n)}))}})();
let docSid=null,docUrls=[];
const docSize=b=>b>=1048576?(b/1048576).toFixed(1)+' MB':Math.max(1,Math.round(b/1024))+' KB';
async function docRender(){const box=$('#docList');if(!box)return;docUrls.forEach(u=>URL.revokeObjectURL(u));docUrls=[];let l;
 try{l=await DOCDB.byStu(docSid)}catch{box.innerHTML='<div class="sub">Anexos indisponíveis neste navegador (modo privado?).</div>';return}
 l.sort((a,b)=>b.date.localeCompare(a.date));DOCN[docSid]=l.length;if(!l.length)delete DOCN[docSid];
 box.innerHTML=l.length?l.map(d=>{const u=URL.createObjectURL(d.blob);docUrls.push(u);return `<div class="item docit"><div class="doct">${d.type.startsWith('image/')?`<img src="${u}" alt="">`:'PDF'}</div><div class="docm"><b>${esc(d.name)}</b><div class="sub">${docSize(d.size)} · ${fmtDate(d.date.slice(0,10))}</div></div><div class="row-acts"><a class="btn sm" href="${u}" target="_blank" rel="noopener">Abrir</a><a class="btn sm" href="${u}" download="${esc(d.name)}">Baixar</a><button type="button" class="btn sm bad" data-act="docDel" data-id="${d.id}">Excluir</button></div></div>`}).join(''):'<div class="sub">Nenhum documento anexado.</div>'}
async function docAdd(ev){const fs=[...ev.target.files];ev.target.value='';let n=0;
 for(const f of fs){if(!(f.type==='application/pdf'||f.type.startsWith('image/')||/\.(pdf|jpe?g|png|webp|heic)$/i.test(f.name))){toast('Formato não aceito: '+f.name);continue}
  if(f.size>15*1048576){toast(f.name+' passa de 15 MB.');continue}
  try{await DOCDB.put({id:'d'+Date.now().toString(36)+Math.random().toString(36).slice(2,6),sid:docSid,name:f.name,type:f.type||(/pdf$/i.test(f.name)?'application/pdf':'image/jpeg'),size:f.size,date:new Date().toISOString(),blob:f});n++}catch{toast('Não foi possível salvar '+f.name+'.')}}
 if(n)toast(n+(n>1?' anexos salvos.':' anexo salvo.'));await docRender();render()}
Object.assign(ACT,{
 docOpen:e=>{docSid=e.dataset.id;const st=studentById(docSid);if(!st)return;
  openModal(`<h2>Documentos · ${esc(st.name)}</h2><label class="docdrop" for="docF"><b>+ Anexar PDF ou imagem</b><span class="sub">Laudos, exames, termos, receitas · até 15 MB por arquivo</span></label><input type="file" id="docF" hidden multiple accept="application/pdf,image/*"><div id="docList" class="docl"></div><div class="sub">Os arquivos ficam guardados somente neste aparelho e não entram na cópia de segurança.</div><div class="foot"><button type="button" class="btn" data-act="closeModal">Fechar</button></div>`);
  $('#docF').onchange=docAdd;docRender()},
 docDel:async e=>{if(!confirm('Excluir este documento?'))return;try{await DOCDB.del(e.dataset.id)}catch{return toast('Não foi possível excluir.')}await docRender();render()}});
DOCDB.counts().then(n=>{if(Object.keys(n).length){Object.assign(DOCN,n);try{render()}catch{}}}).catch(()=>{});
const EXPH_KEY='studio_pilates_louise_karla_exphotos_v1',EXPH_OK=/^data:image\/(?:jpeg|png|webp|gif|svg\+xml);base64,[A-Za-z0-9+/=]+$/;
let EXPH={};try{const p=JSON.parse(localStorage.getItem(EXPH_KEY));if(p&&typeof p==='object'&&!Array.isArray(p))EXPH=p}catch{}
const exphSave=()=>{try{localStorage.setItem(EXPH_KEY,JSON.stringify(EXPH));return true}catch{return false}};
const gxPhLoad=()=>{Object.entries(EXPH).forEach(([k,v])=>{if(typeof v==='string'&&EXPH_OK.test(v))GXPH[k]={id:k,u:v}})};
gxPhLoad();
const gxRead=f=>new Promise((ok,no)=>{const r=new FileReader();r.onload=()=>ok(r.result);r.onerror=()=>no(r.error);r.readAsDataURL(f)});
const gxShrink=(f,max,q)=>new Promise((ok,no)=>{const u=URL.createObjectURL(f),i=new Image();
 i.onload=()=>{try{const w=i.naturalWidth,h=i.naturalHeight,k=Math.min(1,max/Math.max(w,h)),c=document.createElement('canvas');c.width=Math.max(1,Math.round(w*k));c.height=Math.max(1,Math.round(h*k));const x=c.getContext('2d');x.fillStyle='#fff';x.fillRect(0,0,c.width,c.height);x.drawImage(i,0,0,c.width,c.height);URL.revokeObjectURL(u);ok(c.toDataURL('image/jpeg',q))}catch(er){no(er)}};
 i.onerror=()=>{URL.revokeObjectURL(u);no(new Error('img'))};i.src=u});
async function gxPhSave(id,f){
 const nm=f.name||'foto',gif=/gif/.test(f.type)||/\.gif$/i.test(nm),ok=/^image\//.test(f.type)||!f.type||/\.(png|apng|jpe?g|jfif|gif|webp|bmp|heic|heif|avif|svg|tiff?|ico)$/i.test(nm),svg=/svg/.test(f.type)||/\.svg$/i.test(nm);
 if(!ok)return toast('Escolha um arquivo de imagem ou GIF.');
 if(f.size>30*1048576)return toast('O arquivo passa de 30 MB.');
 let url,note='';
 try{
  if(gif&&f.size<=1.5*1048576){url=await gxRead(f);url=url.replace(/^data:[^;,]*/,'data:image/gif')}
  else if(svg&&f.size<=1.5*1048576){url=await gxRead(f);url=url.replace(/^data:[^;,]*/,'data:image/svg+xml')}
  else if(gif){
   const nid='x'+Date.now().toString(36)+Math.random().toString(36).slice(2,6),b=f.type==='image/gif'?f:new Blob([f],{type:'image/gif'});
   try{await DOCDB.put({id:nid,sid:'ex:'+id,name:nm,type:'image/gif',size:f.size,date:new Date().toISOString(),blob:b});
    const o=GXPH[id];if(o&&o.idb){try{DOCDB.del(o.id).catch(()=>{})}catch{}}
    if(EXPH[id]){delete EXPH[id];exphSave()}
    GXPH[id]={id:nid,u:URL.createObjectURL(b),idb:true};try{render()}catch{}try{gxAfter(id)}catch{}return toast('GIF salvo neste aparelho.')}
   catch{url=await gxShrink(f,1000,.82);note=' Este aparelho não guarda GIFs grandes animados; foi salvo como imagem estática.'}}
  else{url=await gxShrink(f,1000,.82)}
 }catch{return toast('Este aparelho não consegue abrir esse formato (comum em HEIC/AVIF fora do Safari). Tente JPG, PNG, WebP ou GIF.')}
 const old=GXPH[id],prev=EXPH[id];EXPH[id]=url;let saved=exphSave();
 if(!saved&&!gif){try{EXPH[id]=url=await gxShrink(f,640,.7);saved=exphSave()}catch{}}
 if(!saved){if(prev)EXPH[id]=prev;else delete EXPH[id]}
 if(old&&old.idb){try{DOCDB.del(old.id).catch(()=>{})}catch{}}
 GXPH[id]={id,u:url,tmp:!saved};
 try{render()}catch{}try{gxAfter(id)}catch{}
 toast(saved?'Foto salva neste aparelho.'+note:'Sem espaço no aparelho: a foto fica só até fechar o app. Libere espaço ou exporte um backup.');
}
Object.assign(ACT,{
 gxPhoto:e=>{const id=e.dataset.id;let i=document.getElementById('gxPhIn');
  if(!i){i=document.createElement('input');i.type='file';i.id='gxPhIn';i.accept='image/*,.gif,.heic,.heif';i.hidden=true;document.body.appendChild(i);
   i.addEventListener('change',()=>{const f=i.files&&i.files[0],tid=i.dataset.id;if(f&&tid)gxPhSave(tid,f);setTimeout(()=>{i.value=''},0)})}
  i.dataset.id=id;i.value='';i.click()},
 gxPhotoDel:e=>{const id=e.dataset.id,o=GXPH[id];if(!o||!confirm('Remover a foto deste exercício?'))return;
  delete EXPH[id];exphSave();if(o.idb){try{DOCDB.del(o.id).catch(()=>{})}catch{}}
  try{if(String(o.u).startsWith('blob:'))URL.revokeObjectURL(o.u)}catch{}delete GXPH[id];try{render()}catch{}try{gxAfter(id)}catch{}}});
if(Object.keys(GXPH).length)setTimeout(()=>{try{render()}catch{}},0);
DOCDB.exAll().then(l=>{let n=0;l.forEach(d=>{const k=d.sid.slice(3);if(!GXPH[k]){GXPH[k]={id:d.id,u:URL.createObjectURL(d.blob),idb:true};n++}});if(n)try{render()}catch{}}).catch(()=>{});

let finView='entries',fsFilter='all';
const fsSorter=()=>{const v=$('#fsSort').value,rk=['late','open','none','paid'],owed=x=>x.m.filter(f=>f.status!=='Pago').reduce((t,f)=>t+Number(f.value||0),0),nm=(a,b)=>a.s.name.localeCompare(b.s.name,'pt-BR');
  return (a,b)=>v==='name'?nm(a,b):v==='pending'?owed(b)-owed(a)||nm(a,b):rk.indexOf(a.st.k)-rk.indexOf(b.st.k)||nm(a,b)};
function rFinStudents(){
  const key=ym(finMonth),q=($('#fsSearch').value||'').trim().toLowerCase(),ix=idxBy(),
    mrows=id=>(ix.f[id]||[]).filter(f=>String(f.dueDate).startsWith(key));
  const cnt={late:0,open:0,none:0,paid:0};
  const list=db.students.filter(s=>((s.status||'Ativo')==='Ativo'||mrows(s.id).length)&&(!q||s.name.toLowerCase().includes(q))).map(s=>({s,m:mrows(s.id)})).map(x=>({...x,st:finState(x.m)}))
    .filter(x=>{cnt[x.st.k]++;return fsFilter==='all'||(fsFilter==='open'&&(x.st.k==='open'||x.st.k==='late'))||x.st.k===fsFilter})
    .sort(fsSorter());
  pillCounts('#fsFilter',{all:cnt.late+cnt.open+cnt.none+cnt.paid,open:cnt.open+cnt.late,late:cnt.late,paid:cnt.paid,none:cnt.none});
  $('#fsList').innerHTML=list.length?list.map(({s,m,st})=>{
    const all=(ix.f[s.id]||[]).sort((a,b)=>String(b.dueDate).localeCompare(String(a.dueDate))),sum=a=>a.reduce((t,f)=>t+Number(f.value||0),0);
    const paid=m.filter(f=>f.status==='Pago'),pend=m.filter(f=>f.status!=='Pago').sort((a,b)=>String(a.dueDate).localeCompare(String(b.dueDate)));
    const openAll=all.filter(f=>f.status!=='Pago'),maxLate=Math.max(0,...openAll.filter(lateOf).map(daysLate)),lastPaid=all.find(f=>f.status==='Pago'),method=lastPaid?.paymentMethod||'—';
    const first=pend[0],w=first&&waLink(s.whatsapp,'');
    const acts=(first?`<button class="btn sm" data-act="payFin" data-id="${first.id}">Marcar pago</button>`:'')+(m.length?`<button class="btn sm" data-act="editFin" data-id="${(first||[...m].sort((a,b)=>String(b.dueDate).localeCompare(String(a.dueDate)))[0]).id}">Editar lançamento</button>`:'')+(w?`<button class="btn sm wa" data-act="waMsg" data-k="bill" data-sid="${s.id}" data-fid="${first.id}">Cobrar</button>`:'')+(st.k==='none'?`<button class="btn sm" data-act="fsGen" data-id="${s.id}">Gerar mensalidade</button>`:'')+`<button class="btn sm" data-act="fsNew" data-id="${s.id}">+ Lançamento</button><button class="btn sm" data-act="editStudent" data-id="${s.id}">Editar aluno</button>`;
    return scard({sid:s.id,key:'fs:'+s.id,...(first?{}:{prim:''}),tone:st.k==='late'?'bad':st.k==='none'?'':'ok',name:s.name,badge:st.label,cls:st.cls,sub:`${esc(s.plan||'Sem plano')} · ${money(s.monthly)}${s.due?' · dia '+esc(s.due):''}`,val:`<span class="${st.k==='late'?'neg':''}">${money(sum(pend)||sum(m))}</span>`,
      mini:[['DO MÊS',money(sum(m))],['PAGO',`<span class="pos">${money(sum(paid))}</span>`],['PENDENTE',`<span class="${st.k==='late'?'neg':''}">${money(sum(pend))}</span>`]],
      det:[['Total em aberto (geral)',`<span class="${openAll.length?'neg':''}">${money(sum(openAll))}</span>`],['Maior atraso',maxLate?maxLate+' dia(s)':'—'],['Último pagamento',lastPaid?fmtDate(lastPaid.paidAt||lastPaid.dueDate):'—'],['Forma de pagamento',esc(method)],
        ...all.slice(0,6).map(f=>[`${fmtDate(f.dueDate)} · ${esc(f.description||'')}`,`${money(f.value)} ${stBadge(f)}${f.status!=='Pago'?` <button class="btn sm" data-act="payFin" data-id="${f.id}">Pagar</button>`:''} <button class="btn sm" data-act="editFin" data-id="${f.id}">Editar</button>`])],acts})}).join('')
    :'<div class="card empty">Nenhum aluno neste filtro.</div>';
}
Object.assign(ACT,{
  fsNew:e=>{const s=studentById(e.dataset.id);finModal(null,{type:'Receita',studentId:s.id,description:`Mensalidade — ${s.plan||'Pilates'}`,value:s.monthly||'',dueDate:`${ym(finMonth)}-${pad(Math.min(Number(s.due)||10,new Date(finMonth.getFullYear(),finMonth.getMonth()+1,0).getDate()))}`,status:'Pendente'})},
  fsGen:e=>{const s=studentById(e.dataset.id),k=ym(finMonth),n=new Date(finMonth.getFullYear(),finMonth.getMonth()+1,0).getDate();if(!s||!(Number(s.monthly)>0))return toast('Defina o plano do aluno para gerar a mensalidade.');
    db.finance.push({id:uid('fin'),type:'Receita',studentId:s.id,studentName:s.name,description:`Mensalidade — ${s.plan||'Pilates'}`,value:Number(s.monthly),dueDate:`${k}-${pad(Math.min(Number(s.due)||10,n))}`,status:'Pendente',paymentMethod:'',notes:''});save();render();toast('Mensalidade gerada.')}
});
Object.assign(ACT,{
  cardToggle:e=>{const d=e.closest('.sc')?.querySelector('details');if(d)d.open=!d.open},
  expandAll:e=>{const ds=$$(e.dataset.s+' details'),open=ds.some(d=>!d.open);ds.forEach(d=>{d.open=open});e.textContent=open?'Recolher':'Expandir'},
  unpayFin:e=>{const f=db.finance.find(x=>x.id===e.dataset.id);if(f){f.status='Pendente';delete f.paidAt;save();render();toast('Pagamento desfeito.')}},
  evoClin:e=>{evoStu=e.dataset.id;render();clinModal()},
  alEdit:e=>e.dataset.k==='fin'?finModal(e.dataset.id):studentModal(e.dataset.id)
});
$('#feSearch').addEventListener('input',rMoney);$('#feSort').addEventListener('change',rMoney);$('#fsSort').addEventListener('change',rFinStudents);
$('#finView').addEventListener('click',e=>{const b=e.target.closest('button');if(b){finView=b.dataset.v;render()}});
$('#fsFilter').addEventListener('click',e=>{const b=e.target.closest('button');if(!b)return;fsFilter=b.dataset.f;$$('button',$('#fsFilter')).forEach(x=>x.classList.toggle('on',x===b));rFinStudents()});
$('#fsSearch').addEventListener('input',rFinStudents);


/* ========== PAGAMENTO COM DATA E FORMA ========== */
function payModal(id){
  const f=db.finance.find(x=>x.id===id);if(!f)return;editing=id;
  const methods=db.payments||['PIX','Cartão de Crédito','Dinheiro','Transferência'];
  const last=db.finance.filter(x=>x.studentId&&x.studentId===f.studentId&&x.paymentMethod).sort((a,b)=>String(b.paidAt||b.dueDate).localeCompare(String(a.paidAt||a.dueDate)))[0];
  openModal(`<h2>Registrar pagamento</h2><div class="sub" style="margin-bottom:12px">${esc(f.studentName||f.description)} · ${money(f.value)} · vence ${fmtDate(f.dueDate)}</div>
    <div class="form"><div class="field"><label for="payDate">Data do pagamento</label><input id="payDate" type="date" value="${iso(new Date())}"></div>
    <div class="field"><label for="payMethod">Forma de pagamento</label><select id="payMethod">${opts(methods,f.paymentMethod||last?.paymentMethod||methods[0])}</select></div></div>
    <div class="foot"><button class="btn" data-act="closeModal">Cancelar</button><button class="btn primary" data-act="confirmPay">Confirmar pagamento</button></div>`);
}
function confirmPay(){
  const f=db.finance.find(x=>x.id===editing),d=$('#payDate').value;if(!f)return;
  if(!d)return toast('Informe a data do pagamento.');
  f.status='Pago';f.paidAt=d;f.paymentMethod=$('#payMethod').value;
  if(!save())return;closeModal();render();toast('Pagamento registrado.');
}


/* ========== GASTOS (despesas detalhadas) ========== */
const EXP_CATS=[['Aluguel','🏠'],['Contas (água/luz/internet)','💡'],['Salários e repasses','👩‍🏫'],['Materiais','🧴'],['Manutenção','🛠'],['Marketing','📣'],['Impostos e taxas','🧾'],['Equipamentos','🏋'],['Outros','📦']];
const catIcon=c=>(EXP_CATS.find(x=>x[0]===c)||EXP_CATS[EXP_CATS.length-1])[1];
const guessCat=d=>{d=String(d||'').toLowerCase();return /alug/.test(d)?EXP_CATS[0][0]:/(luz|energia|[aá]gua|internet|telefone|condom)/.test(d)?EXP_CATS[1][0]:/(sal[aá]rio|repasse|professor|funcion)/.test(d)?EXP_CATS[2][0]:/(material|limpeza|higiene|toalha)/.test(d)?EXP_CATS[3][0]:/(manuten|conserto|reparo)/.test(d)?EXP_CATS[4][0]:/(an[uú]ncio|marketing|instagram|divulg)/.test(d)?EXP_CATS[5][0]:/(imposto|taxa|\bmei\b|\bdas\b|contador)/.test(d)?EXP_CATS[6][0]:/(aparelho|equipamento|reformer|colchonete|bola)/.test(d)?EXP_CATS[7][0]:'Outros'};
const catOf=f=>f.category||guessCat(f.description);
let gStatus='all',gCatF='';
const addMonths=(ds,n)=>{const [y,m,d]=ds.split('-').map(Number),last=new Date(y,m-1+n+1,0).getDate();return iso(new Date(y,m-1+n,Math.min(d,last)))};
const gRows=k=>db.finance.filter(f=>isExp(f)&&String(f.dueDate).startsWith(k));
const gSum=a=>a.reduce((t,f)=>t+Number(f.value||0),0);
function rExpenses(){
  const key=ym(finMonth),pk=ym(new Date(finMonth.getFullYear(),finMonth.getMonth()-1,1)),all=gRows(key),q=($('#gSearch').value||'').trim().toLowerCase();
  const paid=all.filter(f=>f.status==='Pago'),late=all.filter(lateOf),open=all.filter(f=>f.status!=='Pago'&&!lateOf(f)),tot=gSum(all),prev=gSum(gRows(pk));
  const rev=gSum(db.finance.filter(f=>!isExp(f)&&f.status==='Pago'&&String(f.dueDate).startsWith(key)));
  const tr=[5,4,3,2,1,0].map(i=>{const d=new Date(finMonth.getFullYear(),finMonth.getMonth()-i,1);return{l:d.toLocaleDateString('pt-BR',{month:'short'}).replace('.',''),v:gSum(gRows(ym(d))),cur:i===0}}),avg=tr.reduce((t,x)=>t+x.v,0)/6,tmax=Math.max(1,...tr.map(x=>x.v));
  const delta=prev?(tot-prev)/prev*100:null,k=(l,v,f,c='')=>`<div><small>${l}</small><b class="${c}">${v}</b><div class="kf">${f}</div></div>`;
  $('#gKpis').innerHTML=k('TOTAL DO MÊS',money(tot),delta===null?`${all.length} gasto(s)`:Math.abs(delta)<.05?'igual ao mês anterior':`${delta>0?'▲':'▼'} ${dec(Math.abs(delta))}% vs mês anterior`)+k('PAGO',money(gSum(paid)),`${paid.length} gasto(s)`,'pos')+k('A PAGAR',money(gSum(open)),`${open.length} em dia`)+k('VENCIDO',money(gSum(late)),late.length?`${late.length} atrasado(s)`:'Nada vencido ✓',late.length?'neg':'')+k('% DA RECEITA',rev?dec(tot/rev*100)+'%':'—',rev?'gastos ÷ receita recebida':'sem receita no mês',rev&&tot>rev?'neg':'')+k('MÉDIA 6 MESES',money(avg),'por mês');
  $('#gTrend').innerHTML=tr.map(x=>`<div class="${x.cur?'cur':''}"><i style="height:${Math.max(4,x.v/tmax*100)*.62}%" title="${money(x.v)}"></i><span>${esc(x.l)}</span></div>`).join('');
  const byC={};all.forEach(f=>{const c=catOf(f);byC[c]=(byC[c]||0)+Number(f.value||0)});const cats=Object.entries(byC).sort((a,b)=>b[1]-a[1]),cmax=cats[0]?.[1]||1;
  $('#gCatHint').textContent=gCatF?'· filtrando':'· toque para filtrar';
  $('#gCats').innerHTML=cats.length?cats.map(([c,v])=>`<div class="dr${gCatF===c?' on':''}" data-act="gCat" data-c="${esc(c)}" role="button" tabindex="0"><span title="${esc(c)}">${catIcon(c)} ${esc(c)}</span><div class="bar"><i style="width:${v/cmax*100}%"></i></div><b>${money(v)}</b><span class="sub" style="min-width:34px;text-align:right">${tot?Math.round(v/tot*100):0}%</span></div>`).join(''):'<div class="empty">Sem gastos neste mês.</div>';
  const sel=$('#gCatSel'),cur=gCatF,names=[...new Set([...EXP_CATS.map(x=>x[0]),...cats.map(x=>x[0])])];
  sel.innerHTML='<option value="">Todas as categorias</option>'+names.map(c=>`<option${c===cur?' selected':''}>${esc(c)}</option>`).join('');
  const base=all.filter(f=>(!q||String(f.description||'').toLowerCase().includes(q)||String(f.supplier||'').toLowerCase().includes(q))&&(!gCatF||catOf(f)===gCatF));
  pillCounts('#gFilter',{all:base.length,paid:base.filter(f=>f.status==='Pago').length,open:base.filter(f=>f.status!=='Pago'&&!lateOf(f)).length,late:base.filter(lateOf).length});
  const sort=$('#gSort').value,list=base.filter(f=>gStatus==='all'||(gStatus==='paid'&&f.status==='Pago')||(gStatus==='open'&&f.status!=='Pago'&&!lateOf(f))||(gStatus==='late'&&lateOf(f)))
    .sort((a,b)=>sort==='value'?Number(b.value)-Number(a.value):sort==='cat'?catOf(a).localeCompare(catOf(b),'pt-BR')||String(a.dueDate).localeCompare(String(b.dueDate)):String(a.dueDate).localeCompare(String(b.dueDate)));
  $('#gList').innerHTML=list.length?list.map(f=>{
    const fs=finState([f]),c=catOf(f),series=f.recurId?db.finance.filter(x=>x.recurId===f.recurId).length:0;
    return scard({key:'g:'+f.id,tone:fs.k==='late'?'bad':'ok',name:f.description,av:catIcon(c),badge:fs.label,cls:fs.cls,sub:`${esc(c)} · vence ${fmtDate(f.dueDate)}`,
      mini:[['VALOR',money(f.value)],['VENCIMENTO',fmtDate(f.dueDate)],[lateOf(f)?'ATRASO':'FORMA',lateOf(f)?daysLate(f)+' dia(s)':esc(f.paymentMethod||'—')]],
      det:[['Categoria',esc(c)],['Fornecedor',esc(f.supplier||'—')],['Pago em',f.paidAt?fmtDate(f.paidAt):'—'],['Recorrência',series>1?`mensal · ${series} lançamentos`:'—'],['Observações',esc(f.notes||'—')]],
      ...(f.status==='Pago'?{prim:''}:{}),acts:(f.status!=='Pago'?`<button class="btn sm" data-act="payFin" data-id="${f.id}">Pagar</button>`:`<button class="btn sm" data-act="unpayFin" data-id="${f.id}">Desfazer</button>`)+`<button class="btn sm" data-act="editFin" data-id="${f.id}">Editar</button><button class="btn sm" data-act="gDup" data-id="${f.id}">Repetir no próximo mês</button><button class="btn sm bad" data-act="delFin" data-id="${f.id}">Excluir</button>`});
  }).join(''):'<div class="card empty">Nenhum gasto neste filtro.</div>';
}
function expModal(id){
  const f=id?db.finance.find(x=>x.id===id):null,cat=f?catOf(f):'Outros',methods=db.payments||['PIX','Cartão de Crédito','Dinheiro','Transferência'];editing=id||null;
  openModal(`<h2>${f?'Editar gasto':'Novo gasto'}</h2><div class="form">
    <div class="field full"><label for="gDesc">Descrição *</label><input id="gDesc" value="${esc(f?.description)}" placeholder="Ex.: aluguel, energia, material"></div>
    <div class="field"><label for="gCatIn">Categoria</label><select id="gCatIn">${opts([...new Set([...EXP_CATS.map(x=>x[0]),cat])],cat)}</select></div>
    <div class="field"><label for="gSup">Fornecedor</label><input id="gSup" value="${esc(f?.supplier)}"></div>
    <div class="field"><label for="gVal">Valor (R$) *</label><input id="gVal" type="number" min="0" step="0.01" inputmode="decimal" value="${esc(f?.value)}"></div>
    <div class="field"><label for="gDue">Vencimento *</label><input id="gDue" type="date" value="${esc(f?.dueDate||(ym(finMonth)===ym(new Date())?iso(new Date()):ym(finMonth)+'-01'))}"></div>
    <div class="field"><label for="gSt">Status</label><select id="gSt">${opts(['Pendente','Pago'],f?.status||'Pendente')}</select></div>
    <div class="field"><label for="gPay">Forma de pagamento</label><select id="gPay"><option value="">—</option>${opts(methods,f?.paymentMethod)}</select></div>
    ${f?'':'<div class="field full"><label for="gRep">Repetir mensalmente por (meses)</label><input id="gRep" type="number" min="1" max="24" value="1"></div>'}
    <div class="field full"><label for="gNotes">Observações</label><input id="gNotes" value="${esc(f?.notes)}"></div>
  </div><div class="foot"><button class="btn" data-act="closeModal">Cancelar</button><button class="btn primary" data-act="gSave">Salvar</button></div>`);
}
function gSave(){
  const desc=$('#gDesc').value.trim(),val=Number($('#gVal').value),due=$('#gDue').value;
  if(!desc||!(val>0)||!due)return toast('Informe descrição, valor maior que zero e vencimento.');
  const old=editing?db.finance.find(x=>x.id===editing):null,st=$('#gSt').value;
  const base={type:'Despesa',studentId:'',studentName:'',description:desc,category:$('#gCatIn').value,supplier:$('#gSup').value.trim(),value:val,paymentMethod:$('#gPay').value,notes:$('#gNotes').value.trim()};
  if(old){const o={...old,...base,dueDate:due,status:st};if(st==='Pago')o.paidAt=old.paidAt||iso(new Date());else delete o.paidAt;db.finance[db.finance.indexOf(old)]=o}
  else{const n=Math.min(24,Math.max(1,Math.floor(Number($('#gRep').value)||1))),rid=n>1?uid('rec'):'';
    for(let i=0;i<n;i++){const o={...base,id:uid('exp'),dueDate:addMonths(due,i),status:i===0?st:'Pendente'};if(rid)o.recurId=rid;if(o.status==='Pago')o.paidAt=iso(new Date());db.finance.push(o)}}
  if(!save())return;closeModal();render();toast(old?'Gasto atualizado.':'Gasto salvo.');
}
Object.assign(ACT,{
  gNew:()=>expModal(),gSave,
  gCat:e=>{gCatF=gCatF===e.dataset.c?'':e.dataset.c;render()},
  gDup:e=>{const f=db.finance.find(x=>x.id===e.dataset.id);if(!f)return;const c={...f,id:uid('exp'),dueDate:addMonths(f.dueDate,1),status:'Pendente'};delete c.paidAt;db.finance.push(c);save();finMonth=new Date(c.dueDate+'T12:00');render();toast('Gasto repetido no próximo mês.')}
});
$('#gFilter').addEventListener('click',e=>{const b=e.target.closest('button');if(!b)return;gStatus=b.dataset.f;$$('#gFilter button').forEach(x=>x.classList.toggle('on',x===b));rExpenses()});
document.addEventListener('input',e=>{if(e.target.id==='gDesc'&&!editing){const c=$('#gCatIn');if(c&&!c.dataset.t)c.value=guessCat(e.target.value)}});
document.addEventListener('change',e=>{if(e.target.id==='gCatIn')e.target.dataset.t='1'});
$('#gSearch').addEventListener('input',rExpenses);$('#gSort').addEventListener('change',rExpenses);$('#gCatSel').addEventListener('change',e=>{gCatF=e.target.value;rExpenses()});
$('#gCats').addEventListener('keydown',e=>{const r=e.target.closest('.dr');if(r&&(e.key==='Enter'||e.key===' ')){e.preventDefault();ACT.gCat(r)}});


/* ===== seletores dinâmicos ===== */
function fDaySync(){
  if(!$('#fDaySum'))return;
  const cap=Math.max(1,Number(db.settings.capacity)||1),time=$('#fTime')?.value,plan=db.plans.find(p=>p.name===$('#fPlan')?.value),sel=$$('.fDay:checked').map(x=>x.value),full=[];
  $$('.fDay').forEach(x=>{const d=x.value,lab=x.parentNode,sm=lab.querySelector('small'),n=time?activeStudents().filter(z=>z.id!==editing&&z.time===time&&normDays(z.days).includes(d)).length:null;
    if(sm)sm.textContent=n==null?'':`${n}/${cap}`;const f=n!=null&&n>=cap;lab.classList.toggle('full',f);if(f&&x.checked)full.push(DAY[d])});
  const w=plan&&Number(plan.weekly);
  $('#fDaySum').innerHTML=`<b>${sel.length}</b> dia${sel.length===1?'':'s'} por semana`+(w&&sel.length?(sel.length===w?` <span class="badge ok">plano ${w}x</span>`:` <span class="badge warn">plano prevê ${w}x</span>`):'')+(full.length?` <span class="badge bad">lotado: ${full.join(', ')}</span>`:'');
}
const SEGS=['stStatus','feType','feSort','fsSort','gSort','eqFilter','sPixT','hrStep','rpStatus','sDark','sGlass'];
let SEGL=[];
function segKind(sel){
  if(sel.multiple||sel.dataset.act||sel.classList.contains('eqsel'))return null;
  const o=[...sel.options],t=o.map(x=>x.textContent.trim());if(o.length<2)return null;
  if(o.length>=6&&t.every(x=>x.length<=8))return 'grid';
  if(o.length<=5&&t.every(x=>x.length<=18)&&t.join('').length<=60)return 'seg';return null}
function segUp(root){
  const list=root?[...root.querySelectorAll('select')]:SEGS.map(id=>document.getElementById(id)).filter(Boolean);
  list.forEach(sel=>{if(sel.dataset.seg)return;const k=SEGS.includes(sel.id)?'seg':segKind(sel);if(!k)return;sel.dataset.seg='1';
    const box=document.createElement('div');box.className='seg'+(k==='grid'?' grid':'');box.setAttribute('role','radiogroup');
    const draw=()=>{box.innerHTML=[...sel.options].map(o=>`<button type="button" role="radio" aria-checked="${o.value===sel.value}" class="${o.value===sel.value?'on':''}" data-v="${esc(o.value)}">${esc(o.textContent)}</button>`).join('')};
    sel._draw=draw;draw();sel.after(box);SEGL.push(sel);
    box.addEventListener('click',e=>{const b=e.target.closest('button');if(!b)return;sel.value=b.dataset.v;sel.dispatchEvent(new Event('change',{bubbles:true}));draw()})})}
const segRefresh=()=>{SEGL=SEGL.filter(x=>x.isConnected);SEGL.forEach(x=>x._draw())};
document.addEventListener('change',e=>{if(e.target.matches?.('.fDay,#fTime,#fPlan'))fDaySync()});
Object.assign(ACT,{dayPre:e=>{const v=String(e.dataset.d||'').split(',').filter(Boolean);$$('.fDay').forEach(x=>{x.checked=v.includes(x.value)});fDaySync()}});

/* ========== PAINEL: personalização ========== */
Object.assign(ACT,{dashCustom:dashCustomModal,dashReset:()=>{db.settings.dashHidden=[];db.settings.dashOrder=[];save();rDash();dashCustomModal()},dashMove:e=>dashMove(e.dataset.id,Number(e.dataset.dir))});
document.addEventListener('change',e=>{const id=e.target.dataset?.dc;if(!id)return;const set=new Set(dashHidden());e.target.checked?set.delete(id):set.add(id);db.settings.dashHidden=[...set];save();rDash();dashCustomList();$(`#dcList input[data-dc="${id}"]`)?.focus()});

/* ========== RELÓGIO ========== */
function tick(force){
  if(document.hidden&&!force)return;
  const n=new Date(),mk=n.getHours()*60+n.getMinutes(),dk=iso(n),dash=page==='dashboard';
  if(dash)clockTick();
  if(tick.d&&dk!==tick.d){tick.d=dk;tick.m=mk;render();return}
  tick.d=dk;
  if(mk!==tick.m||force){tick.m=mk;if(dash){dashNext();rDashLive()}}
}
(function loop(){setTimeout(()=>{if(!$('#app').hidden)tick();loop()},1000-Date.now()%1000)})();
document.addEventListener('visibilitychange',()=>{if(!document.hidden&&!$('#app').hidden)tick(true)});
window.addEventListener('focus',()=>{if(!$('#app').hidden)tick(true)});

/* ========== LOGIN UI + INÍCIO ========== */
function start(){$('#gate').hidden=true;$('#app').hidden=false;applyTheme();tick();segUp();render()}
const gView=v=>{$('#gForm').hidden=v!=='login';$('#gSubP').hidden=v!=='login';$('#gForgot').hidden=v!=='forgot';['gCode','gNew1','gNew2'].forEach(i=>$('#'+i).value='');$('#gErr2').textContent='';$('#gErr').textContent=''};
$('#gForgotBtn').onclick=()=>gView('forgot');$('#gBack').onclick=()=>gView('login');
$('#gReq').onclick=()=>{
  const n=Auth.norm(db.settings.whatsapp),e=$('#gErr2');
  if(n.length<12)return e.textContent='WhatsApp da proprietária não configurado neste aparelho (Configurações > Studio).';
  const p=Auth.request();$('#gProto').hidden=false;$('#gProtoVal').textContent=p;e.textContent='';
  window.open(`https://wa.me/${n}?text=${encodeURIComponent(`🔐 *Redefinição de senha — ${db.settings.studioName}*\nProtocolo: *${p}*\nPreciso do código de autorização.`)}`,'_blank','noopener');
};
$('#gDo').onclick=()=>{
  const r=Auth.reset($('#gCode').value,$('#gNew1').value,$('#gNew2').value);
  if(!r.ok)return $('#gErr2').textContent=r.msg;
  gView('login');$('#gErr').style.color='var(--ok)';$('#gErr').textContent='Senha redefinida. Entre com a nova senha.';
};
$('#gEye').onclick=()=>{const i=$('#gPass');i.type=i.type==='password'?'text':'password';$('#gEye use').setAttribute('href','#i-'+(i.type==='password'?'eye':'eye-off'))};
$('#gForm').addEventListener('submit',async e=>{
  e.preventDefault();const pw=$('#gPass').value,btn=$('#gBtn'),err=$('#gErr');
  if(!pw){err.textContent='Digite a senha.';return}
  btn.disabled=true;btn.textContent='Verificando…';err.textContent='';
  const r=await Auth.attempt(pw,$('#gRem').checked);
  btn.disabled=false;btn.textContent='Entrar';
  if(r.ok){const m=$('#gMail').value.trim();if(m&&window.FB)window.FB.signIn(m,pw);$('#gPass').value='';start()}else{err.textContent=r.msg;$('#gPass').select()}
});
window.SPApp={get db(){return db},save,render,applyTheme,toast}; /* ponte usada por firebase-sync.js */
try{$('#gMail').value=localStorage.getItem('sp_fb_email')||''}catch{}
if(Auth.valid())start();else{applyTheme();$('#gPass').focus()}

/* ===== decoração automática de ícones (botões, títulos, KPIs, seções, vazios) ===== */
(function(){
const BA={newStudent:'plus',payFin:'check',unpayFin:'undo',confirmPay:'check',mkDone:'check',wtConv:'check',mkToAgenda:'calendar',genMonth:'calendar',genBills:'receipt',exportDb:'download',rpCsv:'download',importDb:'upload',changePw:'lock',authGen:'key',authSend:'chat',alRestore:'undo',dashReset:'undo',alDismiss:'x',closeModal:'x',dashCustom:'sliders',hrSeq:'clock',hrSeqToggle:'clock',eqAuto:'check',eqHist:'dumbbell',eqWeek:'calendar',eqClear:'undo',gDup:'copy',phDel:'trash',avOpen:'users',avUse:'check',avRand:'undo'};
const act=a=>BA[a]||(/^(edit|tEdit|alEdit)/.test(a)?'edit':/^(save|tSave|gSave)/.test(a)?'save':/^del/.test(a)?'trash':'');
const G={'\u2715':'x','\u21BA':'undo','\u2190':'chev-l','\u2192':'chev-r'};
const KM=[['ALUNO','users'],['RECEBIDO','cash'],['A RECEBER','clock'],['DESPESA','receipt'],['SALDO','wallet'],['AULAS','calendar'],['ATEN','bell'],['CAPACIDADE','pie'],['OCUPA','pie'],['LIVRES','pie'],['APARELHO','dumbbell'],['UNIDADES','dumbbell'],['REPASSE','cash'],['RECEITA','chart'],['MARGEM','chart'],['TICKET','chart'],['CANCELADAS','x'],['PAGO','check'],['VENCIDO','alert'],['TOTAL','receipt']];
const SM={alerts:'bell',equip:'dumbbell',pipe:'chart',rev:'cash',mgmt:'pie',bday:'cake',week:'calendar',teach:'teacher',fin:'cash'};
const HM=[['Studio','home'],['Paleta','palette'],['PIX','pix'],['Planos','tag'],['Hor\u00e1rios','clock'],['Mensagens','chat'],['Dados','save'],['Alterar','lock'],['Autorizar','key'],['Hoje','calendar'],['Aparelhos','dumbbell'],['Rod\u00edzio','dumbbell'],['Receita por','chart'],['Por hor\u00e1rio','clock'],['Grade','calendar'],['Registros','pulse'],['Controle','undo'],['Pr\u00f3ximas','clock']];
const PT={students:'users',agenda:'calendar',money:'wallet',settings:'sliders',makeups:'undo',waitlist:'hourglass',birthdays:'cake',hours:'clock',occupancy:'pie',teachers:'teacher',alerts:'bell',evolution:'pulse',reports:'chart',equipment:'dumbbell',guide:'bulb',learn:'book',search:'search'};
function btn(b){b.dataset.ic='1';if(b.querySelector('svg'))return;const t=b.textContent.trim();
  if(G[t]){b.innerHTML=ico(G[t]);return}
  if(!b.children.length){
    if(t.startsWith('+ ')){b.textContent=t.slice(2);b.insertAdjacentHTML('afterbegin',ico('plus'));return}
    if(t.startsWith('\u2190 ')){b.textContent=t.slice(2);b.insertAdjacentHTML('afterbegin',ico('chev-l'));return}
    if(t.endsWith(' \u2192')){b.textContent=t.slice(0,-2);b.insertAdjacentHTML('beforeend',ico('chev-r'));return}}
  if(!t||!b.classList.contains('btn'))return;
  const n=b.id==='logoutBtn'?'logout':b.classList.contains('wa')?'chat':act(b.dataset.act||'');
  if(n)b.insertAdjacentHTML('afterbegin',ico(n))}
function run(){
  document.querySelectorAll('button:not([data-ic])').forEach(btn);
  fabSync();
  document.querySelectorAll('.sc:not([data-n]),.item:not([data-n])').forEach(el=>{el.dataset.n=1;el.style.setProperty('--n',Math.min(8,[].indexOf.call(el.parentNode.children,el)))});
  document.querySelectorAll('.kpi:not([data-ic])').forEach(k=>{k.dataset.ic='1';const s=k.querySelector('small');if(!s)return;const u=s.textContent.toUpperCase(),m=KM.find(x=>u.includes(x[0]));if(m)k.insertAdjacentHTML('beforeend','<span class="ki">'+ico(m[1])+'</span>')});
  document.querySelectorAll('details.sec[data-sec]:not([data-ic])').forEach(d=>{d.dataset.ic='1';const s=d.querySelector('summary'),n=SM[d.dataset.sec];if(s&&n)s.insertAdjacentHTML('afterbegin',ico(n))});
  document.querySelectorAll('.card h2:not([data-ic])').forEach(h=>{h.dataset.ic='1';if(h.children.length)return;const t=h.textContent.trim(),m=HM.find(x=>t.startsWith(x[0]));if(m)h.insertAdjacentHTML('afterbegin',ico(m[1]))});
  document.querySelectorAll('.empty:not([data-ic])').forEach(e=>{e.dataset.ic='1';e.insertAdjacentHTML('afterbegin','<span class="ei">'+ico('inbox')+'</span>')})}
Object.entries(PT).forEach(([p,n])=>{const h=document.querySelector('#page-'+p+' .head h1');if(h)h.insertAdjacentHTML('afterbegin','<span class="ti">'+ico(n)+'</span>')});
let q=0;new MutationObserver(()=>{if(!q)q=requestAnimationFrame(()=>{q=0;run()})}).observe(document.body,{childList:true,subtree:true});
run();
})();
