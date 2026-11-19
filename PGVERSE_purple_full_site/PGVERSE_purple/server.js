'use strict';
// PG//VERSE demonstration backend: game accounts, cloud saves and a shared leaderboard.
// No Roblox API, password checking, or third-party account access is performed.
const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');

const ROOT = __dirname;
const PUBLIC = path.join(ROOT,'public');
const DATA_DIR = process.env.DATA_DIR || path.join(ROOT,'data');
const DB_FILE = path.join(DATA_DIR,'players.json');
const PORT = parseInt(process.env.PORT || '3000',10);
const COOKIE = 'pgverse_session';
const WEEK = 7*24*60*60*1000;
const SECURE = process.env.NODE_ENV === 'production';
fs.mkdirSync(DATA_DIR,{recursive:true});
let db = {users:[],sessions:[]};
try {const saved=JSON.parse(fs.readFileSync(DB_FILE,'utf8')); if(Array.isArray(saved.users)&&Array.isArray(saved.sessions))db=saved;} catch(e){if(e.code!=='ENOENT')console.error('Error reading database; refusing to overwrite:',e.message);}
let writesDisabled=false;
try{if(fs.existsSync(DB_FILE))JSON.parse(fs.readFileSync(DB_FILE,'utf8'));}catch(e){writesDisabled=true;}
function persist(){
 if(writesDisabled)throw new Error('Database damaged; writes disabled to protect data');
 const temp=DB_FILE+'.tmp';
 fs.writeFileSync(temp,JSON.stringify(db),{mode:0o600});
 fs.renameSync(temp,DB_FILE);
}
function json(res,code,payload,headers={}){
 res.writeHead(code,{'Content-Type':'application/json; charset=utf-8','Cache-Control':'no-store','X-Content-Type-Options':'nosniff',...headers});res.end(JSON.stringify(payload));
}
function err(res,status,message){return json(res,status,{error:message});}
function readBody(req,maxBytes=450000){return new Promise((resolve,reject)=>{
 let size=0;const parts=[];req.on('data',chunk=>{size+=chunk.length;if(size>maxBytes){reject(new Error('Payload too large'));req.destroy();return;}parts.push(chunk)});
 req.on('end',()=>{try{resolve(JSON.parse(Buffer.concat(parts).toString('utf8')||'{}'));}catch{reject(new Error('Invalid JSON'));}});
 req.on('error',reject);
});}
function parseCookies(req){const all={};for(const p of (req.headers.cookie||'').split(';')){const i=p.indexOf('=');if(i>0)all[p.slice(0,i).trim()]=p.slice(i+1).trim();}return all;}
function hash(text){return crypto.createHash('sha256').update(text).digest('hex');}
function getAuth(req){
 const token=parseCookies(req)[COOKIE];if(!token||!/^[a-f0-9]{64}$/.test(token))return null;
 const rec=db.sessions.find(s=>s.tokenHash===hash(token)&&s.expires>Date.now());
 return rec?db.users.find(u=>u.id===rec.userId)||null:null;
}
function setCookie(res,token){const value=COOKIE+'='+token+'; HttpOnly; Path=/; SameSite=Strict; Max-Age='+Math.floor(WEEK/1000)+(SECURE?'; Secure':'');res.setHeader('Set-Cookie',value);}
function clearCookie(res){res.setHeader('Set-Cookie',COOKIE+'=; HttpOnly; Path=/; SameSite=Strict; Max-Age=0'+(SECURE?'; Secure':''));}
function newSession(res,user){
 const token=crypto.randomBytes(32).toString('hex');const cutoff=Date.now()-1000;
 db.sessions=db.sessions.filter(x=>x.expires>cutoff);
 db.sessions.push({tokenHash:hash(token),userId:user.id,expires:Date.now()+WEEK});
 persist();setCookie(res,token);
}
function pwHash(password,salt){return crypto.scryptSync(password,salt,64).toString('hex');}
function checkPassword(password,user){const test=Buffer.from(pwHash(password,user.salt),'hex');const saved=Buffer.from(user.passwordHash,'hex');return test.length===saved.length&&crypto.timingSafeEqual(test,saved);}
const limits=new Map();
function rateOk(req,scope){
 const addr=(req.socket.remoteAddress||'unknown');const key=addr+':'+scope;const now=Date.now();let row=limits.get(key);
 if(!row||now-row.since>15*60*1000){row={since:now,count:0};limits.set(key,row);}
 row.count++;return row.count<=(scope==='auth'?20:360);
}
function cleanNumber(x,max){return Number.isFinite(x)&&x>=0?Math.min(max,Math.floor(x)):0;}
function safeProgress(input){
 if(!input||typeof input!=='object'||Array.isArray(input))return null;
 // Keep only game-state fields. Never store arbitrary profile fields or real credentials.
 const fields=['version','coins','level','xp','runs','found','skipped','streak','recordSeq','targetSeq','sales','earned','best','inventory','targets','selectedTargetId','upgrades','questClaimed','history','activeLog'];
 const clean={};for(const k of fields)if(Object.prototype.hasOwnProperty.call(input,k))clean[k]=input[k];
 if(!Array.isArray(clean.inventory)||clean.inventory.length>1500)return null;
 if(!Array.isArray(clean.targets)||clean.targets.length>150)return null;
 if(!Array.isArray(clean.history)||clean.history.length>500)return null;
 if(!clean.upgrades||typeof clean.upgrades!=='object'||Array.isArray(clean.upgrades))return null;
 if(JSON.stringify(clean).length>400000)return null;
 clean.version=8;
 for(const key of ['coins','level','xp','runs','found','skipped','streak','recordSeq','targetSeq','sales','earned'])clean[key]=cleanNumber(clean[key],1e10);
 clean.level=Math.max(1,clean.level);
 clean.best=Math.max(-1,Math.min(15,Number.isInteger(clean.best)?clean.best:-1));
 return clean;
}
async function routeAPI(req,res,url){
 const p=url.pathname;
 if(p==='/api/health'&&req.method==='GET')return json(res,200,{ok:true,server:'PGVERSE-8',online:true});
 if(p==='/api/me'&&req.method==='GET'){const user=getAuth(req);return json(res,200,{user:user?{username:user.username}:null,progress:user?user.progress:null});}
 if(p==='/api/leaderboard'&&req.method==='GET'){
  const players=db.users.map(u=>({username:u.username,found:cleanNumber(u.progress?.found,1e10),earned:cleanNumber(u.progress?.earned,1e10),level:Math.max(1,cleanNumber(u.progress?.level,1e6))}));
  players.sort((a,b)=>b.earned-a.earned||b.found-a.found||b.level-a.level||a.username.localeCompare(b.username));
  return json(res,200,{total:players.length,players:players.slice(0,50).map((v,i)=>({rank:i+1,...v}))});
 }
 if(p==='/api/auth/register'&&req.method==='POST'){
  if(!rateOk(req,'auth'))return err(res,429,'Too many attempts; try again later');
  const body=await readBody(req,2000);const username=String(body.username||'').trim();const password=body.password;
  if(!/^[A-Za-z0-9_]{3,20}$/.test(username)||typeof password!=='string'||password.length<8||password.length>72)return err(res,400,'Имя: 3–20 латинских символов, пароль: 8–72 символа');
  if(db.users.some(u=>u.username.toLowerCase()===username.toLowerCase()))return err(res,409,'Это имя уже занято');
  const salt=crypto.randomBytes(16).toString('hex');const user={id:crypto.randomUUID(),username,salt,passwordHash:pwHash(password,salt),progress:null,createdAt:Date.now()};
  db.users.push(user);newSession(res,user);return json(res,201,{user:{username},progress:null});
 }
 if(p==='/api/auth/login'&&req.method==='POST'){
  if(!rateOk(req,'auth'))return err(res,429,'Too many attempts; try again later');
  const body=await readBody(req,2000);const username=String(body.username||'').trim();const password=body.password;
  const user=db.users.find(u=>u.username.toLowerCase()===username.toLowerCase());
  if(!user||typeof password!=='string'||!checkPassword(password,user))return err(res,401,'Неверное имя или пароль');
  newSession(res,user);return json(res,200,{user:{username:user.username},progress:user.progress});
 }
 if(p==='/api/auth/logout'&&req.method==='POST'){
  const token=parseCookies(req)[COOKIE];if(token){db.sessions=db.sessions.filter(s=>s.tokenHash!==hash(token));persist();}
  clearCookie(res);return json(res,200,{ok:true});
 }
 if(p==='/api/progress'&&req.method==='GET'){
  const user=getAuth(req);if(!user)return err(res,401,'Требуется вход');return json(res,200,{progress:user.progress});
 }
 if(p==='/api/progress'&&req.method==='POST'){
  const user=getAuth(req);if(!user)return err(res,401,'Требуется вход');if(!rateOk(req,'save'))return err(res,429,'Too many saves');
  const body=await readBody(req);const progress=safeProgress(body.progress);if(!progress)return err(res,400,'Некорректный прогресс');
  user.progress=progress;user.updatedAt=Date.now();persist();return json(res,200,{ok:true,updatedAt:user.updatedAt});
 }
 return err(res,404,'Not found');
}
const MIME={'.html':'text/html; charset=utf-8','.js':'application/javascript; charset=utf-8','.css':'text/css; charset=utf-8','.webp':'image/webp','.png':'image/png','.svg':'image/svg+xml','.ico':'image/x-icon'};
function staticFile(res,url){
 let filename;
 try{filename=decodeURIComponent(url.pathname==='/'?'/index.html':url.pathname);}catch{return err(res,400,'Invalid URL');}
 const full=path.resolve(PUBLIC,'.'+filename);
 if(full!==PUBLIC&&!full.startsWith(PUBLIC+path.sep))return err(res,403,'Forbidden');
 fs.stat(full,(e,st)=>{
  if(e||!st.isFile())return err(res,404,'Not found');
  res.writeHead(200,{'Content-Type':MIME[path.extname(full)]||'application/octet-stream','Content-Length':st.size,'X-Content-Type-Options':'nosniff','Referrer-Policy':'strict-origin-when-cross-origin','Cache-Control':path.extname(full)==='.html'?'no-cache':'public, max-age=86400'});
  fs.createReadStream(full).pipe(res);
 });
}
http.createServer(async(req,res)=>{
 res.setHeader('X-Frame-Options','DENY');
 let url;try{url=new URL(req.url,'http://localhost');}catch{return err(res,400,'Invalid URL');}
 if(req.method==='POST'){
  // Reject cross-origin browser state mutations. Strict session cookies also block CSRF.
  const origin=req.headers.origin;
  if(origin){let host;try{host=new URL(origin).host}catch{return err(res,403,'Origin blocked')};if(host!==req.headers.host)return err(res,403,'Origin blocked');}
 }
 if(url.pathname.startsWith('/api/')){
  try{await routeAPI(req,res,url);}catch(e){console.error(e);if(!res.headersSent)err(res,400,'Ошибка запроса');}
  return;
 }
 if(req.method!=='GET'&&req.method!=='HEAD')return err(res,405,'Method not allowed');
 staticFile(res,url);
}).listen(PORT,'0.0.0.0',()=>console.log('PG//VERSE v8 listening on http://localhost:'+PORT));
