'use strict';
const express = require('express');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const helmet = require('helmet');
const multer = require('multer');
const rateLimit = require('express-rate-limit');
const Database = require('better-sqlite3');
const nodemailer = require('nodemailer');
const { execFile } = require('child_process');
const { promisify } = require('util');
const execFileAsync = promisify(execFile);

const app = express();
const PORT = Number(process.env.PORT || 3000);
const ROOT = __dirname;
const UPLOADS = path.join(ROOT, 'uploads');
const APK_DIR = path.join(UPLOADS, 'apks');
const IMAGE_DIR = path.join(UPLOADS, 'images');
[UPLOADS, APK_DIR, IMAGE_DIR].forEach(p => fs.mkdirSync(p, {recursive:true}));
const secret = process.env.JWT_SECRET || 'development-only-change-this-secret-before-deploying';
if (secret.length < 32 && process.env.NODE_ENV === 'production') throw new Error('JWT_SECRET must be at least 32 characters in production');

app.use(helmet({contentSecurityPolicy:false, crossOriginResourcePolicy:{policy:'cross-origin'}}));
app.use(express.json({limit:'1mb'}));
app.use(express.urlencoded({extended:false, limit:'1mb'}));
app.use('/uploads', express.static(UPLOADS, {dotfiles:'deny', index:false, maxAge:'1h'}));
app.use(express.static(path.join(ROOT,'public')));
app.use('/api/auth', rateLimit({windowMs:15*60*1000, max:60, standardHeaders:true, legacyHeaders:false}));

const db = new Database(path.join(ROOT,'apphub.sqlite'));
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');
db.exec(`
CREATE TABLE IF NOT EXISTS users (
 id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, email TEXT NOT NULL UNIQUE,
 password_hash TEXT NOT NULL, role TEXT NOT NULL DEFAULT 'user', email_verified INTEGER NOT NULL DEFAULT 0, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS apps (
 id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, developer TEXT NOT NULL DEFAULT 'Unknown developer',
 description TEXT NOT NULL DEFAULT '', category TEXT NOT NULL DEFAULT 'Other', version TEXT NOT NULL DEFAULT '1.0',
 icon_url TEXT NOT NULL DEFAULT '', screenshots TEXT NOT NULL DEFAULT '[]', apk_path TEXT NOT NULL,
 apk_size INTEGER NOT NULL DEFAULT 0, downloads INTEGER NOT NULL DEFAULT 0, featured INTEGER NOT NULL DEFAULT 0,
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS reviews (
 id INTEGER PRIMARY KEY AUTOINCREMENT, app_id INTEGER NOT NULL REFERENCES apps(id) ON DELETE CASCADE,
 user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE, rating INTEGER NOT NULL CHECK(rating BETWEEN 1 AND 5),
 comment TEXT NOT NULL DEFAULT '', created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, UNIQUE(app_id,user_id)
);
CREATE TABLE IF NOT EXISTS email_verifications (
 id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 token_hash TEXT NOT NULL, expires_at INTEGER NOT NULL, used INTEGER NOT NULL DEFAULT 0,
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS password_resets (
 id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 otp_hash TEXT NOT NULL, expires_at INTEGER NOT NULL, attempts INTEGER NOT NULL DEFAULT 0, used INTEGER NOT NULL DEFAULT 0,
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS app_delete_otps (
 id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE, app_id INTEGER NOT NULL,
 otp_hash TEXT NOT NULL, expires_at INTEGER NOT NULL, attempts INTEGER NOT NULL DEFAULT 0, used INTEGER NOT NULL DEFAULT 0,
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS submissions (
 id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 name TEXT NOT NULL, developer TEXT NOT NULL DEFAULT 'Unknown developer', description TEXT NOT NULL DEFAULT '',
 category TEXT NOT NULL DEFAULT 'Other', version TEXT NOT NULL DEFAULT '1.0', icon_url TEXT NOT NULL DEFAULT '',
 screenshots TEXT NOT NULL DEFAULT '[]', apk_path TEXT NOT NULL, apk_size INTEGER NOT NULL DEFAULT 0,
 status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','approved','rejected')),
 reviewer_note TEXT NOT NULL DEFAULT '', approved_app_id INTEGER REFERENCES apps(id) ON DELETE SET NULL,
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, reviewed_at TEXT
);
CREATE TABLE IF NOT EXISTS download_events (
 id INTEGER PRIMARY KEY AUTOINCREMENT, app_id INTEGER NOT NULL REFERENCES apps(id) ON DELETE CASCADE,
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS app_reports (
 id INTEGER PRIMARY KEY AUTOINCREMENT, app_id INTEGER NOT NULL REFERENCES apps(id) ON DELETE CASCADE,
 user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE, reason TEXT NOT NULL, details TEXT NOT NULL DEFAULT '',
 status TEXT NOT NULL DEFAULT 'open' CHECK(status IN ('open','reviewed','dismissed')),
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, UNIQUE(app_id,user_id,status)
);
`);

// Backward-compatible migration: accounts created before verification was added remain usable.
if (!db.prepare('PRAGMA table_info(users)').all().some(c => c.name === 'email_verified')) db.exec('ALTER TABLE users ADD COLUMN email_verified INTEGER NOT NULL DEFAULT 1');

function publicApp(row) {
 if (!row) return null;
 const stats = db.prepare('SELECT ROUND(AVG(rating),1) avgRating, COUNT(*) reviewCount FROM reviews WHERE app_id=?').get(row.id);
 let screenshots=[]; try { screenshots=JSON.parse(row.screenshots||'[]'); } catch {}
 return {id:row.id,name:row.name,developer:row.developer,description:row.description,category:row.category,version:row.version,
 iconUrl:row.icon_url,screenshots,apkSize:row.apk_size,downloads:row.downloads,featured:!!row.featured,createdAt:row.created_at,
 rating:Number(stats.avgRating||0),reviewCount:stats.reviewCount||0};
}
function tokenFor(user){return jwt.sign({id:user.id,email:user.email,role:user.role,name:user.name},secret,{expiresIn:'7d'});}
function auth(req,res,next){const h=req.headers.authorization||'';const token=h.startsWith('Bearer ')?h.slice(7):'';if(!token)return res.status(401).json({error:'Login required'});try{req.user=jwt.verify(token,secret);next();}catch{return res.status(401).json({error:'Session expired. Please log in again.'});}}
function admin(req,res,next){if(req.user?.role!=='admin')return res.status(403).json({error:'Admin access required'});next();}
function safeName(s){return String(s||'').replace(/[<>\u0000-\u001f]/g,'').trim().slice(0,100);}
function mailer(){
 const host=process.env.SMTP_HOST, user=process.env.SMTP_USER, pass=process.env.SMTP_PASS;
 if(!host||!user||!pass) return null;
 return nodemailer.createTransport({host,port:Number(process.env.SMTP_PORT||587),secure:String(process.env.SMTP_SECURE||'false')==='true',auth:{user,pass}});
}
async function sendMail(message){
 const transport=mailer(); if(!transport){console.warn('Email not sent: configure SMTP_HOST, SMTP_USER and SMTP_PASS in .env');return false;}
 try{await transport.sendMail({from:process.env.MAIL_FROM||process.env.SMTP_USER,...message});return true;}
 catch(e){console.error('Email delivery failed:',e.message);return false;}
}
function absoluteUpload(p){const f=path.resolve(ROOT,p);if(!f.startsWith(path.resolve(APK_DIR)+path.sep))throw new Error('Invalid APK path');return f;}


// Create/update the initial admin account from environment variables.
(async()=>{
 const email=(process.env.ADMIN_EMAIL||'').trim().toLowerCase(); const password=process.env.ADMIN_PASSWORD||'';
 if(email && password){const existing=db.prepare('SELECT id FROM users WHERE email=?').get(email);const hash=await bcrypt.hash(password,12);
 if(existing) db.prepare("UPDATE users SET role='admin',email_verified=1 WHERE email=?").run(email);
 else db.prepare("INSERT INTO users(name,email,password_hash,role,email_verified) VALUES(?,?,?,'admin',1)").run('APPHUB Admin',email,hash);}
})();

const apkStorage=multer.diskStorage({destination:(req,file,cb)=>cb(null,APK_DIR),filename:(req,file,cb)=>cb(null,crypto.randomUUID()+'.apk')});
const apkUpload=multer({storage:apkStorage,limits:{fileSize:Number(process.env.MAX_APK_MB||300)*1024*1024,files:1},fileFilter:(req,file,cb)=>{
 const ext=path.extname(file.originalname||'').toLowerCase(); if(ext!=='.apk')return cb(new Error('Only .apk files are accepted')); cb(null,true);
}});
const imageStorage=multer.diskStorage({destination:(req,file,cb)=>cb(null,IMAGE_DIR),filename:(req,file,cb)=>cb(null,crypto.randomUUID()+path.extname(file.originalname||'').toLowerCase())});
const imageUpload=multer({storage:imageStorage,limits:{fileSize:8*1024*1024,files:8},fileFilter:(req,file,cb)=>{
 const ok=['image/png','image/jpeg','image/webp','image/gif'].includes(file.mimetype); if(!ok)return cb(new Error('Only PNG, JPG, WEBP or GIF images are accepted'));cb(null,true);
}});

async function validateApkUpload(req,res,next){
 if(!req.file)return next();
 try{
  const fd=fs.openSync(req.file.path,'r');const sig=Buffer.alloc(4);const n=fs.readSync(fd,sig,0,4,0);fs.closeSync(fd);
  if(n<4||sig[0]!==0x50||sig[1]!==0x4b){fs.rmSync(req.file.path,{force:true});return res.status(400).json({error:'File is not a valid ZIP/APK container'});}
  if(String(process.env.CLAMSCAN_ENABLED||'false').toLowerCase()==='true'){
   const bin=process.env.CLAMSCAN_BIN||'clamscan';
   try{await execFileAsync(bin,['--no-summary',req.file.path],{timeout:120000});}
   catch(e){fs.rmSync(req.file.path,{force:true});if(e.code===1)return res.status(400).json({error:'Security scan detected a possible threat. Upload rejected.'});return res.status(503).json({error:'Malware scanning is enabled but ClamAV is unavailable or failed. Contact the site administrator.'});}
  }
  next();
 }catch(e){if(req.file?.path)fs.rmSync(req.file.path,{force:true});res.status(400).json({error:'Could not validate uploaded APK'});}
}
app.get('/api/health',(req,res)=>res.json({ok:true,name:'APPHUB API',time:new Date().toISOString()}));
const resetLimiter=rateLimit({windowMs:15*60*1000,max:5,standardHeaders:true,legacyHeaders:false});
app.post('/api/auth/register',async(req,res)=>{
 const name=safeName(req.body.name);const email=String(req.body.email||'').trim().toLowerCase();const password=String(req.body.password||'');
 if(name.length<2||!/^\S+@\S+\.\S+$/.test(email)||password.length<8)return res.status(400).json({error:'Name, valid email and password (at least 8 characters) are required'});
 try{
  const hash=await bcrypt.hash(password,12);const info=db.prepare("INSERT INTO users(name,email,password_hash,role,email_verified) VALUES(?,?,?,'user',0)").run(name,email,hash);
  const user=db.prepare('SELECT id,name,email,role FROM users WHERE id=?').get(info.lastInsertRowid);
  const tokenValue=crypto.randomBytes(32).toString('hex'),tokenHash=crypto.createHash('sha256').update(tokenValue).digest('hex');
  db.prepare('INSERT INTO email_verifications(user_id,token_hash,expires_at) VALUES(?,?,?)').run(user.id,tokenHash,Date.now()+24*60*60*1000);
  const base=(process.env.APP_BASE_URL||`http://localhost:${PORT}`).replace(/\/$/,'');
  const sent=await sendMail({to:user.email,subject:'Verify your APPHUB email',text:`Hi ${user.name},\n\nVerify your APPHUB email within 24 hours by opening this link:\n${base}/api/auth/verify-email?token=${tokenValue}\n\nIf you did not create this account, ignore this email.`});
  if(String(process.env.REQUIRE_EMAIL_VERIFICATION||'true').toLowerCase()==='true')return res.status(201).json({ok:true,needsVerification:true,message:sent?'Account created. Check your email and open the verification link before signing in.':'Account created, but verification email could not be sent. Admin must configure SMTP; request another verification email after fixing it.'});
  db.prepare('UPDATE users SET email_verified=1 WHERE id=?').run(user.id);res.status(201).json({token:tokenFor(user),user});
 }
 catch(e){if(String(e.message).includes('UNIQUE'))return res.status(409).json({error:'Email already registered'});res.status(500).json({error:'Could not create account'});}
});
app.get('/api/auth/verify-email',async(req,res)=>{
 const tokenValue=String(req.query.token||'');if(!/^[a-f0-9]{64}$/.test(tokenValue))return res.status(400).send('Invalid or expired verification link.');
 const hash=crypto.createHash('sha256').update(tokenValue).digest('hex');const row=db.prepare('SELECT * FROM email_verifications WHERE token_hash=? AND used=0 ORDER BY id DESC LIMIT 1').get(hash);
 if(!row||row.expires_at<Date.now())return res.status(400).send('Verification link is invalid or expired. Please request a new one.');
 db.prepare('UPDATE users SET email_verified=1 WHERE id=?').run(row.user_id);db.prepare('UPDATE email_verifications SET used=1 WHERE user_id=?').run(row.user_id);
 res.send('<!doctype html><meta name="viewport" content="width=device-width,initial-scale=1"><title>APPHUB email verified</title><main style="font:16px system-ui;max-width:560px;margin:12vh auto;padding:24px"><h1>Email verified ✓</h1><p>Your APPHUB email is verified. Return to APPHUB and sign in.</p><a href="/">Open APPHUB</a></main>');
});
app.post('/api/auth/resend-verification',resetLimiter,async(req,res)=>{
 const email=String(req.body.email||'').trim().toLowerCase(),generic='If this account needs verification and email is configured, a new link will be sent.';const user=db.prepare('SELECT id,name,email,email_verified FROM users WHERE email=?').get(email);
 if(user&&!user.email_verified){const raw=crypto.randomBytes(32).toString('hex'),hash=crypto.createHash('sha256').update(raw).digest('hex');db.prepare('UPDATE email_verifications SET used=1 WHERE user_id=? AND used=0').run(user.id);db.prepare('INSERT INTO email_verifications(user_id,token_hash,expires_at) VALUES(?,?,?)').run(user.id,hash,Date.now()+24*60*60*1000);const base=(process.env.APP_BASE_URL||`http://localhost:${PORT}`).replace(/\/$/,'');await sendMail({to:user.email,subject:'APPHUB email verification link',text:`Hi ${user.name},\n\nVerify your email within 24 hours: ${base}/api/auth/verify-email?token=${raw}`});}
 res.json({ok:true,message:generic});
});
app.post('/api/auth/login',async(req,res)=>{const email=String(req.body.email||'').trim().toLowerCase();const password=String(req.body.password||'');const user=db.prepare('SELECT * FROM users WHERE email=?').get(email);if(!user||!(await bcrypt.compare(password,user.password_hash)))return res.status(401).json({error:'Email or password is incorrect'});if(!user.email_verified&&String(process.env.REQUIRE_EMAIL_VERIFICATION||'true').toLowerCase()==='true')return res.status(403).json({error:'Please verify your email first. Check your inbox or request a new verification link.'});res.json({token:tokenFor(user),user:{id:user.id,name:user.name,email:user.email,role:user.role}});});
app.post('/api/auth/forgot-password',resetLimiter,async(req,res)=>{
 const email=String(req.body.email||'').trim().toLowerCase();
 // Always return the same message so the endpoint does not reveal registered accounts.
 const generic='If this email is registered and email delivery is configured, a reset code will be sent.';
 if(!/^\S+@\S+\.\S+$/.test(email))return res.json({ok:true,message:generic});
 const user=db.prepare('SELECT id,name,email FROM users WHERE email=?').get(email);
 if(user){
  const otp=String(crypto.randomInt(0,1000000)).padStart(6,'0');
  const hash=crypto.createHash('sha256').update(otp).digest('hex');
  db.prepare('UPDATE password_resets SET used=1 WHERE user_id=? AND used=0').run(user.id);
  db.prepare('INSERT INTO password_resets(user_id,otp_hash,expires_at) VALUES(?,?,?)').run(user.id,hash,Date.now()+10*60*1000);
  await sendMail({to:user.email,subject:'APPHUB password reset code',text:`Hi ${user.name},\n\nYour APPHUB password reset code is: ${otp}\n\nIt expires in 10 minutes and can be used once. If you did not request this, ignore this email.`});
 }
 res.json({ok:true,message:generic});
});
app.post('/api/auth/reset-password',resetLimiter,async(req,res)=>{
 const email=String(req.body.email||'').trim().toLowerCase(),otp=String(req.body.otp||'').trim(),password=String(req.body.password||'');
 if(!/^\S+@\S+\.\S+$/.test(email)||!/^\d{6}$/.test(otp)||password.length<8)return res.status(400).json({error:'Enter a valid email, six-digit code and password of at least 8 characters'});
 const user=db.prepare('SELECT id FROM users WHERE email=?').get(email);if(!user)return res.status(400).json({error:'Invalid or expired reset code'});
 const row=db.prepare('SELECT * FROM password_resets WHERE user_id=? AND used=0 ORDER BY id DESC LIMIT 1').get(user.id);
 if(!row||row.expires_at<Date.now()||row.attempts>=5)return res.status(400).json({error:'Invalid or expired reset code'});
 const provided=crypto.createHash('sha256').update(otp).digest('hex');
 if(provided!==row.otp_hash){db.prepare('UPDATE password_resets SET attempts=attempts+1 WHERE id=?').run(row.id);return res.status(400).json({error:'Invalid or expired reset code'});}
 const hash=await bcrypt.hash(password,12);db.prepare('UPDATE users SET password_hash=? WHERE id=?').run(hash,user.id);db.prepare('UPDATE password_resets SET used=1 WHERE id=?').run(row.id);
 res.json({ok:true,message:'Password changed. You can now sign in.'});
});
app.get('/api/auth/me',auth,(req,res)=>{const u=db.prepare('SELECT id,name,email,role,created_at FROM users WHERE id=?').get(req.user.id);if(!u)return res.status(404).json({error:'User not found'});res.json({user:u});});

app.get('/api/apps',(req,res)=>{
 const q=String(req.query.q||'').trim().slice(0,100);const category=String(req.query.category||'').trim().slice(0,50);const sort=String(req.query.sort||'popular');
 let sql='SELECT * FROM apps WHERE 1=1',args=[];if(q){sql+=' AND (name LIKE ? OR developer LIKE ? OR description LIKE ?)';args.push('%'+q+'%','%'+q+'%','%'+q+'%');}if(category&&category!=='All'){sql+=' AND category=?';args.push(category);}
 if(sort==='rating')sql+=' ORDER BY (SELECT AVG(rating) FROM reviews WHERE app_id=apps.id) DESC, downloads DESC';else if(sort==='new')sql+=' ORDER BY created_at DESC';else sql+=' ORDER BY featured DESC, downloads DESC, created_at DESC';
 sql+=' LIMIT 100';res.json({apps:db.prepare(sql).all(...args).map(publicApp)});
});
app.get('/api/apps/:id',(req,res)=>{const row=db.prepare('SELECT * FROM apps WHERE id=?').get(Number(req.params.id));if(!row)return res.status(404).json({error:'App not found'});const reviews=db.prepare('SELECT r.id,r.rating,r.comment,r.created_at createdAt,u.name FROM reviews r JOIN users u ON u.id=r.user_id WHERE r.app_id=? ORDER BY r.created_at DESC LIMIT 100').all(row.id);res.json({app:publicApp(row),reviews});});
app.post('/api/apps/:id/reviews',auth,(req,res)=>{const appId=Number(req.params.id),rating=Number(req.body.rating),comment=String(req.body.comment||'').trim().slice(0,1000);if(!Number.isInteger(rating)||rating<1||rating>5)return res.status(400).json({error:'Rating must be 1–5'});if(!db.prepare('SELECT id FROM apps WHERE id=?').get(appId))return res.status(404).json({error:'App not found'});db.prepare(`INSERT INTO reviews(app_id,user_id,rating,comment) VALUES(?,?,?,?) ON CONFLICT(app_id,user_id) DO UPDATE SET rating=excluded.rating,comment=excluded.comment,created_at=CURRENT_TIMESTAMP`).run(appId,req.user.id,rating,comment);res.json({ok:true,message:'Review saved'});});
app.get('/api/apps/:id/download', (req,res)=>{const row=db.prepare('SELECT * FROM apps WHERE id=?').get(Number(req.params.id));if(!row)return res.status(404).json({error:'App not found'});const file=path.resolve(ROOT,row.apk_path);if(!file.startsWith(path.resolve(APK_DIR)+path.sep)||!fs.existsSync(file))return res.status(404).json({error:'APK file is missing'});db.prepare('UPDATE apps SET downloads=downloads+1 WHERE id=?').run(row.id);db.prepare('INSERT INTO download_events(app_id) VALUES(?)').run(row.id);res.download(file,`${row.name.replace(/[^a-z0-9-_ ]/gi,'').trim()||'app'}.apk`);});

// User/developer submissions remain private until an admin approves them.
app.post('/api/submissions',auth,apkUpload.single('apk'),validateApkUpload,async(req,res)=>{
 if(!req.file)return res.status(400).json({error:'APK file is required'});
 const b=req.body,name=safeName(b.name),developer=safeName(b.developer)||req.user.name;
 if(name.length<2){fs.rmSync(req.file.path,{force:true});return res.status(400).json({error:'App name is required'});}
 let screenshots=[];try{screenshots=JSON.parse(b.screenshots||'[]')}catch{};
 if(!Array.isArray(screenshots))screenshots=[];
 screenshots=screenshots.filter(x=>typeof x==='string'&&/^https:\/\//i.test(x)).slice(0,8);
 const icon=String(b.iconUrl||'');
 const info=db.prepare(`INSERT INTO submissions(user_id,name,developer,description,category,version,icon_url,screenshots,apk_path,apk_size)
 VALUES(?,?,?,?,?,?,?,?,?,?)`).run(req.user.id,name,developer,String(b.description||'').slice(0,10000),safeName(b.category)||'Other',safeName(b.version)||'1.0',icon.startsWith('https://')?icon.slice(0,1000):'',JSON.stringify(screenshots),path.relative(ROOT,req.file.path),req.file.size);
 const sub=db.prepare('SELECT s.*,u.email user_email,u.name user_name FROM submissions s JOIN users u ON u.id=s.user_id WHERE s.id=?').get(info.lastInsertRowid);
 const maxAttach=Number(process.env.MAIL_ATTACHMENT_MAX_MB||15)*1024*1024;let attachments=[];
 if(req.file.size<=maxAttach)attachments=[{filename:(name.replace(/[^a-z0-9-_ ]/gi,'').trim()||'app')+'.apk',path:req.file.path,contentType:'application/vnd.android.package-archive'}];
 const adminEmail=(process.env.ADMIN_EMAIL||'8325460@gmail.com').trim();
 await sendMail({to:adminEmail,subject:`[APPHUB] App approval required: ${name}`,text:`A new app has been submitted and is NOT live yet.\n\nApp: ${name}\nDeveloper: ${developer}\nSubmitter name: ${sub.user_name}\nSubmitter email: ${sub.user_email}\nCategory: ${sub.category}\nVersion: ${sub.version}\nAPK size: ${(req.file.size/1048576).toFixed(2)} MB\nSubmission ID: ${sub.id}\n\nSign in to APPHUB Admin > Pending submissions to approve or reject it.${req.file.size>maxAttach?'\nAPK was not attached because it exceeds MAIL_ATTACHMENT_MAX_MB; download it securely from the admin panel.':''}`,attachments});
 await sendMail({to:sub.user_email,subject:`APPHUB received your app: ${name}`,text:`Hi ${sub.user_name},\n\nAPPHUB has received your app submission “${name}”. It is pending admin review and will not appear publicly until approved.\nSubmission ID: ${sub.id}\n\nYou will receive another email after the review decision.`});
 res.status(201).json({ok:true,submission:{id:sub.id,name:sub.name,status:sub.status,createdAt:sub.created_at},message:'Submission received. It will go live only after admin approval.'});
});
app.get('/api/submissions/mine',auth,(req,res)=>{
 const rows=db.prepare('SELECT id,name,category,version,apk_size apkSize,status,reviewer_note reviewerNote,created_at createdAt,reviewed_at reviewedAt FROM submissions WHERE user_id=? ORDER BY created_at DESC LIMIT 100').all(req.user.id);
 res.json({submissions:rows});
});
// List approved apps published by this account.
app.get('/api/submissions/mine/apps',auth,(req,res)=>{
 const rows=db.prepare(`SELECT a.id,a.name,a.version,a.category,a.apk_size apkSize,a.downloads,s.id submissionId FROM submissions s JOIN apps a ON a.id=s.approved_app_id WHERE s.user_id=? AND s.status='approved' ORDER BY a.created_at DESC`).all(req.user.id);
 res.json({apps:rows,count:rows.length});
});
// Developers may update only apps that were approved from their own account.
app.post('/api/submissions/mine/apps/:id/update',auth,apkUpload.single('apk'),validateApkUpload,(req,res)=>{
 if(!req.file)return res.status(400).json({error:'Select the new .apk file first'});
 const id=Number(req.params.id),version=safeName(req.body.version);
 const owned=db.prepare(`SELECT a.* FROM apps a JOIN submissions s ON s.approved_app_id=a.id WHERE s.user_id=? AND s.status='approved' AND a.id=?`).get(req.user.id,id);
 if(!owned){fs.rmSync(req.file.path,{force:true});return res.status(404).json({error:'You can update only apps approved under your account'});}
 if(!version){fs.rmSync(req.file.path,{force:true});return res.status(400).json({error:'Enter the new version number'});}
 const oldPath=path.resolve(ROOT,owned.apk_path);
 db.prepare('UPDATE apps SET version=?,apk_path=?,apk_size=? WHERE id=?').run(version,path.relative(ROOT,req.file.path),req.file.size,id);
 if(oldPath.startsWith(path.resolve(APK_DIR)+path.sep)&&oldPath!==path.resolve(req.file.path))fs.rmSync(oldPath,{force:true});
 res.json({ok:true,message:`${owned.name} updated to version ${version}.`,app:{id,name:owned.name,version,apkSize:req.file.size}});
});

// Delete a hosted app only after a one-time code is sent to the signed-in developer's email.
app.post('/api/submissions/mine/apps/:id/delete-otp',auth,async(req,res)=>{
 const id=Number(req.params.id);
 const owned=db.prepare(`SELECT a.id,a.name FROM apps a JOIN submissions s ON s.approved_app_id=a.id WHERE s.user_id=? AND s.status='approved' AND a.id=?`).get(req.user.id,id);
 if(!owned)return res.status(404).json({error:'Hosted app not found in your account'});
 const user=db.prepare('SELECT id,name,email FROM users WHERE id=?').get(req.user.id);
 const otp=String(crypto.randomInt(0,1000000)).padStart(6,'0');
 const hash=crypto.createHash('sha256').update(otp).digest('hex');
 db.prepare('UPDATE app_delete_otps SET used=1 WHERE user_id=? AND app_id=? AND used=0').run(user.id,id);
 db.prepare('INSERT INTO app_delete_otps(user_id,app_id,otp_hash,expires_at) VALUES(?,?,?,?)').run(user.id,id,hash,Date.now()+10*60*1000);
 const sent=await sendMail({to:user.email,subject:`APPHUB delete confirmation code: ${owned.name}`,text:`Hi ${user.name},

Your code to delete the hosted app “${owned.name}” is: ${otp}

It expires in 10 minutes and can be used once. If you did not request this, ignore this email.`});
 if(!sent)return res.status(503).json({error:'Could not send OTP email. Check SMTP settings and try again.'});
 res.json({ok:true,message:`A 6-digit deletion code was sent to ${user.email}. It expires in 10 minutes.`});
});
app.post('/api/submissions/mine/apps/:id/delete',auth,async(req,res)=>{
 const id=Number(req.params.id),otp=String(req.body.otp||'').trim();
 if(!/^\d{6}$/.test(otp))return res.status(400).json({error:'Enter the 6-digit code sent to your email'});
 const owned=db.prepare(`SELECT a.* FROM apps a JOIN submissions s ON s.approved_app_id=a.id WHERE s.user_id=? AND s.status='approved' AND a.id=?`).get(req.user.id,id);
 if(!owned)return res.status(404).json({error:'Hosted app not found in your account'});
 const row=db.prepare('SELECT * FROM app_delete_otps WHERE user_id=? AND app_id=? AND used=0 ORDER BY id DESC LIMIT 1').get(req.user.id,id);
 if(!row||row.expires_at<Date.now()||row.attempts>=5)return res.status(400).json({error:'Code expired or invalid. Request a new code.'});
 const hash=crypto.createHash('sha256').update(otp).digest('hex');
 if(hash!==row.otp_hash){db.prepare('UPDATE app_delete_otps SET attempts=attempts+1 WHERE id=?').run(row.id);return res.status(400).json({error:'Incorrect code. Please check your email.'});}
 db.prepare('UPDATE app_delete_otps SET used=1 WHERE id=?').run(row.id);
 const oldPath=path.resolve(ROOT,owned.apk_path);
 const tx=db.transaction(()=>{
  db.prepare("UPDATE submissions SET status='rejected',reviewer_note='Removed by developer after email OTP confirmation',approved_app_id=NULL,reviewed_at=CURRENT_TIMESTAMP WHERE user_id=? AND approved_app_id=?").run(req.user.id,id);
  db.prepare('DELETE FROM apps WHERE id=?').run(id);
 });tx();
 if(oldPath.startsWith(path.resolve(APK_DIR)+path.sep))fs.rmSync(oldPath,{force:true});
 res.json({ok:true,message:`${owned.name} deleted after email verification.`});
});

app.get('/api/admin/submissions',auth,admin,(req,res)=>{
 const rows=db.prepare(`SELECT s.id,s.name,s.developer,s.description,s.category,s.version,s.icon_url iconUrl,s.screenshots,s.apk_size apkSize,s.status,s.reviewer_note reviewerNote,s.created_at createdAt,u.name userName,u.email userEmail
 FROM submissions s JOIN users u ON u.id=s.user_id ORDER BY CASE s.status WHEN 'pending' THEN 0 ELSE 1 END,s.created_at DESC LIMIT 200`).all();
 res.json({submissions:rows.map(r=>({...r,screenshots:(()=>{try{return JSON.parse(r.screenshots||'[]')}catch{return []}})()}))});
});
app.get('/api/admin/submissions/:id/apk',auth,admin,(req,res)=>{
 const row=db.prepare('SELECT * FROM submissions WHERE id=?').get(Number(req.params.id));if(!row)return res.status(404).json({error:'Submission not found'});
 let file;try{file=absoluteUpload(row.apk_path)}catch{return res.status(400).json({error:'Invalid APK path'})}
 if(!fs.existsSync(file))return res.status(404).json({error:'APK file is missing'});
 res.download(file,`${row.name.replace(/[^a-z0-9-_ ]/gi,'').trim()||'submitted-app'}.apk`);
});
app.post('/api/admin/submissions/:id/review',auth,admin,async(req,res)=>{
 const id=Number(req.params.id),decision=String(req.body.decision||''),note=String(req.body.note||'').trim().slice(0,1000);
 if(!['approve','reject'].includes(decision))return res.status(400).json({error:'Decision must be approve or reject'});
 const row=db.prepare(`SELECT s.*,u.email user_email,u.name user_name FROM submissions s JOIN users u ON u.id=s.user_id WHERE s.id=?`).get(id);
 if(!row)return res.status(404).json({error:'Submission not found'});
 if(row.status!=='pending')return res.status(409).json({error:'This submission has already been reviewed'});
 let appId=null;
 if(decision==='approve'){
  const info=db.prepare(`INSERT INTO apps(name,developer,description,category,version,icon_url,screenshots,apk_path,apk_size,featured) VALUES(?,?,?,?,?,?,?,?,?,0)`)
   .run(row.name,row.developer,row.description,row.category,row.version,row.icon_url,row.screenshots,row.apk_path,row.apk_size);
  appId=Number(info.lastInsertRowid);
 }
 db.prepare('UPDATE submissions SET status=?,reviewer_note=?,approved_app_id=?,reviewed_at=CURRENT_TIMESTAMP WHERE id=?').run(decision==='approve'?'approved':'rejected',note,appId,id);
 const subject=decision==='approve'?`APPHUB approved your app: ${row.name}`:`APPHUB update for your app: ${row.name}`;
 const textBody=decision==='approve'?`Hi ${row.user_name},\n\nGood news! Your app “${row.name}” has been approved and is now live on APPHUB.\nApp ID: ${appId}\n${note?`Admin note: ${note}\n`:''}\nThanks for publishing with APPHUB.`:`Hi ${row.user_name},\n\nYour app “${row.name}” was not approved at this time.\n${note?`Reason/note: ${note}\n`:'Please contact APPHUB admin for details.\n'}You may correct the submission and submit again.`;
 await sendMail({to:row.user_email,subject,text:textBody});
 res.json({ok:true,status:decision==='approve'?'approved':'rejected',appId,message:decision==='approve'?'Approved; app is now live.':'Submission rejected.'});
});
app.delete('/api/admin/submissions/:id',auth,admin,(req,res)=>{
 const id=Number(req.params.id);const row=db.prepare("SELECT * FROM submissions WHERE id=? AND status IN ('pending','rejected')").get(id);
 if(!row)return res.status(404).json({error:'Only pending or rejected submissions can be deleted here'});
 const file=path.resolve(ROOT,row.apk_path);db.prepare('DELETE FROM submissions WHERE id=?').run(id);
 if(file.startsWith(path.resolve(APK_DIR)+path.sep))fs.rmSync(file,{force:true});
 res.json({ok:true,message:`Submission “${row.name}” deleted.`});
});
app.get('/api/admin/stats',auth,admin,(req,res)=>{res.json({apps:db.prepare('SELECT COUNT(*) n FROM apps').get().n,users:db.prepare('SELECT COUNT(*) n FROM users').get().n,downloads:db.prepare('SELECT COALESCE(SUM(downloads),0) n FROM apps').get().n,reviews:db.prepare('SELECT COUNT(*) n FROM reviews').get().n});});

app.use((err,req,res,next)=>{console.error(err.message);if(err instanceof multer.MulterError)return res.status(400).json({error:err.code==='LIMIT_FILE_SIZE'?'File is too large':err.message});if(err) return res.status(400).json({error:err.message||'Request failed'});next();});
app.get('*',(req,res)=>res.sendFile(path.join(ROOT,'public','index.html')));
app.listen(PORT,()=>console.log(`APPHUB running at http://localhost:${PORT}`));
