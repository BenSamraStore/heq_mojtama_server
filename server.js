
const express = require("express");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const fs = require("fs");
const UAParser = require('ua-parser-js');
const geoip = require('geoip-lite');
const path = require("path");
const multer = require("multer");
const { Pool } = require("pg");
const cloudinary = require("cloudinary").v2;
const { authenticator } = require("otplib");
const app = express();
cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET,
  secure: true, 
});


const PORT = process.env.PORT;
const SECRET_KEY = process.env.SECRET_KEY;
const REFRESH_SECRET = process.env.REFRESH_SECRET;
const EMAIL_USER = process.env.EMAIL_USER;
const EMAIL_PASS = process.env.EMAIL_PASS;
const ACCESS_EXPIRES_IN = "2h";
const REFRESH_EXPIRES_DAYS = 30;

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});


function runQuery(q, params = []) {
  return pool.query(q, params);
}


const UPLOADS_DIR = path.join(__dirname, "uploads");
if (!fs.existsSync(UPLOADS_DIR)) fs.mkdirSync(UPLOADS_DIR, { recursive: true });
const upload = multer({ dest: UPLOADS_DIR });

// ✅ ميدلويرز
app.use(cors());
app.use(express.json({ limit: "5mb" }));
app.use("/uploads", express.static(UPLOADS_DIR));


function auth(req, res, next) {
  const h = req.headers.authorization || "";
  const token = h.startsWith("Bearer ") ? h.slice(7) : null;
  if (!token) return res.status(401).json({ error: "مطلوب توثيق" });
  jwt.verify(token, SECRET_KEY, (err, payload) => {
    if (err) return res.status(401).json({ error: "توكن غير صالح" });
    req.user = payload; // { id, email }
    next();
  });
}

async function requireAdmin(req, res, next) {
  const email = req.user && req.user.email;
  if (!email) return res.status(401).json({ error: "جلسة غير صالحة" });
  try {
    const { rows } = await runQuery(
      "SELECT is_admin FROM users WHERE email = $1 LIMIT 1",
      [email]
    );
    if (!rows.length || rows[0].is_admin !== 1)
      return res.status(403).json({ error: "🚫 الوصول مرفوض: صلاحيات غير كافية" });
    next();
  } catch (e) {
    return res.status(500).json({ error: "خطأ في قاعدة البيانات" });
  }
}

function signAccessToken(payload) {
  return jwt.sign(payload, SECRET_KEY, { expiresIn: ACCESS_EXPIRES_IN });
}
function signRefreshToken(payload) {
  return jwt.sign(payload, REFRESH_SECRET, { expiresIn: `${REFRESH_EXPIRES_DAYS}d` });
}
async function storeRefreshToken(userId, refreshToken, deviceInfo = 'Unknown Device') {
  const createdAt = Date.now();
  const expiresAt = Date.now() + REFRESH_EXPIRES_DAYS * 24 * 60 * 60 * 1000;
  await runQuery(
    `INSERT INTO refresh_tokens (user_id, token, expires_at, created_at, device_info)
     VALUES ($1, $2, $3, $4, $5)`,
    [userId, refreshToken, expiresAt, createdAt, deviceInfo]
  );
}
async function notifyUser(toUserId, title, body, type = "system", meta = {}) {
  const createdAt = Date.now();
  let finalTitle = title;
  let finalBody = body;
  let senderName = "مستخدم";

  try {
    
    if (meta.sender_id) {
      const { rows } = await runQuery("SELECT name FROM users WHERE id = $1", [meta.sender_id]);
      if (rows.length > 0) {
        senderName = rows[0].name;
      }
    }

    
    switch (type) {
      case "comment":
        finalTitle = "💬 تعليق جديد";
        finalBody = `${senderName} علّق على منشورك.`;
        break;
      case "reply":
        finalTitle = "↩️ رد على تعليقك";
        finalBody = `${senderName} ردّ على تعليقك.`;
        break;
      case "reaction":
        finalTitle = "👍 تفاعل جديد";
        finalBody = `${senderName} تفاعل مع منشورك.`;
        break;
      case "connect_request":
        finalTitle = "🔗 طلب وصل جديد";
        finalBody = `${senderName} أرسل إليك طلب وصل.`;
        break;
      case "connect_accept":
        finalTitle = "🎉 تم قبول طلبك";
        finalBody = `لقد وافق ${senderName} على طلب الوصل.`;
        break;

      case "connect_reject":
        finalTitle = "😔 تم رفض طلبك";
        finalBody = `قام ${senderName} برفض طلب الوصل.`;
        break;
      
      
    }

   
    await runQuery(
      `INSERT INTO notifications (to_user_id, title, body, type, meta, is_read, created_at)
       VALUES ($1, $2, $3, $4, $5, 0, $6)`,
      [toUserId ?? null, finalTitle, finalBody, type, JSON.stringify(meta), createdAt]
    );
    
    console.log(`📢 إشعار مرسل إلى ${toUserId || 'الكل'}: ${finalBody}`);

  } catch (e) {
    console.error("❌ خطأ أثناء إنشاء وإرسال الإشعار:", e.message);
  }
}


app.get("/api/test", (_req, res) => {
  res.json({ ok: true, message: "✅ API + DB (PG) ready", time: new Date().toISOString() });
});


(async () => {
  try {
    await runQuery("SELECT NOW()");
    console.log("🟢 تم الاتصال بـ PostgreSQL");
    
    
    await runQuery(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        email TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        name TEXT NOT NULL,
        bio TEXT DEFAULT '',
        avatar TEXT DEFAULT '',
        joined_at BIGINT NOT NULL,
        verified INTEGER DEFAULT 1,
        country TEXT DEFAULT '',
        residence TEXT DEFAULT '',
        age INTEGER,
        gender TEXT DEFAULT '',
        lock_until BIGINT DEFAULT 0,
        failed_attempts INTEGER DEFAULT 0,
        is_admin INTEGER DEFAULT 0,
        two_fa_enabled INTEGER DEFAULT 0,
        two_fa_secret TEXT DEFAULT '',
        disabled INTEGER DEFAULT 0,
        show_email INTEGER DEFAULT 0,
        heq_id TEXT DEFAULT '',
        display_count INTEGER DEFAULT 0,
        flames INTEGER DEFAULT 0,
        faith_rank TEXT DEFAULT '',
        last_faith_activity BIGINT DEFAULT 0,
        rank_tier TEXT DEFAULT ''
      )
    `);

    // posts
    await runQuery(`
      CREATE TABLE IF NOT EXISTS posts (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
        text TEXT,
        image TEXT,
        agree INTEGER DEFAULT 0,
        disagree INTEGER DEFAULT 0,
        created_at BIGINT NOT NULL
      )
    `);

    // comments
    await runQuery(`
      CREATE TABLE IF NOT EXISTS comments (
        id SERIAL PRIMARY KEY,
        post_id INTEGER NOT NULL REFERENCES posts(id) ON DELETE CASCADE,
        user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
        parent_id INTEGER REFERENCES comments(id) ON DELETE CASCADE,
        text TEXT NOT NULL,
        agree INTEGER DEFAULT 0,
        disagree INTEGER DEFAULT 0,
        created_at BIGINT NOT NULL
      )
    `);

    // reactions
    await runQuery(`
      CREATE TABLE IF NOT EXISTS reactions (
        id SERIAL PRIMARY KEY,
        user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        target_type TEXT NOT NULL,        -- 'post' | 'comment'
        target_id INTEGER NOT NULL,
        action TEXT NOT NULL,             -- 'agree' | 'disagree'
        UNIQUE (user_id, target_type, target_id)
      )
    `);

    
    await runQuery(`
      CREATE TABLE IF NOT EXISTS refresh_tokens (
        id SERIAL PRIMARY KEY,
        user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        token TEXT NOT NULL UNIQUE,
        expires_at BIGINT NOT NULL,
        created_at BIGINT NOT NULL,
        device_info TEXT DEFAULT '', 
        revoked INTEGER DEFAULT 0
      )
    `);
    // جداول مؤقتة للتسجيل والتحقق
await runQuery(`
  CREATE TABLE IF NOT EXISTS pending_users (
    id SERIAL PRIMARY KEY,
    email TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    name TEXT NOT NULL,
    otp_code TEXT NOT NULL,
    created_at BIGINT NOT NULL
  )
`);

await runQuery(`
  CREATE TABLE IF NOT EXISTS otp_codes (
    id SERIAL PRIMARY KEY,
    email TEXT NOT NULL,
    code TEXT NOT NULL,
    expires_at BIGINT NOT NULL
  )
`);
console.log("📩 جداول pending_users و otp_codes جاهزة");

    // notifications
    await runQuery(`
      CREATE TABLE IF NOT EXISTS notifications (
        id SERIAL PRIMARY KEY,
        to_user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        title TEXT NOT NULL,
        body TEXT NOT NULL,
        type TEXT DEFAULT 'system',
        meta JSONB DEFAULT '{}'::jsonb,
        is_read INTEGER DEFAULT 0,
        created_at BIGINT NOT NULL
      )
    `);

    // system_chat
    await runQuery(`
      CREATE TABLE IF NOT EXISTS system_chat (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
        message TEXT NOT NULL,
        from_admin INTEGER DEFAULT 0,
        created_at BIGINT NOT NULL
      )
    `);

    // connections
    await runQuery(`
      CREATE TABLE IF NOT EXISTS connections (
        id SERIAL PRIMARY KEY,
        user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        target_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        status TEXT DEFAULT 'pending', -- pending | connected | rejected
        created_at BIGINT NOT NULL,
        updated_at BIGINT NOT NULL,
        UNIQUE (user_id, target_id)
      )
    `);

 
    await runQuery(`
      CREATE TABLE IF NOT EXISTS reports (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
        post_id INTEGER,
        comment_id INTEGER,
        reason TEXT,
        status TEXT DEFAULT 'open',
        resolution_note TEXT DEFAULT '',
        resolved_at BIGINT DEFAULT 0,
        resolver_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
        created_at BIGINT NOT NULL
      )
    `);
    // profile_visits_log (يسجل آخر زيارة لزوج زائر/مزار لمنع تكرار العد اليومي)
    await runQuery(`
      CREATE TABLE IF NOT EXISTS profile_visits_log (
        id SERIAL PRIMARY KEY,
        visitor_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        visited_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        last_visit_at BIGINT NOT NULL,
        UNIQUE (visitor_id, visited_id) 
      )
    `);
    console.log("👤 جدول profile_visits_log جاهز");
    //  (الشعلة الحيّة/العقاب/الفينيق)
    await runQuery(`
      CREATE TABLE IF NOT EXISTS companion (
        id SERIAL PRIMARY KEY,
        user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE UNIQUE,
        xp INTEGER DEFAULT 0,                 
        level INTEGER DEFAULT 1,             
        evolution_stage INTEGER DEFAULT 1,  
        current_companion TEXT DEFAULT 'phoenix',
        last_activity BIGINT DEFAULT 0,      
        last_visit_check BIGINT DEFAULT 0,   
        visits_count INTEGER DEFAULT 0       
      )
    `);
    console.log("🔥 جدول companion جاهز");
    
// saved_posts
await runQuery(`
  CREATE TABLE IF NOT EXISTS saved_posts (
    id SERIAL PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    post_id INTEGER NOT NULL REFERENCES posts(id) ON DELETE CASCADE,
    saved_at BIGINT NOT NULL,
    UNIQUE(user_id, post_id)
  )
`);
    // videos
await runQuery(`
  CREATE TABLE IF NOT EXISTS videos (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
    cloudinary_url TEXT NOT NULL,
    thumbnail_url TEXT, 
    description TEXT DEFAULT '',
    duration INTEGER,
    agree INTEGER DEFAULT 0,
    disagree INTEGER DEFAULT 0,
    created_at BIGINT NOT NULL
  )
`);
console.log("🎬 جدول videos جاهز");
    // video_comments
await runQuery(`
  CREATE TABLE IF NOT EXISTS video_comments (
    id SERIAL PRIMARY KEY,
    video_id INTEGER NOT NULL REFERENCES videos(id) ON DELETE CASCADE, 
    user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
    parent_id INTEGER REFERENCES video_comments(id) ON DELETE CASCADE,
    text TEXT NOT NULL,
    agree INTEGER DEFAULT 0,
    disagree INTEGER DEFAULT 0,
    created_at BIGINT NOT NULL
  )
`);
console.log("💬 جدول video_comments جاهز");
    
   
    await runQuery(`CREATE INDEX IF NOT EXISTS idx_posts_created ON posts(created_at)`);
    await runQuery(`CREATE INDEX IF NOT EXISTS idx_comments_post ON comments(post_id)`);
    await runQuery(`CREATE INDEX IF NOT EXISTS idx_react_target ON reactions(target_type, target_id)`);
    await runQuery(`CREATE INDEX IF NOT EXISTS idx_notif_to ON notifications(to_user_id, is_read, created_at)`);
    await runQuery(`CREATE INDEX IF NOT EXISTS idx_chat_user ON system_chat(user_id, created_at)`);
    

    console.log("✅ جميع الجداول والفهارس جاهزة");

    // 🔐 seed admin (من ENV لتجنب التسريب)
    if (process.env.ADMIN_EMAIL && process.env.ADMIN_PASS) {
      const { rows } = await runQuery(`SELECT id FROM users WHERE is_admin = 1 LIMIT 1`);
      if (!rows.length) {
        const hash = await bcrypt.hash(process.env.ADMIN_PASS, 10);
        await runQuery(
          `INSERT INTO users (email, password, name, is_admin, verified, joined_at)
           VALUES ($1, $2, $3, 1, 1, $4)`,
          [process.env.ADMIN_EMAIL, hash, "المطور الرئيسي", Date.now()]
        );
        console.log(`✅ تم إنشاء حساب الأدمن (${process.env.ADMIN_EMAIL})`);
      } else {
        console.log("ℹ️ أدمن موجود مسبقاً — تخطي الإنشاء");
      }
    } else {
      console.log("ℹ️ لم يتم إعداد ADMIN_EMAIL/ADMIN_PASS — تخطي إنشاء الأدمن");
    }
  } catch (err) {
    console.error("❌ تهيئة القاعدة/الجداول فشلت:", err.message);
  }
})();

// ====== توليد كود OTP عشوائي ======
function generateOTP() {
  return Math.floor(100000 + Math.random() * 900000).toString();
}

// ====== تسجيل مستخدم جديد مع إرسال كود التفعيل ======
app.post("/api/signup", async (req, res) => {
  try {
    const { email, password, name } = req.body;
    if (!email || !password || !name)
      return res.status(400).json({ error: "الرجاء إدخال جميع الحقول المطلوبة" });

    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email))
      return res.status(400).json({ error: "صيغة البريد غير صالحة" });

    // تحقق إن كان البريد مستخدم مسبقاً
    const existing = await pool.query("SELECT * FROM users WHERE email = $1", [email]);
    if (existing.rows.length)
      return res.status(400).json({ error: "هذا البريد مستخدم بالفعل" });

    // تحقق من المعلقين أيضًا
    const pending = await pool.query("SELECT * FROM pending_users WHERE email = $1", [email]);
    if (pending.rows.length)
      return res.status(400).json({ error: "رمز التفعيل أُرسل مسبقاً، تحقق من بريدك" });

    // تشفير كلمة السر
    const hashed = await bcrypt.hash(password, 10);
    const otp = generateOTP();
    const createdAt = Date.now();

    // إنشاء المستخدم المؤقت
    await pool.query(
      `INSERT INTO pending_users (email, password, name, otp_code, created_at)
       VALUES ($1, $2, $3, $4, $5)`,
      [email, hashed, name, otp, createdAt]
    );

    // إرسال البريد الإلكتروني
    const mailOptions = {
      from: `HEQ المجتمع <${EMAIL_USER}>`,
      to: email,
      subject: "رمز التفعيل لحسابك في HEQ المجتمع",
      html: `
        <div style="font-family:Arial;padding:20px;">
          <h2>رمز تفعيل حسابك في HEQ المجتمع</h2>
          <p>السلام عليكم ورحمة الله ${name} 👋،</p>
          <p>رمز التفعيل الخاص بك هو:</p>
          <h1 style="color:#007BFF;letter-spacing:3px;">${otp}</h1>
          <p>ينتهي الرمز خلال <b>10 دقائق</b>.</p>
        </div>
      `
    };

    await sendEmailBrevo(mailOptions.to, mailOptions.subject, mailOptions.html);

    // تخزين الرمز في جدول otp_codes
    const expiresAt = Date.now() + 10 * 60 * 1000; // 10 دقائق
    await pool.query(
      "INSERT INTO otp_codes (email, code, expires_at) VALUES ($1, $2, $3)",
      [email, otp, expiresAt]
    );

    res.json({
      ok: true,
      message: "📧 تم إرسال رمز التفعيل إلى بريدك الإلكتروني",
      email
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "حدث خطأ داخلي في الخادم" });
  }
});

// ====== تأكيد رمز التفعيل ======
app.post("/api/verify", async (req, res) => {
  try {
    const { email, code } = req.body;
    if (!email || !code)
      return res.status(400).json({ error: "يرجى إدخال البريد الإلكتروني والرمز" });

    // التحقق من وجود الكود وصلاحيته
    const otpRes = await pool.query(
      "SELECT * FROM otp_codes WHERE email = $1 AND code = $2",
      [email, code]
    );
    if (!otpRes.rows.length)
      return res.status(400).json({ error: "رمز غير صحيح ❌" });

    const otpRow = otpRes.rows[0];
    if (Date.now() > otpRow.expires_at)
      return res.status(400).json({ error: "⏳ انتهت صلاحية الرمز" });

    // جلب المستخدم المؤقت
    const pendingRes = await pool.query(
      "SELECT * FROM pending_users WHERE email = $1",
      [email]
    );
    if (!pendingRes.rows.length)
      return res.status(400).json({ error: "لم يتم العثور على المستخدم المؤقت" });

    const userRow = pendingRes.rows[0];
    const joinedAt = Date.now();  
    const insertRes = await pool.query(
      `INSERT INTO users (email, password, name, bio, avatar, joined_at, verified)
       VALUES ($1, $2, $3, '', '', $4, 1) RETURNING id`,
      [userRow.email, userRow.password, userRow.name, joinedAt]
    );
    const userId = insertRes.rows[0].id;
    const heqId = `HEQ${String(userId).padStart(5, "0")}`;
    await pool.query("UPDATE users SET heq_id = $1 WHERE id = $2", [heqId, userId]);
    console.log(`🆔 تم تعيين HEQ-ID: ${heqId}`);
    await pool.query("DELETE FROM pending_users WHERE email = $1", [email]);
    await pool.query("DELETE FROM otp_codes WHERE email = $1", [email]);  
    const payload = { email: userRow.email, id: userId };
    const token = signAccessToken(payload);
    const refreshToken = signRefreshToken(payload);
    const userAgent = req.headers['user-agent'] || 'Unknown Device';
    await storeRefreshToken(userId, refreshToken, userAgent);
    console.log(`✅ تم تفعيل حساب: ${email}`);
    const DEV_EMAIL = "hajeenheq@gmail.com";
    const devRes = await pool.query("SELECT id FROM users WHERE email = $1", [DEV_EMAIL]);
    if (devRes.rows.length) {
      const devId = devRes.rows[0].id;
      const countRes = await pool.query("SELECT COUNT(*) FROM users");
      const total = parseInt(countRes.rows[0].count);
      if (total > 1) {
        const updated = (total - 1) * 5;
        await pool.query("UPDATE users SET display_count = $1 WHERE id = $2", [updated, devId]);
        console.log(`🔢 تم تحديث عداد الموصولين للمطور إلى ${updated}`);
      }
    }

    return res.json({
      ok: true,
      message: "✅ تم تفعيل الحساب بنجاح! جاري توجيهك لإكمال الملف الشخصي.",
      token,
      refreshToken
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "فشل أثناء التحقق أو إنشاء الحساب" });
  }
});
// 🌍 دالة استخراج معلومات الجهاز والموقع
function getClientDetails(req) {
  // 1. تحليل الجهاز (User-Agent)
  const ua = UAParser(req.headers['user-agent']);
  let deviceName = `${ua.os.name || 'System'} - ${ua.browser.name || 'Browser'}`;
  
  // محاولة الحصول على اسم الجهاز الحقيقي (مثل Samsung SM-A50)
  if (ua.device.model) {
    deviceName = `${ua.device.vendor || ''} ${ua.device.model} (${ua.os.name || ''})`;
  }

  // 2. تحليل الموقع (IP)
  // ملاحظة: في Render نستخدم x-forwarded-for للحصول على الـ IP الحقيقي
  let ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress || '';
  if (ip.includes(',')) ip = ip.split(',')[0].trim(); // أخذ أول IP في القائمة

  const geo = geoip.lookup(ip);
  let location = 'موقع غير معروف';
  
  if (geo) {
    location = `${geo.city || ''}, ${geo.country || ''}`;
  } else if (ip === '::1' || ip === '127.0.0.1') {
    location = 'Localhost';
  }

  // دمج النتيجة
  return `${deviceName} | 📍 ${location}`;
}

app.post("/api/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password)
      return res.status(400).json({ error: "أدخل البريد وكلمة المرور" });

    // 1. التحقق من المستخدم
    const userRes = await pool.query("SELECT * FROM users WHERE email = $1", [email]);
    if (!userRes.rows.length)
      return res.status(400).json({ error: "الحساب غير موجود" });

    const user = userRes.rows[0];

    // 2. فحوصات الحظر والتعطيل
    if (user.disabled)
      return res.status(403).json({ error: "🚫 تم تعطيل حسابك." });
    if (user.lock_until && user.lock_until > Date.now()) {
      return res.status(403).json({ error: "🚫 الحساب محظور مؤقتًا." });
    }

    // 3. التحقق من كلمة المرور
    const match = await bcrypt.compare(password, user.password);
    if (!match) {
      return res.status(400).json({ error: "❌ كلمة المرور غير صحيحة." });
    }

    // تصفير المحاولات الفاشلة
    await pool.query("UPDATE users SET failed_attempts = 0, lock_until = 0 WHERE email = $1", [email]);
    
    if (!user.verified) return res.status(403).json({ error: "الحساب غير مفعّل بعد" });

    // ✨✨✨ 4. منطق اكتشاف الجهاز الجديد (المعدل) ✨✨✨
    
    // 1. استخراج المعلومات باستخدام المكتبات الجديدة
    const deviceInfo = getClientDetails(req); 
    
    // 2. تنظيف الجلسات القديمة لنفس الجهاز (باستخدام deviceInfo)
    await pool.query(
        `UPDATE refresh_tokens 
         SET revoked = 1 
         WHERE user_id = $1 AND device_info = $2 AND revoked = 0`,
        [user.id, deviceInfo]
    );

    // 3. التحقق هل هذا الجهاز جديد؟ (نستخدم deviceInfo)
    const deviceCheck = await pool.query(
        "SELECT id FROM refresh_tokens WHERE user_id = $1 AND device_info = $2 LIMIT 1",
        [user.id, deviceInfo] // ✅ استخدمنا deviceInfo هنا
    );

    // إذا لم نجد الجهاز -> نرسل تنبيه
    if (deviceCheck.rows.length === 0) {
        console.log(`🚨 جهاز جديد: ${deviceInfo}`); // ✅ وهنا
        
        const loginTime = new Date().toLocaleString("ar-EG", { timeZone: "Asia/Riyadh" });
        
        const emailHtml = `
        <div style="font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px; border: 1px solid #e0e0e0; border-radius: 10px; background-color: #f9f9f9;">
            <div style="text-align: center; margin-bottom: 20px;">
                <h2 style="color: #333;">تنبيه أمني: تسجيل دخول جديد 🛡️</h2>
            </div>
            <p style="color: #555; font-size: 16px;">السلام عليكم يا <b>${user.name}</b> 👋</p>
            <p style="color: #555; font-size: 15px;">لاحظنا عملية تسجيل دخول جديدة لحسابك على منصة <b>هَجين</b>.</p>
            
            <div style="background-color: #fff; padding: 15px; border-radius: 8px; border-left: 4px solid #00ffaa; margin: 20px 0;">
                <p style="margin: 5px 0;"><b>📱 الجهاز:</b> ${deviceInfo}</p> <p style="margin: 5px 0;"><b>👤 الحساب:</b> ${user.name}</p>
                <p style="margin: 5px 0;"><b>⏰ الوقت:</b> ${loginTime}</p>
            </div>

            <p style="color: #d9534f; font-size: 14px; font-weight: bold;">
                ⚠️ إذا لم تكن أنت من قام بذلك، لا تتجاهل هذه الرسالة!
            </p>
            <p style="color: #555;">يرجى التوجه فوراً لتغيير كلمة المرور وتفعيل التحقق بخطوتين.</p>
            
            <div style="text-align: center; margin-top: 25px;">
                <a href="https://heq-mojtama.onrender.com/settings.html" style="background-color: #d9534f; color: white; padding: 12px 20px; text-decoration: none; border-radius: 5px; font-weight: bold;">تغيير كلمة المرور وتأمين الحساب</a>
            </div>
            <hr style="margin-top: 30px; border: 0; border-top: 1px solid #eee;">
            <p style="font-size: 12px; color: #888; text-align: center;">فريق أمان هَجين</p>
        </div>
        `;

        sendEmailBrevo(user.email, "🚨 تنبيه: تسجيل دخول من جهاز جديد", emailHtml).catch(console.error);
    }
    // ✨✨✨ (انتهى المنطق الجديد) ✨✨✨

    // 5. إنشاء التوكنات
    const payload = { id: user.id, email: user.email };
    const token = signAccessToken(payload);
    const refreshToken = signRefreshToken(payload);

    // 6. التحقق بخطوتين
    if (user.two_fa_enabled === 1) {
      return res.json({
        ok: true,
        two_fa_required: true,
        message: "يرجى إدخال رمز التحقق بخطوتين"
      });
    } else {
      // حفظ التوكن والجهاز في قاعدة البيانات
      await storeRefreshToken(user.id, refreshToken, deviceInfo); // ✅ وهنا

      res.json({
        ok: true,
        two_fa_required: false,
        message: "✅ تم تسجيل الدخول بنجاح",
        token,
        refreshToken
      });
    }

  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "حدث خطأ أثناء تسجيل الدخول" });
  }
});

// ====== تجديد التوكن باستخدام Refresh Token ======
app.post("/api/refresh", async (req, res) => {
  try {
    const { refreshToken } = req.body;
    if (!refreshToken)
      return res.status(400).json({ error: "refreshToken مفقود" });

    // التحقق من وجوده
    const tokenRes = await pool.query(
      "SELECT * FROM refresh_tokens WHERE token = $1 AND revoked = 0",
      [refreshToken]
    );
    if (!tokenRes.rows.length)
      return res.status(401).json({ error: "توكن غير معروف أو ملغى" });

    const row = tokenRes.rows[0];
    if (Date.now() > row.expires_at)
      return res.status(401).json({ error: "انتهت صلاحية الـ Refresh Token" });

    // التحقق من التوقيع
    jwt.verify(refreshToken, REFRESH_SECRET, (err, payload) => {
      if (err)
        return res.status(401).json({ error: "توكن غير صالح" });

      const newAccessToken = signAccessToken({
        id: payload.id,
        email: payload.email
      });

      res.json({
        ok: true,
        message: "✅ تم إصدار توكن جديد بنجاح",
        token: newAccessToken
      });
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "خطأ أثناء تجديد التوكن" });
  }
});

// ====== نسيان كلمة المرور (إرسال رمز إعادة التعيين) ======
app.post("/api/forgot_password", async (req, res) => {
  try {
    const { email } = req.body;
    if (!email)
      return res.status(400).json({ error: "يرجى إدخال البريد الإلكتروني" });

    // التحقق من وجود المستخدم
    const userRes = await pool.query("SELECT * FROM users WHERE email = $1", [email]);
    if (!userRes.rows.length)
      return res.status(404).json({ error: "لم يتم العثور على هذا البريد" });

    // حذف الأكواد القديمة
    await pool.query("DELETE FROM otp_codes WHERE email = $1", [email]);

    // توليد رمز جديد
    const otp = generateOTP();
    const expiresAt = Date.now() + 10 * 60 * 1000; // 10 دقائق

    // تخزين الرمز
    await pool.query(
      "INSERT INTO otp_codes (email, code, expires_at) VALUES ($1, $2, $3)",
      [email, otp, expiresAt]
    );

    // إرسال البريد
    const mailOptions = {
      from: `HEQ المجتمع <${EMAIL_USER}>`,
      to: email,
      subject: "رمز استعادة كلمة المرور - HEQ المجتمع",
      html: `
        <div style="font-family:Arial;padding:20px;">
          <h2>طلب استعادة كلمة المرور</h2>
          <p>السلام عليكم ورحمة الله 👋، لقد طلبت إعادة تعيين كلمة المرور لحسابك.</p>
          <p>رمز التفعيل الخاص بك هو:</p>
          <h1 style="color:#007BFF;letter-spacing:3px;">${otp}</h1>
          <p>ينتهي الرمز خلال <b>10 دقائق</b>.</p>
          <p>إذا لم تكن أنت تحقق من حسابك.</p>
        </div>
      `
    };

    await sendEmailBrevo(mailOptions.to, mailOptions.subject, mailOptions.html);
    console.log(`📧 تم إرسال رمز استعادة لكلمة المرور إلى ${email}: ${otp}`);

    res.json({ ok: true, message: "📨 تم إرسال رمز الاستعادة إلى بريدك الإلكتروني" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "فشل في إرسال رمز الاستعادة" });
  }
});
// ====== التحقق من رمز استعادة كلمة المرور ======
app.post("/api/verify_reset_code", async (req, res) => {
  try {
    const { email, code } = req.body;
    if (!email || !code)
      return res.status(400).json({ error: "يرجى إدخال البريد الإلكتروني والرمز" });

    const { rows } = await pool.query(
      "SELECT * FROM otp_codes WHERE email = $1 AND code = $2",
      [email, code]
    );
    if (!rows.length)
      return res.status(400).json({ error: "رمز غير صحيح ❌" });

    const otp = rows[0];
    if (Date.now() > otp.expires_at)
      return res.status(400).json({ error: "⏳ انتهت صلاحية الرمز، اطلب رمزاً جديداً" });

    res.json({ ok: true, message: "✅ الرمز صالح، يمكنك الآن تعيين كلمة مرور جديدة." });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "خطأ داخلي أثناء التحقق من الرمز" });
  }
});

// ====== إعادة تعيين كلمة المرور ======
app.post("/api/reset_password", async (req, res) => {
  try {
    const { email, newPassword, confirmPassword } = req.body;

    if (!email || !newPassword || !confirmPassword)
      return res.status(400).json({ error: "يرجى إدخال جميع الحقول المطلوبة" });

    if (newPassword !== confirmPassword)
      return res.status(400).json({ error: "❌ كلمتا المرور غير متطابقتين" });

    if (newPassword.length < 12)
      return res.status(400).json({ error: "⚠️ كلمة المرور يجب أن تحتوي على 12 رمز على الأقل." });

    const hasLetters = /[A-Za-z]/.test(newPassword);
    const hasNumbers = /\d/.test(newPassword);
    if (!hasLetters || !hasNumbers)
      return res.status(400).json({ error: "⚠️ كلمة المرور يجب أن تحتوي على أحرف وأرقام معاً." });

    const userRes = await pool.query("SELECT * FROM users WHERE email = $1", [email]);
    if (!userRes.rows.length)
      return res.status(404).json({ error: "لم يتم العثور على هذا البريد" });

    const hashed = await bcrypt.hash(newPassword, 10);
    await pool.query("UPDATE users SET password = $1 WHERE email = $2", [hashed, email]);
    await pool.query("DELETE FROM otp_codes WHERE email = $1", [email]);

    console.log(`🔐 تم تغيير كلمة المرور بنجاح للمستخدم: ${email}`);
    res.json({ ok: true, message: "✅ تم تحديث كلمة المرور بنجاح! يمكنك الآن تسجيل الدخول." });
  } catch (err) {
    console.error("❌ خطأ داخلي:", err);
    res.status(500).json({ error: "حدث خطأ داخلي في الخادم" });
  }
});

// ====== فحص المستخدمين الموجودين ======
app.get("/api/debug/users", async (_req, res) => {
  try {
    const { rows } = await pool.query("SELECT * FROM users");
    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ====== فحص المستخدمين المعلقين ======
app.get("/api/debug/pending", async (_req, res) => {
  try {
    const { rows } = await pool.query("SELECT * FROM pending_users");
    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ====== ترقية مستخدم ليصبح مطوّر ======
app.post("/api/make_admin", async (req, res) => {
  try {
    const { email } = req.body;
    if (!email)
      return res.status(400).json({ error: "يرجى إدخال البريد الإلكتروني" });

    const result = await pool.query("UPDATE users SET is_admin = 1 WHERE email = $1", [email]);
    if (result.rowCount === 0)
      return res.status(404).json({ error: "لم يتم العثور على هذا البريد" });

    res.json({ ok: true, message: `✅ تمت ترقية ${email} ليصبح مطوراً` });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "خطأ في قاعدة البيانات" });
  }
});

// ====== تحديث الملف الشخصي ======
app.post("/api/profile", auth, async (req, res) => { // ⏪ حذفنا upload.single من هنا
  try {
    const email = req.user.email;
    if (!email) return res.status(401).json({ error: "جلسة غير صالحة" });

    // ⏪ عدنا لاستخدام avatarBase64
    const { name, bio, country, residence, age, gender, avatarBase64, show_email } = req.body;
    const setClauses = [];
    const params = [];
    let newAvatarUrl = null;

    if (typeof name !== "undefined")       { setClauses.push(`name = $${params.length + 1}`); params.push(name); }
    if (typeof bio !== "undefined")        { setClauses.push(`bio = $${params.length + 1}`); params.push(bio); }
    if (typeof country !== "undefined")    { setClauses.push(`country = $${params.length + 1}`); params.push(country); }
    if (typeof residence !== "undefined")  { setClauses.push(`residence = $${params.length + 1}`); params.push(residence); }
    if (typeof age !== "undefined")        { setClauses.push(`age = $${params.length + 1}`); params.push(age ?? null); }
    if (typeof gender !== "undefined")     { setClauses.push(`gender = $${params.length + 1}`); params.push(gender); }
    if (typeof show_email !== "undefined") { setClauses.push(`show_email = $${params.length + 1}`); params.push(show_email ? 1 : 0); }

    // ✨ منطق الرفع الجديد من Base64
    if (avatarBase64 && avatarBase64.startsWith('data:image')) {
      try {
        // Cloudinary يمكنه الرفع مباشرة من نص Base64
        const result = await cloudinary.uploader.upload(avatarBase64, {
          folder: "heq_mojtama/avatars",
          public_id: `avatar_${req.user.id}`,
          overwrite: true,
          transformation: [
            { width: 250, height: 250, gravity: "face", crop: "thumb" },
            { fetch_format: "auto", quality: "auto" }
          ]
        });
        newAvatarUrl = result.secure_url;
        setClauses.push(`avatar = $${params.length + 1}`);
        params.push(newAvatarUrl);

      } catch (uploadError) {
        console.error("❌ خطأ أثناء الرفع من Base64 إلى Cloudinary:", uploadError);
      }
    }

    if (setClauses.length === 0) {
      return res.json({ ok: true, message: "لا توجد تغييرات للتحديث." });
    }

    params.push(email);
    const query = `UPDATE users SET ${setClauses.join(", ")} WHERE email = $${params.length}`;
    await pool.query(query, params);

    res.json({ ok: true, message: "✅ تم تحديث الملف الشخصي بنجاح", newAvatarUrl });

  } catch (err) {
    console.error("❌ خطأ أثناء تحديث الملف الشخصي:", err);
    res.status(500).json({ error: "فشل تحديث البيانات" });
  }
});
// ====== جلب بيانات المستخدم الحالي (نسخة محدثة لتشمل الرفيق) ======
app.get("/api/me", auth, async (req, res) => {
  try {
    const userId = req.user && req.user.id; // ⭐️ نستخدم ID بدلاً من email
    if (!userId) return res.status(401).json({ error: "جلسة غير صالحة" });

    const { rows } = await pool.query(
      `SELECT
          u.id, u.heq_id, u.email, u.name, u.bio, u.avatar, u.country, u.residence, u.age, u.gender, 
          u.joined_at, u.display_count, u.flames, u.faith_rank, u.last_faith_activity, u.rank_tier, 
          u.show_email, u.two_fa_enabled,

          -- بيانات الرفيق (القيم الافتراضية)
          COALESCE(c.xp, 0) AS xp, 
          COALESCE(c.level, 1) AS level, 
          COALESCE(c.evolution_stage, '1') AS evolution_stage, 
          COALESCE(c.current_companion, 'phoenix') AS current_companion, 
          
          -- 🔥 جلب عدد الزيارات الحقيقي للمستخدم الحالي
          COALESCE(c.visits_count, 0) AS visits_count,
          
          -- حساب XP اللازمة للمستوى التالي
          (CASE 
              WHEN COALESCE(c.level, 1) < 10 THEN (COALESCE(c.level, 1) * 100) 
              WHEN COALESCE(c.level, 1) = 10 THEN 1000 
              ELSE 1000 
          END) AS xp_to_next_level 
      FROM users u
      LEFT JOIN companion c ON u.id = c.user_id
      WHERE u.id = $1`, // ⭐️ نستخدم ID للبحث
      [userId]
    );

    if (!rows.length)
      return res.status(404).json({ error: "المستخدم غير موجود" });

    const user = rows[0];

    // تجميع بيانات الرفيق داخل كائن 'companion'
    const companionData = {
        xp: user.xp,
        level: user.level,
        evolution_stage: user.evolution_stage,
        visits_count: user.visits_count, // ⭐️ سيحتوي على القيمة الحقيقية
        current_companion: user.current_companion,
        xp_to_next_level: user.xp_to_next_level,
        xp_required: user.xp_to_next_level - user.xp,
    };

    const profileCompleted = Boolean(
      (user.bio && user.bio.trim().length > 0) ||
      (user.avatar && user.avatar.trim().length > 0) ||
      (user.country && user.country.trim().length > 0) ||
      (user.residence && user.residence.trim().length > 0)
    );

    return res.json({
      ok: true,
      user: {
        id: user.id,
        heq_id: user.heq_id,
        email: user.email, 
        name: user.name,
        bio: user.bio,
        avatar: user.avatar,
        country: user.country,
        residence: user.residence,
        age: user.age,
        gender: user.gender,
        joined_at: parseInt(user.joined_at, 10),
        show_email: user.show_email,
        faith_rank: user.faith_rank,
        flames: user.flames,
        rank_tier: user.rank_tier,
        two_fa_enabled: user.two_fa_enabled,
        companion: companionData 
      },
      profileCompleted
    });
  } catch (err) {
    console.error("❌ خطأ أثناء جلب بيانات /api/me:", err);
    res.status(500).json({ error: "فشل جلب بيانات المستخدم" });
  }
});
// ====== جلب جميع المنشورات (عام) ======
app.get("/api/posts", async (_req, res) => {
  try {
    const { rows } = await pool.query(`
      SELECT 
        p.id, p.user_id, p.text, p.image, p.agree, p.disagree, p.created_at,
        u.name AS author_name,
        u.avatar AS author_avatar,
        u.faith_rank AS author_rank,
        u.rank_tier AS author_tier,
        u.flames AS author_flames
      FROM posts p
      LEFT JOIN users u ON u.id = p.user_id
      ORDER BY p.created_at DESC
    `);

    // ✨ التحويل إلى أرقام
    const posts = rows.map(post => ({
      ...post,
      created_at: parseInt(post.created_at, 10)
    }));

    res.json({ ok: true, posts: posts });
  } catch (err) {
    console.error("❌ خطأ في جلب المنشورات:", err);
    res.status(500).json({ error: "خطأ في جلب المنشورات" });
  }
});

// ====== إنشاء منشور جديد ======
app.post("/api/posts", auth, upload.single("image"), async (req, res) => {
  try {
    const { text } = req.body;
    const userId = req.user.id;

    // 🧠 فحص الحظر أو التعطيل
    const userRes = await pool.query("SELECT disabled, lock_until FROM users WHERE id = $1", [userId]);
    const user = userRes.rows[0];
    if (!user)
      return res.status(404).json({ error: "المستخدم غير موجود" });

    if (user.disabled)
      return res.status(403).json({ error: "🚫 حسابك معطّل. لا يمكنك النشر أو التفاعل." });

    if (user.lock_until && user.lock_until > Date.now()) {
      const diffH = Math.ceil((user.lock_until - Date.now()) / (1000 * 60 * 60));
      return res.status(403).json({ error: `⏳ حسابك محظور مؤقتًا (${diffH} ساعة متبقية).` });
    }

    if (!text && !req.file)
      return res.status(400).json({ error: "يرجى كتابة نص أو رفع صورة" });

    let imageUrl = null;
    // ✨ منطق الرفع الجديد إلى Cloudinary
    if (req.file) {
      try {
        const result = await cloudinary.uploader.upload(req.file.path, {
          folder: "heq_mojtama/posts", // مجلد خاص بصور المنشورات
          transformation: [ // تحويلات لتحسين الصورة
            { width: 1080, crop: "limit" }, // تحديد أقصى عرض للصورة
            { fetch_format: "auto", quality: "auto" }
          ]
        });
        imageUrl = result.secure_url;
        
        // حذف الملف المؤقت من خادم Render بعد رفعه بنجاح
        fs.unlinkSync(req.file.path);

      } catch (uploadError) {
        console.error("❌ خطأ أثناء رفع صورة المنشور:", uploadError);
        return res.status(500).json({ error: "فشل في معالجة الصورة" });
      }
    }

    const createdAt = Date.now();
    const result = await pool.query(
      `INSERT INTO posts (user_id, text, image, created_at)
       VALUES ($1, $2, $3, $4) RETURNING id`,
      [userId, text || "", imageUrl, createdAt]
    );

    res.json({
      ok: true,
      id: result.rows[0].id,
      message: "✅ تم نشر المنشور بنجاح",
      image: imageUrl // إرجاع رابط Cloudinary
    });
  } catch (err) {
    console.error("❌ فشل إنشاء المنشور:", err);
    res.status(500).json({ error: "فشل إنشاء المنشور" });
  }
});

// --- 1. Upload a New Video ---
app.post("/api/videos", auth, upload.single("video"), async (req, res) => {
  try {
    const { description } = req.body;
    const userId = req.user.id;

    // Check if user is banned or disabled (similar to creating posts)
    const userRes = await pool.query("SELECT disabled, lock_until FROM users WHERE id = $1", [userId]);
    const user = userRes.rows[0];
    if (!user) return res.status(404).json({ error: "المستخدم غير موجود" });
    if (user.disabled) return res.status(403).json({ error: "🚫 حسابك معطّل. لا يمكنك رفع فيديوهات." });
    if (user.lock_until && user.lock_until > Date.now()) {
      const diffH = Math.ceil((user.lock_until - Date.now()) / (1000 * 60 * 60));
      return res.status(403).json({ error: `⏳ حسابك محظور مؤقتًا (${diffH} ساعة متبقية).` });
    }

    
    if (!req.file) {
      return res.status(400).json({ error: "⚠️ لم يتم رفع أي ملف فيديو" });
    }

    

    let videoUrl = null;
    let thumbnailUrl = null;
    let duration = null;

    try {
      console.log(`☁️ Uploading video for user ${userId} to Cloudinary...`);
      const result = await cloudinary.uploader.upload(req.file.path, {
        resource_type: "video", 
        folder: "heq_mojtama/videos",
        
        // ✨✨✨ هذا هو التعديل الأساسي ✨✨✨
        // هذا الأمر يخبر كلاوديناري أن يجعل الفيديو 9:16 ويضيف حواف سوداء
        transformation: [
          { width: 576, height: 1024, crop: "pad", background: "black" }
        ],
        // ✨✨✨ (انتهى التعديل الأساسي) ✨✨✨

        // (تعديل اختياري): من الأفضل جعل الصورة المصغرة بنفس النسبة
        eager: [
          // { width: 300, height: 400, crop: "limit", format: 'jpg' } // ❌ النسبة القديمة
          { width: 300, height: 533, crop: "fill", gravity: "auto", format: 'jpg' } // ✅ نسبة 9:16
        ],
        eager_async: false, 
        
      });

      videoUrl = result.secure_url;
      duration = Math.round(result.duration); // Duration in seconds

      // Get thumbnail URL from eager transformation
      if (result.eager && result.eager[0]) {
        thumbnailUrl = result.eager[0].secure_url;
      }

      console.log(`✅ Video uploaded successfully: ${videoUrl}`);
      // Delete temporary file from Render server
      fs.unlinkSync(req.file.path);

    } catch (uploadError) {
      console.error("❌ Cloudinary Upload Error:", uploadError);
      // Try to delete temp file even if upload failed
      if (req.file && fs.existsSync(req.file.path)) {
          try { fs.unlinkSync(req.file.path); } catch (e) { console.error("Error deleting temp file:", e);}
      }
      return res.status(500).json({ error: "فشل في معالجة الفيديو في Cloudinary" });
    }

    // Insert video info into the database
    const createdAt = Date.now();
    const insertRes = await pool.query(
      `INSERT INTO videos (user_id, cloudinary_url, thumbnail_url, description, duration, created_at)
       VALUES ($1, $2, $3, $4, $5, $6) RETURNING id`,
      [userId, videoUrl, thumbnailUrl, description || "", duration, createdAt]
    );

    res.status(201).json({
      ok: true,
      message: "✅ تم رفع الفيديو بنجاح!",
      video: {
        id: insertRes.rows[0].id,
        url: videoUrl,
        thumbnail: thumbnailUrl,
        duration: duration,
        description: description || "",
        createdAt: createdAt
      }
    });

  } catch (err) {
    console.error("❌ فشل رفع الفيديو (API):", err);
    // Try to delete temp file in case of DB error too
    if (req.file && fs.existsSync(req.file.path)) {
        try { fs.unlinkSync(req.file.path); } catch (e) { console.error("Error deleting temp file:", e);}
    }
    res.status(500).json({ error: "فشل داخلي أثناء رفع الفيديو" });
  }
});
// --- 2. Get List of Videos (With PAGINATION) ---
app.get("/api/videos", async (req, res) => {
  try {
    
    const limit = parseInt(req.query.limit) || 10; 
    const page = parseInt(req.query.page) || 1;  
    const offset = (page - 1) * limit; 
    const { rows } = await pool.query(`
 
      SELECT
        v.id, v.user_id, v.cloudinary_url, v.thumbnail_url, v.description, v.duration,
        v.agree, v.disagree, v.created_at,
        u.name AS author_name, u.avatar AS author_avatar,
        u.faith_rank AS author_rank, u.rank_tier AS author_tier,
        (SELECT COUNT(*) FROM video_comments vc WHERE vc.video_id = v.id) AS comment_count
      FROM videos v
      LEFT JOIN users u ON u.id = v.user_id
      ORDER BY v.created_at DESC
      LIMIT $1 OFFSET $2 
   `, [limit, offset]);

    const videos = rows.map(video => ({
      id: video.id,
      user_id: video.user_id,
      url: video.cloudinary_url,
      thumbnail: video.thumbnail_url,
      description: video.description,
      duration: video.duration ? parseInt(video.duration, 10) : null,
      agree: parseInt(video.agree, 10),
      disagree: parseInt(video.disagree, 10),
      created_at: parseInt(video.created_at, 10),
      author_name: video.author_name || "مستخدم محذوف",
      author_avatar: video.author_avatar || "https://res.cloudinary.com/dqmlhgegm/image/upload/v1760854549/WhatsApp_Image_2025-10-19_at_8.15.20_AM_njvijg.jpg",
      author_rank: video.author_rank,
      author_tier: video.author_tier,
      comment_count: parseInt(video.comment_count || 0, 10) 
    }));

    res.json({ ok: true, videos: videos });

  } catch (err) {
    console.error("❌ خطأ أثناء جلب قائمة الفيديوهات:", err);
    res.status(500).json({ ok: false, error: "فشل في جلب الفيديوهات" });
  }
});
// --- 6. جلب فيديوهات مستخدم معين (للملف الشخصي) ---
app.get("/api/users/:id/videos", async (req, res) => {
  try {
    const userId = parseInt(req.params.id);
    if (isNaN(userId)) return res.status(400).json({ error: "رقم المستخدم غير صالح" });

    const { rows } = await pool.query(`
      SELECT
        v.id, v.user_id, v.cloudinary_url, v.thumbnail_url, v.description, v.duration,
        v.agree, v.disagree, v.created_at,
        u.name AS author_name, u.avatar AS author_avatar,
        u.faith_rank AS author_rank, u.rank_tier AS author_tier,
        (SELECT COUNT(*) FROM video_comments vc WHERE vc.video_id = v.id) AS comment_count
      FROM videos v
      LEFT JOIN users u ON u.id = v.user_id
      WHERE v.user_id = $1  -- ✨ الشرط: فيديوهات هذا المستخدم فقط
      ORDER BY v.created_at DESC
    `, [userId]);

    // تنسيق البيانات
    const videos = rows.map(video => ({
      id: video.id,
      user_id: video.user_id,
      url: video.cloudinary_url,
      thumbnail: video.thumbnail_url,
      description: video.description,
      duration: video.duration ? parseInt(video.duration, 10) : null,
      agree: parseInt(video.agree, 10),
      disagree: parseInt(video.disagree, 10),
      comment_count: parseInt(video.comment_count, 10) || 0,
      created_at: parseInt(video.created_at, 10),
      author_name: video.author_name || "مستخدم محذوف",
      author_avatar: video.author_avatar || "https://res.cloudinary.com/dqmlhgegm/image/upload/v1760854549/WhatsApp_Image_2025-10-19_at_8.15.20_AM_njvijg.jpg",
      author_rank: video.author_rank,
      author_tier: video.author_tier,
    }));

    res.json({ ok: true, videos: videos });

  } catch (err) {
    console.error("❌ خطأ جلب فيديوهات المستخدم:", err);
    res.status(500).json({ ok: false, error: "فشل جلب الفيديوهات" });
  }
});

// --- 3. Delete a Video ---
app.delete("/api/videos/:id", auth, async (req, res) => {
  try {
    const videoId = parseInt(req.params.id);
    const userId = req.user.id; // ID of the user requesting deletion

    if (isNaN(videoId)) {
      return res.status(400).json({ error: "معرف الفيديو غير صالح" });
    }

    // Get the video owner's ID and Cloudinary public ID
    const videoRes = await pool.query(
      "SELECT user_id, cloudinary_url FROM videos WHERE id = $1",
      [videoId]
    );

    if (!videoRes.rows.length) {
      return res.status(404).json({ error: "الفيديو غير موجود" });
    }

    const videoOwnerId = videoRes.rows[0].user_id;
    const cloudinaryUrl = videoRes.rows[0].cloudinary_url;

    // Check if the user is the owner OR an admin
    let isAdmin = false;
    if (userId !== videoOwnerId) {
      const adminRes = await pool.query("SELECT is_admin FROM users WHERE id = $1", [userId]);
      isAdmin = adminRes.rows.length > 0 && adminRes.rows[0].is_admin === 1;
    }

    if (userId !== videoOwnerId && !isAdmin) {
      return res.status(403).json({ error: "🚫 غير مصرح لك بحذف هذا الفيديو" });
    }

    // --- Deletion Process ---
    // 1. Delete from PostgreSQL database (will cascade delete comments)
    const deleteRes = await pool.query("DELETE FROM videos WHERE id = $1", [videoId]);

    if (deleteRes.rowCount === 0) {
      // Should not happen if we found it earlier, but good to check
      return res.status(404).json({ error: "فشل حذف الفيديو من قاعدة البيانات (ربما حُذف تواً)" });
    }

    console.log(`🗑️ Video ${videoId} deleted from database by user ${userId}.`);

    // 2. Delete from Cloudinary (Optional but recommended)
    if (cloudinaryUrl) {
      try {
        // Extract public_id from URL (Needs careful implementation based on your URL structure)
        // Example: if URL is https://res.cloudinary.com/.../upload/v123/folder/publicid.mp4
        // The public_id would be 'folder/publicid'
        const urlParts = cloudinaryUrl.split('/');
        const publicIdWithFormat = urlParts.slice(urlParts.indexOf('upload') + 2).join('/');
        const publicId = publicIdWithFormat.substring(0, publicIdWithFormat.lastIndexOf('.'));

        if (publicId) {
          console.log(`☁️ Attempting to delete video ${publicId} from Cloudinary...`);
          // We need to specify resource_type as 'video' for deletion
          await cloudinary.uploader.destroy(publicId, { resource_type: 'video' });
          console.log(`✅ Video ${publicId} deleted from Cloudinary.`);
        }
      } catch (cloudinaryError) {
        console.error(`⚠️ Cloudinary Deletion Error for video ${videoId}:`, cloudinaryError.message);
        // Don't fail the whole request if Cloudinary deletion fails, just log it.
      }
    }

    res.json({ ok: true, message: "🗑️ تم حذف الفيديو بنجاح" });

  } catch (err) {
    console.error("❌ خطأ أثناء حذف الفيديو (API):", err);
    res.status(500).json({ error: "فشل داخلي أثناء حذف الفيديو" });
  }
});
// --- 4. Add a Comment to a Video ---
app.post("/api/videos/:id/comments", auth, async (req, res) => {
  try {
    const videoId = parseInt(req.params.id);
    const { parent_id, text } = req.body; // parent_id for replies
    const userId = req.user.id;

    if (isNaN(videoId)) {
      return res.status(400).json({ error: "معرف الفيديو غير صالح" });
    }
    if (!text || text.trim() === "") {
      return res.status(400).json({ error: "نص التعليق لا يمكن أن يكون فارغاً" });
    }

    // Check user ban/disable status
    const userRes = await pool.query("SELECT disabled, lock_until FROM users WHERE id = $1", [userId]);
    const user = userRes.rows[0];
    if (!user) return res.status(404).json({ error: "المستخدم غير موجود" });
    if (user.disabled) return res.status(403).json({ error: "🚫 حسابك معطّل. لا يمكنك التعليق." });
    if (user.lock_until && user.lock_until > Date.now()) {
        const diffH = Math.ceil((user.lock_until - Date.now()) / (1000 * 60 * 60));
        return res.status(403).json({ error: `⏳ حسابك محظور مؤقتًا (${diffH} ساعة متبقية).` });
    }

    // Check if video exists
    const videoExists = await pool.query("SELECT id FROM videos WHERE id = $1", [videoId]);
    if (!videoExists.rows.length) {
        return res.status(404).json({ error: "الفيديو غير موجود" });
    }

    const createdAt = Date.now();
    const insertRes = await pool.query(
      `INSERT INTO video_comments (video_id, user_id, parent_id, text, created_at)
       VALUES ($1, $2, $3, $4, $5)
       RETURNING id, created_at`, // Return created_at as well
      [videoId, userId, parent_id || null, text.trim(), createdAt]
    );

    const newCommentId = insertRes.rows[0].id;
    const newCommentCreatedAt = insertRes.rows[0].created_at;

    // --- Send Notification (Similar to post comments) ---
    // Get video owner ID
    const videoOwnerRes = await pool.query(`SELECT user_id FROM videos WHERE id = $1`, [videoId]);
    const videoOwnerId = videoOwnerRes.rows.length ? videoOwnerRes.rows[0].user_id : null;

    if (!parent_id) {
      // New comment on video
      if (videoOwnerId && videoOwnerId !== userId) {
        await notifyUser(
          videoOwnerId,
          "💬 تعليق جديد على الفيديو", // Title changed
          "قام أحد المستخدمين بالتعليق على الفيديو الخاص بك.", // Body changed
          "comment", // Same type? Or maybe 'video_comment'? Let's keep 'comment' for now.
          { video_id: videoId, comment_id: newCommentId, sender_id: userId } // Meta changed
        );
      }
    } else {
      // Reply to a video comment
      const parentOwnerRes = await pool.query(`SELECT user_id FROM video_comments WHERE id = $1`, [parent_id]);
      const parentOwnerId = parentOwnerRes.rows.length ? parentOwnerRes.rows[0].user_id : null;
      if (parentOwnerId && parentOwnerId !== userId) {
        await notifyUser(
          parentOwnerId,
          "↩️ رد على تعليقك", // Same title
          "قام أحد المستخدمين بالرد على تعليقك على الفيديو.", // Body slightly changed
          "reply", // Same type
          { video_id: videoId, parent_id, comment_id: newCommentId, sender_id: userId } // Meta changed
        );
      }
    }

    res.status(201).json({
      ok: true,
      id: newCommentId,
      created_at: parseInt(newCommentCreatedAt, 10), // Send back timestamp
      message: "💬 تم إضافة التعليق بنجاح"
    });

  } catch (err) {
    console.error("❌ خطأ أثناء إضافة تعليق على الفيديو:", err);
    res.status(500).json({ error: "فشل إنشاء التعليق" });
  }
});
// --- 5. Get Comments for a Video ---
app.get("/api/videos/:id/comments", async (req, res) => {
  try {
    const videoId = parseInt(req.params.id);

    if (isNaN(videoId)) {
      return res.status(400).json({ error: "معرف الفيديو غير صالح" });
    }

    // Check if video exists
    const videoExists = await pool.query("SELECT id FROM videos WHERE id = $1", [videoId]);
    if (!videoExists.rows.length) {
        return res.status(404).json({ error: "الفيديو غير موجود" });
    }

    // Join video_comments with users table
    const { rows } = await pool.query(`
      SELECT
        vc.*, -- Select all columns from video_comments
        u.name AS author_name,
        u.avatar AS author_avatar,
        u.faith_rank AS author_rank, -- Include rank info
        u.rank_tier AS author_tier   -- Include rank tier
      FROM video_comments vc
      LEFT JOIN users u ON u.id = vc.user_id
      WHERE vc.video_id = $1
      ORDER BY vc.created_at ASC -- Order comments chronologically
    `, [videoId]);

    // Convert timestamps and ensure numbers are numbers
    const comments = rows.map(comment => ({
      id: comment.id,
      video_id: comment.video_id,
      user_id: comment.user_id,
      parent_id: comment.parent_id,
      text: comment.text,
      agree: parseInt(comment.agree, 10),
      disagree: parseInt(comment.disagree, 10),
      created_at: parseInt(comment.created_at, 10),
      author_name: comment.author_name || "مستخدم محذوف",
      author_avatar: comment.author_avatar || "https://res.cloudinary.com/dqmlhgegm/image/upload/v1760854549/WhatsApp_Image_2025-10-19_at_8.15.20_AM_njvijg.jpg",
      author_rank: comment.author_rank,
      author_tier: comment.author_tier,
    }));

    res.json({ ok: true, comments: comments });

  } catch (err) {
    console.error("❌ خطأ في جلب تعليقات الفيديو:", err);
    res.status(500).json({ ok: false, error: "فشل في جلب التعليقات" });
  }
});
// ====== إنشاء تعليق جديد ======  
app.post("/api/comments", auth, async (req, res) => {  
  try {  
    const { post_id, parent_id, text } = req.body;  
    const userId = req.user.id;  
  
    if (!text || !post_id)  
      return res.status(400).json({ error: "النص والمعرف مطلوبان" });  
  
    const userRes = await pool.query("SELECT disabled, lock_until FROM users WHERE id = $1", [userId]);  
    const user = userRes.rows[0];  
    if (!user)  
      return res.status(404).json({ error: "المستخدم غير موجود" });  
  
    if (user.disabled)  
      return res.status(403).json({ error: "🚫 حسابك معطّل. لا يمكنك التعليق." });  
  
    if (user.lock_until && user.lock_until > Date.now()) {  
      const diffH = Math.ceil((user.lock_until - Date.now()) / (1000 * 60 * 60));  
      return res.status(403).json({ error: `⏳ حسابك محظور مؤقتًا (${diffH} ساعة متبقية).` });  
    }  
  
    const createdAt = Date.now();  
    const insertRes = await pool.query(  
      `INSERT INTO comments (post_id, user_id, parent_id, text, created_at)  
       VALUES ($1, $2, $3, $4, $5)  
       RETURNING id`,  
      [post_id, userId, parent_id || null, text, createdAt]  
    );  
  
    const commentId = insertRes.rows[0].id;  
  
    // 📢 إشعار لصاحب المنشور أو التعليق  
    if (!parent_id) {  
      // تعليق جديد على منشور  
      const postOwner = await pool.query(`SELECT user_id FROM posts WHERE id = $1`, [post_id]);  
      if (postOwner.rows.length && postOwner.rows[0].user_id !== userId) {  
        await notifyUser(  
          postOwner.rows[0].user_id,  
          "💬 تعليق جديد على منشورك",  
          "قام أحد المستخدمين بالتعليق على منشورك.",  
          "comment",  
          { post_id, comment_id: commentId, sender_id: userId }  
        );  
      }  
    } else {  
      // رد على تعليق  
      const parentOwner = await pool.query(`SELECT user_id FROM comments WHERE id = $1`, [parent_id]);  
      if (parentOwner.rows.length && parentOwner.rows[0].user_id !== userId) {  
        await notifyUser(  
          parentOwner.rows[0].user_id,  
          "↩️ رد على تعليقك",  
          "قام أحد المستخدمين بالرد على تعليقك.",  
          "reply",  
          { post_id, parent_id, comment_id: commentId, sender_id: userId }  
        );  
      }  
    }
    // 🧩 جلب اسم المرسل لواجهة العميل
    const nameRes = await pool.query("SELECT name FROM users WHERE id = $1", [userId]);
    const fromUser = nameRes.rows.length ? nameRes.rows[0].name : "مستخدم";

   res.json({
  ok: true,
  id: insertRes.rows[0].id,
  created_at: insertRes.rows[0].created_at, // ← أضف هذا
  message: "💬 تم إضافة التعليق بنجاح"
});
  } catch (err) {
    console.error("❌ خطأ أثناء إضافة التعليق:", err);
    res.status(500).json({ error: "فشل إنشاء التعليق" });
  }
});

// ====== جلب جميع التعليقات لمنشور معين ======
app.get("/api/comments/:postId", async (req, res) => {
  try {
    const postId = req.params.postId;
    const { rows } = await pool.query(`
      SELECT 
        c.*, 
        u.name AS author_name, 
        u.avatar AS author_avatar,
        u.faith_rank AS author_rank,
        u.rank_tier AS author_tier,
        u.flames AS author_flames
      FROM comments c
      LEFT JOIN users u ON u.id = c.user_id
      WHERE c.post_id = $1
      ORDER BY c.created_at ASC
    `, [postId]);

    // ✨ التحويل إلى أرقام
    const comments = rows.map(comment => ({
      ...comment,
      created_at: parseInt(comment.created_at, 10)
    }));

    res.json({ ok: true, comments: comments });
  } catch (err) {
    console.error("❌ خطأ في جلب التعليقات:", err);
    res.status(500).json({ error: "فشل في جلب التعليقات" });
  }
});
// ====== نظام تفاعل متطور (يدعم المنشورات والفيديوهات وتعليقاتهما) ======
app.post("/api/react", auth, async (req, res) => {
  try {
    // 👇 نقبل أنواع جديدة: video, video_comment
    const { type, targetId, action } = req.body; // type = post | comment | video | video_comment
    const userId = req.user.id;

    if (!type || !targetId || !["agree", "disagree"].includes(action)) {
      return res.status(400).json({ error: "طلب غير صالح (type, targetId, action required)" });
    }

    // Check user ban/disable status
    const userRes = await pool.query("SELECT disabled, lock_until FROM users WHERE id = $1", [userId]);
    const user = userRes.rows[0];
    if (!user) return res.status(404).json({ error: "المستخدم غير موجود" });
    if (user.disabled) return res.status(403).json({ error: "🚫 حسابك معطّل. لا يمكنك التفاعل." });
    if (user.lock_until && user.lock_until > Date.now()) {
        const diffH = Math.ceil((user.lock_until - Date.now()) / (1000 * 60 * 60));
        return res.status(403).json({ error: `⏳ حسابك محظور مؤقتًا (${diffH} ساعة متبقية).` });
    }

    // 👇 تحديد الجدول المستهدف بناءً على النوع
    let targetTable = null;
    switch (type) {
      case "post":
        targetTable = "posts";
        break;
      case "comment":
        targetTable = "comments";
        break;
      case "video":
        targetTable = "videos";
        break;
      case "video_comment":
        targetTable = "video_comments";
        break;
      default:
        return res.status(400).json({ error: "نوع الهدف غير معروف" });
    }

    // --- نفس منطق التفاعل السابق (إضافة/إزالة/تبديل) ---

    const client = await pool.connect(); // Use transaction for consistency
    try {
      await client.query('BEGIN');

      // Check existing reaction
      const reactRes = await client.query(
        "SELECT id, action FROM reactions WHERE user_id = $1 AND target_type = $2 AND target_id = $3",
        [userId, type, targetId]
      );

      const oppositeAction = action === "agree" ? "disagree" : "agree";
      let operation = null; // null, 'insert', 'delete', 'update'

      if (reactRes.rows.length === 0) {
        // الحالة 1: المستخدم لم يصوت من قبل -> إضافة تفاعل جديد
        await client.query(
          "INSERT INTO reactions (user_id, target_type, target_id, action) VALUES ($1, $2, $3, $4)",
          [userId, type, targetId, action]
        );
        await client.query(
          `UPDATE ${targetTable} SET ${action} = ${action} + 1 WHERE id = $1`,
          [targetId]
        );
        operation = 'insert';

      } else {
        const existingReaction = reactRes.rows[0];
        if (existingReaction.action === action) {
          // الحالة 2: ضغط نفس الزر مرة ثانية -> حذف التصويت
          await client.query("DELETE FROM reactions WHERE id = $1", [existingReaction.id]);
          await client.query(
            `UPDATE ${targetTable} SET ${action} = GREATEST(${action} - 1, 0) WHERE id = $1`, // Use GREATEST to prevent negative counts
            [targetId]
          );
          operation = 'delete';
        } else {
          // الحالة 3: غيّر رأيه -> تحديث التفاعل وتحديث العدادات
          await client.query("UPDATE reactions SET action = $1 WHERE id = $2", [action, existingReaction.id]);
          await client.query(
            `UPDATE ${targetTable}
             SET ${action} = ${action} + 1,
                 ${oppositeAction} = GREATEST(${oppositeAction} - 1, 0)
             WHERE id = $1`,
            [targetId]
          );
          operation = 'update';
        }
      }

      // --- جلب القيم الجديدة وصاحب المحتوى للإشعار ---
      const updatedCountsRes = await client.query(
        `SELECT agree, disagree, user_id FROM ${targetTable} WHERE id = $1`,
        [targetId]
      );
      const updatedCounts = updatedCountsRes.rows[0] || { agree: 0, disagree: 0, user_id: null };
      const targetOwnerId = updatedCounts.user_id;

      await client.query('COMMIT'); // Commit transaction

      res.json({
        ok: true,
        agree: updatedCounts.agree,
        disagree: updatedCounts.disagree,
        // (يمكن إزالة from_user و target_user_id إذا لم تعد الواجهة تستخدمها مباشرة)
      });

      // --- إرسال الإشعار (إذا كان تفاعل إيجابي ولم يكن تفاعل مع النفس) ---
      if (action === 'agree' && operation !== 'delete' && targetOwnerId && targetOwnerId !== userId) {
          let notifTitle = "👍 تفاعل جديد";
          let notifBody = "قام أحد المستخدمين بالتفاعل بالإيجاب.";
          let meta = { target_type: type, target_id: targetId, sender_id: userId };

          if (type === 'post') { notifTitle = "👍 تفاعل مع منشورك"; notifBody = "قام أحد المستخدمين بالإعجاب بمنشورك."; meta.post_id = targetId; }
          else if (type === 'comment') { notifTitle = "👍 تفاعل مع تعليقك"; notifBody = "قام أحد المستخدمين بالإعجاب بتعليقك."; meta.comment_id = targetId; }
          else if (type === 'video') { notifTitle = "👍 تفاعل مع الفيديو الخاص بك"; notifBody = "قام أحد المستخدمين بالإعجاب بالفيديو الخاص بك."; meta.video_id = targetId; }
          else if (type === 'video_comment') { notifTitle = "👍 تفاعل مع تعليقك على الفيديو"; notifBody = "قام أحد المستخدمين بالإعجاب بتعليقك على الفيديو."; meta.video_comment_id = targetId; }

          // تأكد من تمرير البيانات الصحيحة لـ notifyUser
          await notifyUser(targetOwnerId, notifTitle, notifBody, "reaction", meta);
      }

    } catch (e) {
      await client.query('ROLLBACK'); // Rollback on error
      console.error("❌ خطأ Transaction في نظام التفاعل:", e);
      res.status(500).json({ error: "حدث خطأ أثناء معالجة التفاعل" });
    } finally {
      client.release(); // Release client back to pool
    }

  } catch (err) {
    // Handle errors outside transaction (like initial user check)
    console.error("❌ خطأ عام في نظام التفاعل:", err);
    res.status(500).json({ error: "حدث خطأ عام" });
  }
});
// ====== تعديل منشور ======
app.put("/api/posts/:id", auth, upload.single("image"), async (req, res) => {
  try {
    const postId = req.params.id;
    const userId = req.user.id;
    const { text } = req.body;

    const postRes = await pool.query("SELECT * FROM posts WHERE id = $1", [postId]);
    if (!postRes.rows.length)
      return res.status(404).json({ error: "المنشور غير موجود" });

    const post = postRes.rows[0];
    if (post.user_id !== userId)
      return res.status(403).json({ error: "❌ لا يمكنك تعديل منشور غيرك" });

    let imageUrl = post.image; // القيمة الافتراضية هي الصورة القديمة

    // ✨ منطق الرفع الجديد إلى Cloudinary
    if (req.file) {
      try {
        const result = await cloudinary.uploader.upload(req.file.path, {
          folder: "heq_mojtama/posts",
          transformation: [
            { width: 1080, crop: "limit" }, // تحديد أقصى عرض للصورة
            { fetch_format: "auto", quality: "auto" }
          ]
        });
        imageUrl = result.secure_url; // تحديث الرابط بالصورة الجديدة
        fs.unlinkSync(req.file.path); // حذف الملف المؤقت
      } catch (uploadError) {
        console.error("❌ خطأ أثناء تعديل صورة المنشور:", uploadError);
        return res.status(500).json({ error: "فشل في معالجة الصورة الجديدة" });
      }
    }

    await pool.query(
      "UPDATE posts SET text = $1, image = $2 WHERE id = $3",
      [text || post.text, imageUrl, postId]
    );

    res.json({ ok: true, message: "✅ تم تعديل المنشور بنجاح", image: imageUrl });
  } catch (err) {
    console.error("❌ خطأ أثناء تعديل المنشور:", err);
    res.status(500).json({ error: "فشل تعديل المنشور" });
  }
});

// ====== حذف منشور ======
app.delete("/api/posts/:id", auth, async (req, res) => {
  try {
    const postId = req.params.id;
    const userId = req.user.id;

    const postRes = await pool.query("SELECT * FROM posts WHERE id = $1", [postId]);
    if (!postRes.rows.length)
      return res.status(404).json({ error: "المنشور غير موجود" });

    const post = postRes.rows[0];
    if (post.user_id !== userId)
      return res.status(403).json({ error: "❌ لا يمكنك حذف منشور غيرك" });

    await pool.query("DELETE FROM posts WHERE id = $1", [postId]);

    res.json({ ok: true, message: "🗑️ تم حذف المنشور بنجاح" });
  } catch (err) {
    console.error("❌ خطأ أثناء حذف المنشور:", err);
    res.status(500).json({ error: "فشل حذف المنشور" });
  }
});

app.post("/api/report", auth, async (req, res) => {
  try {
    const { post_id, reason } = req.body;
    const userId = req.user.id;

    if (!post_id || !reason)
      return res.status(400).json({ error: "يجب إدخال سبب الإبلاغ ومعرف المنشور" });

    const createdAt = Date.now();
    await pool.query(
      "INSERT INTO reports (user_id, post_id, reason, created_at) VALUES ($1, $2, $3, $4)",
      [userId, post_id, reason, createdAt]
    );

    res.json({ ok: true, message: "🚩 تم إرسال البلاغ بنجاح" });
  } catch (err) {
    console.error("❌ فشل إرسال البلاغ:", err);
    res.status(500).json({ error: "فشل إرسال البلاغ" });
  }
});

// ====== فحص صلاحية المطور ======
app.get("/api/check_admin", auth, async (req, res) => {
  try {
    const email = req.user.email;
    const { rows } = await pool.query("SELECT is_admin FROM users WHERE email = $1", [email]);
    if (!rows.length || rows[0].is_admin !== 1)
      return res.status(403).json({ ok: false, message: "ليس مطوراً" });

    res.json({ ok: true, message: "المستخدم مطور معتمد ✅" });
  } catch (err) {
    console.error("❌ check_admin:", err);
    res.status(500).json({ error: "خطأ في قاعدة البيانات" });
  }
});

// ====== إدارة المستخدمين ======
app.get("/api/admin/users", auth, requireAdmin, async (req, res) => {
  try {
    const { rows } = await pool.query(`
      SELECT id, email, name, is_admin, verified, disabled, failed_attempts, lock_until, joined_at
      FROM users
      ORDER BY joined_at DESC
    `);
    res.json({ ok: true, users: rows });
  } catch (err) {
    res.status(500).json({ error: "خطأ في قاعدة البيانات" });
  }
});

// حظر مؤقت
app.post("/api/admin/users/:id/ban", auth, requireAdmin, async (req, res) => {
  try {
    const uid = +req.params.id;
    const hours = Math.max(1, +req.body.hours || 12);
    const reason = (req.body.reason || "مخالفة القواعد").trim();
    const lockUntil = Date.now() + hours * 3600 * 1000;

    const result = await pool.query("UPDATE users SET lock_until = $1 WHERE id = $2", [lockUntil, uid]);
    if (result.rowCount === 0)
      return res.status(404).json({ error: "فشل الحظر أو المستخدم غير موجود" });

    await notifyUser(uid, "تم حظرك مؤقتًا", `تم حظر حسابك لمدة ${hours} ساعة.\nالسبب: ${reason}`, "moderation");
    res.json({ ok: true, message: "تم الحظر المؤقت وإرسال إشعار" });
  } catch (err) {
    console.error("❌ ban:", err);
    res.status(500).json({ error: "فشل الحظر" });
  }
});

// رفع الحظر
app.post("/api/admin/users/:id/unban", auth, requireAdmin, async (req, res) => {
  try {
    const uid = +req.params.id;
    const result = await pool.query("UPDATE users SET lock_until = 0, failed_attempts = 0 WHERE id = $1", [uid]);
    if (result.rowCount === 0)
      return res.status(404).json({ error: "فشل رفع الحظر أو المستخدم غير موجود" });

    await notifyUser(uid, "تم رفع الحظر", "أصبح حسابك فعّالًا من جديد.", "moderation");
    res.json({ ok: true });
  } catch (err) {
    res.status(500).json({ error: "فشل رفع الحظر" });
  }
});

// تعطيل حساب نهائي
app.post("/api/admin/users/:id/disable", auth, requireAdmin, async (req, res) => {
  try {
    const uid = +req.params.id;
    const reason = (req.body.reason || "مخالفة القواعد").trim();
    const result = await pool.query("UPDATE users SET disabled = 1 WHERE id = $1", [uid]);
    if (result.rowCount === 0)
      return res.status(404).json({ error: "فشل التعطيل أو المستخدم غير موجود" });

    await notifyUser(uid, "تم تعطيل حسابك", `السبب: ${reason}`, "moderation");
    res.json({ ok: true });
  } catch (err) {
    res.status(500).json({ error: "فشل التعطيل" });
  }
});

// ✅ تمكين حساب (فك التعطيل)
app.post("/api/admin/users/:id/enable", auth, requireAdmin, async (req, res) => {
  try {
    const uid = +req.params.id;
    const result = await pool.query("UPDATE users SET disabled = 0 WHERE id = $1", [uid]);
    if (result.rowCount === 0)
      return res.status(404).json({ error: "فشل تمكين الحساب أو المستخدم غير موجود" });

    await notifyUser(uid, "✅ تم تفعيل حسابك من جديد", "يمكنك الآن استخدام المجتمع بحرية.", "moderation");
    res.json({ ok: true, message: "✅ تم تمكين الحساب بنجاح" });
  } catch (err) {
    res.status(500).json({ error: "فشل تمكين الحساب" });
  }
});

// ترقية إلى مطور
app.post("/api/admin/users/:id/promote", auth, requireAdmin, async (req, res) => {
  try {
    const uid = +req.params.id;
    const result = await pool.query("UPDATE users SET is_admin = 1 WHERE id = $1", [uid]);
    if (result.rowCount === 0)
      return res.status(404).json({ error: "فشل الترقية أو المستخدم غير موجود" });

    await notifyUser(uid, "ترقية حسابك", "🎉 تمت ترقيتك إلى مطوّر النظام", "system");
    res.json({ ok: true });
  } catch (err) {
    res.status(500).json({ error: "فشل الترقية" });
  }
});

// ====== إدارة المنشورات ======
app.get("/api/admin/posts", auth, requireAdmin, async (req, res) => {
  try {
    const { rows } = await pool.query(`
      SELECT p.id, p.user_id, u.name AS author_name, p.text, p.image, p.agree, p.disagree, p.created_at
      FROM posts p LEFT JOIN users u ON u.id = p.user_id
      ORDER BY p.created_at DESC
    `);
    res.json({ ok: true, posts: rows });
  } catch (err) {
    res.status(500).json({ error: "فشل جلب المنشورات" });
  }
});

app.post("/api/admin/posts/:id/delete", auth, requireAdmin, async (req, res) => {
  try {
    const pid = +req.params.id;
    const reason = (req.body.reason || "مخالفة القواعد").trim();

    const { rows } = await pool.query("SELECT user_id FROM posts WHERE id = $1", [pid]);
    if (!rows.length)
      return res.status(404).json({ error: "المنشور غير موجود" });

    const owner = rows[0].user_id;
    await pool.query("DELETE FROM posts WHERE id = $1", [pid]);

    await notifyUser(owner, "تم حذف منشورك", `السبب: ${reason}`, "moderation", { post_id: pid });
    res.json({ ok: true, message: "تم حذف المنشور وإشعار صاحبه" });
  } catch (err) {
    res.status(500).json({ error: "فشل حذف المنشور" });
  }
});

// ====== إدارة البلاغات ======
app.get("/api/admin/reports", auth, requireAdmin, async (req, res) => {
  try {
    const { rows } = await pool.query(`
      SELECT r.*, u.name AS reporter_name, p.text AS post_text
      FROM reports r
      LEFT JOIN users u ON u.id = r.user_id
      LEFT JOIN posts p ON p.id = r.post_id
      ORDER BY r.created_at DESC
    `);
    res.json({ ok: true, reports: rows });
  } catch (err) {
    res.status(500).json({ error: "فشل جلب البلاغات" });
  }
});

app.post("/api/admin/reports/:id/resolve", auth, requireAdmin, async (req, res) => {
  try {
    const rid = +req.params.id;
    const action = (req.body.action || "تم التحقق").trim();
    const note = (req.body.note || "").trim();
    const resolverId = req.user.id;

    const { rows } = await pool.query("SELECT user_id FROM reports WHERE id = $1", [rid]);
    if (!rows.length)
      return res.status(404).json({ error: "البلاغ غير موجود" });

    const reporterId = rows[0].user_id;
    await pool.query(
      `UPDATE reports 
       SET status = 'resolved', resolution_note = $1, resolved_at = $2, resolver_id = $3 
       WHERE id = $4`,
      [note || action, Date.now(), resolverId, rid]
    );

    await notifyUser(reporterId, "تمت معالجة بلاغك", `النتيجة: ${action}\n${note}`, "moderation");
    res.json({ ok: true, message: "تم إنهاء البلاغ وإشعار المبلّغ" });
  } catch (err) {
    res.status(500).json({ error: "فشل تحديث البلاغ" });
  }
});
// =======================================
// ====== إدارة الفيديوهات (للمطور) ======
// =======================================

// 1. جلب قائمة الفيديوهات (نسخة مبسطة)
app.get("/api/admin/videos", auth, requireAdmin, async (req, res) => {
  try {
    const { rows } = await pool.query(`
      SELECT 
        v.id, 
        u.name AS author_name, 
        v.cloudinary_url, 
        v.description, 
        v.created_at
      FROM videos v
      LEFT JOIN users u ON u.id = v.user_id
      ORDER BY v.created_at DESC
    `);
    res.json({ ok: true, videos: rows });
  } catch (err) {
    res.status(500).json({ error: "فشل جلب الفيديوهات" });
  }
});

// 2. حذف فيديو (مع إرسال سبب)
app.post("/api/admin/videos/:id/delete", auth, requireAdmin, async (req, res) => {
  try {
    const vid = +req.params.id;
    const reason = (req.body.reason || "مخالفة القواعد").trim();

    // جلب بيانات الفيديو (لإشعار المالك وحذف الكلاود)
    const { rows } = await pool.query("SELECT user_id, cloudinary_url FROM videos WHERE id = $1", [vid]);
    if (!rows.length)
      return res.status(404).json({ error: "الفيديو غير موجود" });

    const owner = rows[0].user_id;
    const cloudinaryUrl = rows[0].cloudinary_url;

    // 1. حذف من قاعدة البيانات (سيؤدي لحذف التعليقات المرتبطة)
    await pool.query("DELETE FROM videos WHERE id = $1", [vid]);

    // 2. إشعار صاحب الفيديو
    await notifyUser(owner, "تم حذف الفيديو الخاص بك", `السبب: ${reason}`, "moderation", { video_id: vid });

    // 3. (مهم) حذف من Cloudinary
    if (cloudinaryUrl) {
      try {
        const urlParts = cloudinaryUrl.split('/');
        const publicIdWithFormat = urlParts.slice(urlParts.indexOf('upload') + 2).join('/');
        const publicId = publicIdWithFormat.substring(0, publicIdWithFormat.lastIndexOf('.'));

        if (publicId) {
          await cloudinary.uploader.destroy(publicId, { resource_type: 'video' });
          console.log(`✅ Admin deleted video ${publicId} from Cloudinary.`);
        }
      } catch (cloudinaryError) {
        console.error(`⚠️ Admin Cloudinary Deletion Error for video ${vid}:`, cloudinaryError.message);
      }
    }

    res.json({ ok: true, message: "تم حذف الفيديو وإشعار صاحبه" });
  } catch (err) {
    res.status(500).json({ error: "فشل حذف الفيديو" });
  }
});
// ====== إرسال إشعار عام أو موجه ======
app.post("/api/admin/notify", auth, requireAdmin, async (req, res) => {
  try {
    const { to_user_id = null, title, body, type = "broadcast", meta = {} } = req.body || {};
    if (!title || !body) return res.status(400).json({ error: "العنوان والمحتوى مطلوبان" });
    await notifyUser(to_user_id ? +to_user_id : null, title, body, type, meta);
    res.json({ ok: true, message: "تم إرسال الإشعار بنجاح" });
  } catch (err) {
    console.error("admin/notify:", err);
    res.status(500).json({ error: "فشل إرسال الإشعار" });
  }
});

// ====== جلب إشعارات المستخدم ======
app.get("/api/notifications", auth, async (req, res) => {
  try {
    const uid = req.user.id;
    const { rows } = await pool.query(
      `SELECT * FROM notifications
       WHERE to_user_id IS NULL OR to_user_id = $1
       ORDER BY created_at DESC
       LIMIT 100`,
      [uid]
    );
    res.json({ ok: true, notifications: rows });
  } catch (err) {
    console.error("get /notifications:", err);
    res.status(500).json({ error: "فشل جلب الإشعارات" });
  }
});

// 💻 3) المطور يجلب كل المحادثات مع المستخدمين
app.get("/api/admin/chat/users", auth, requireAdmin, async (_req, res) => {
  try {
    const { rows } = await pool.query(
      `SELECT DISTINCT u.id, u.name, u.email, u.avatar
       FROM users u
       JOIN system_chat s ON s.user_id = u.id
       ORDER BY u.name ASC`
    );
    res.json({ ok: true, users: rows });
  } catch (err) {
    console.error("admin/chat/users:", err);
    res.status(500).json({ error: "فشل جلب المستخدمين" });
  }
});

// 📜 4) المطور يفتح محادثة مستخدم محدد
app.get("/api/admin/chat/:user_id", auth, requireAdmin, async (req, res) => {
  try {
    const uid = +req.params.user_id;
    const { rows } = await pool.query(
      `SELECT * FROM system_chat WHERE user_id = $1 ORDER BY created_at ASC`,
      [uid]
    );
    res.json({ ok: true, messages: rows });
  } catch (err) {
    console.error("admin/chat/:user_id:", err);
    res.status(500).json({ error: "فشل جلب المحادثة" });
  }
});

// 📨 5) المطور يرد على مستخدم
app.post("/api/admin/chat/reply", auth, requireAdmin, async (req, res) => {
  try {
    const { to_user_id, message } = req.body;
    if (!to_user_id || !message?.trim())
      return res.status(400).json({ error: "بيانات ناقصة" });

    const createdAt = Date.now();
    await pool.query(
      `INSERT INTO system_chat (user_id, message, from_admin, created_at)
       VALUES ($1, $2, 1, $3)`,
      [+to_user_id, message.trim(), createdAt]
    );

    await notifyUser(
      +to_user_id,
      "💬 رد من النظام",
      message.trim(),
      "system",
      { chat_reply: true }
    );

    res.json({ ok: true, message: "✅ تم إرسال الرد للمستخدم" });
  } catch (err) {
    console.error("admin/chat/reply:", err);
    res.status(500).json({ error: "فشل إرسال الرد" });
  }
});

// ====== تعليم جميع إشعارات المستخدم كمقروءة ======
app.post("/api/notifications/read_all", auth, async (req, res) => {
  try {
    const uid = req.user.id;
    const result = await pool.query(
      `UPDATE notifications SET is_read = 1 WHERE to_user_id = $1`,
      [uid]
    );
    res.json({
      ok: true,
      message: `✅ تم تعليم ${result.rowCount} إشعار كمقروء.`,
    });
  } catch (err) {
    console.error("notifications/read_all:", err);
    res.status(500).json({ error: "فشل تحديث حالة الإشعارات" });
  }
});

// ====== 🧩 نظام المحادثة الإدارية (System Chat) ======

// 📨 1) المستخدم يرسل رسالة للمطور
app.post("/api/chat/send", auth, async (req, res) => {
  try {
    const { message } = req.body;
    const userId = req.user.id;
    const msg = (message || "").trim();

    if (!msg) return res.status(400).json({ error: "الرسالة فارغة" });
    if (msg.length > 2000) return res.status(400).json({ error: "الرسالة طويلة جدًا (الحد الأقصى 2000 حرف)" });

    const createdAt = Date.now();
    await pool.query(
      `INSERT INTO system_chat (user_id, message, from_admin, created_at)
       VALUES ($1, $2, 0, $3)`,
      [userId, msg, createdAt]
    );

    res.json({ ok: true, message: "✅ تم إرسال الرسالة للمطور" });
  } catch (err) {
    console.error("chat/send:", err);
    res.status(500).json({ error: "فشل إرسال الرسالة" });
  }
});

// 💬 2) المستخدم يجلب سجل المحادثة الخاص به
app.get("/api/chat/history", auth, async (req, res) => {
  try {
    const userId = req.user.id;
    const { rows } = await pool.query(
      `SELECT * FROM system_chat WHERE user_id = $1 ORDER BY created_at ASC`,
      [userId]
    );
    res.json({ ok: true, messages: rows });
  } catch (err) {
    console.error("chat/history:", err);
    res.status(500).json({ error: "فشل جلب المحادثة" });
  }
});

// ====== 📬 إنشاء إشعار من واجهة المستخدم ======
app.post("/api/notifications", auth, async (req, res) => {
  try {
    const { to_user_id, title, body, type = "system", meta = {} } = req.body;
    const senderId = req.user.id;
    if (!to_user_id || !body) {
      return res.status(400).json({ error: "الحقول المطلوبة ناقصة" });
    }
    await notifyUser(+to_user_id, title || "إشعار جديد", body, type, { ...meta, sender_id: senderId });
    res.json({ ok: true, message: "✅ تم إرسال الإشعار بنجاح" });
  } catch (err) {
    console.error("post /notifications:", err);
    res.status(500).json({ error: "فشل إرسال الإشعار" });
  }
});

// =======================================
// ====== جلب بيانات أي مستخدم عامة (مع بيانات الرفيق) ======
// =======================================
app.get("/api/users/:id", async (req, res) => {
  const targetId = parseInt(req.params.id);
  if (isNaN(targetId)) {
    return res.status(400).json({ error: "معرف مستخدم غير صالح." });
  }

  try {
    // الاستعلام الآمن مع COALESCE للتعامل مع قيم الـ NULL في جدول companion
    const { rows } = await pool.query(
      `SELECT
          u.id, u.heq_id, u.email, u.name, u.bio, u.avatar, u.country, u.residence, u.age, u.gender, 
          u.joined_at, u.display_count, u.flames, u.faith_rank, u.last_faith_activity, u.rank_tier, 
          u.show_email,

          -- بيانات الرفيق (القيم الافتراضية)
          COALESCE(c.xp, 0) AS xp, 
          COALESCE(c.level, 1) AS level, 
          COALESCE(c.evolution_stage, '1') AS evolution_stage, -- ✅ نستخدم 1 كقيمة افتراضية (رقم)
          COALESCE(c.current_companion, 'phoenix') AS current_companion, 
          
          -- لا نرسل visits_count هنا لحماية الخصوصية
          
          -- حساب XP اللازمة للمستوى التالي
          (CASE 
              WHEN COALESCE(c.level, 1) < 10 THEN (COALESCE(c.level, 1) * 100) 
              WHEN COALESCE(c.level, 1) = 10 THEN 1000 
              ELSE 1000 
          END) AS xp_to_next_level 
      FROM users u
      LEFT JOIN companion c ON u.id = c.user_id
      WHERE u.id = $1`,
      [targetId]
    );

    if (!rows.length) {
      return res.status(404).json({ error: "لم يتم العثور على المستخدم." });
    }

    const user = rows[0];

    // تجميع بيانات الرفيق داخل كائن 'companion'
    const companionData = {
        xp: user.xp,
        level: user.level,
        evolution_stage: user.evolution_stage,
        visits_count: 0, // ⚠️ القيمة دائماً صفر للملفات العامة
        current_companion: user.current_companion,
        xp_to_next_level: user.xp_to_next_level,
        xp_required: user.xp_to_next_level - user.xp,
    };
    
    // إخفاء البريد إذا لم يختر المستخدم إظهاره
    const safeEmail = user.show_email ? user.email : "مخفي";

    return res.json({ 
        ok: true,
        user: {
            id: user.id,
            heq_id: user.heq_id,
            email: safeEmail,
            name: user.name,
            bio: user.bio,
            avatar: user.avatar,
            country: user.country,
            residence: user.residence,
            age: user.age,
            gender: user.gender,
            joined_at: parseInt(user.joined_at, 10),
            show_email: user.show_email,
            faith_rank: user.faith_rank,
            flames: user.flames,
            rank_tier: user.rank_tier,
            // 🔥 إضافة بيانات الرفيق هنا
            companion: companionData
        }
    });

  } catch (err) {
    console.error("❌ خطأ أثناء جلب بيانات المستخدم (/api/users/:id):", err);
    res.status(500).json({ error: "فشل داخلي في الخادم أثناء جلب بيانات المستخدم." });
  }
});
// =========================================
// 🔍 البحث عن المستخدمين بالاسم أو HEQ-ID
// =========================================
app.get("/api/search", auth, async (req, res) => {
  try {
    const q = (req.query.query || "").trim();
    if (!q) return res.json({ ok: false, error: "الكلمة فارغة" });

    const likeQuery = `%${q}%`;
    const { rows } = await pool.query(
      `SELECT id, heq_id, name, avatar
       FROM users
       WHERE name ILIKE $1 OR heq_id ILIKE $2
       LIMIT 5`,
      [likeQuery, likeQuery]
    );

    if (!rows || rows.length === 0)
      return res.json({ ok: true, users: [] });

    const cleanUsers = rows.map(u => ({
      id: u.id,
      heq_id: u.heq_id,
      name: u.name || "مستخدم بدون اسم",
      avatar: u.avatar || "assets/default-avatar.png"
    }));

    return res.json({ ok: true, users: cleanUsers });
  } catch (err) {
    console.error("❌ خطأ أثناء البحث:", err);
    res.status(500).json({ ok: false, error: "خطأ في قاعدة البيانات" });
  }
});
// =======================================
// 🤝 نظام الوصل الحقيقي بين المستخدمين (PostgreSQL)
// =======================================

// 🔹 1. فحص الحالة الحالية بين المستخدمين
app.get("/api/connect/status/:targetId", auth, async (req, res) => {
  try {
    const userId = req.user.id;
    const targetId = +req.params.targetId;

    if (userId === targetId)
      return res.json({ status: "self", direction: "self" });

    const { rows } = await pool.query(
      `SELECT * FROM connections 
       WHERE (user_id=$1 AND target_id=$2) OR (user_id=$2 AND target_id=$1)
       LIMIT 1`,
      [userId, targetId]
    );

    if (!rows.length)
      return res.json({ status: "none", direction: "none" });

    const row = rows[0];
    let direction = "none";
    if (row.user_id === userId && row.target_id === targetId) direction = "outgoing";
    else if (row.user_id === targetId && row.target_id === userId) direction = "incoming";

    res.json({
      status: row.status,
      direction,
      requester_id: row.user_id,
      target_id: row.target_id
    });
  } catch (err) {
    console.error("connect/status:", err);
    res.status(500).json({ error: "خطأ في قاعدة البيانات" });
  }
});

// 🔹 2. إرسال طلب وصل
app.post("/api/connect", auth, async (req, res) => {
  try {
    const userId = req.user.id;
    const { target_id } = req.body;
    const targetId = +target_id;
    if (!targetId || userId === targetId)
      return res.status(400).json({ error: "طلب غير صالح" });

    const now = Date.now();

    await pool.query(
      `INSERT INTO connections (user_id, target_id, status, created_at, updated_at)
       VALUES ($1, $2, 'pending', $3, $3)
       ON CONFLICT (user_id, target_id) DO UPDATE SET 
         status='pending', updated_at=$3`,
      [userId, targetId, now]
    );

    await notifyUser(
      targetId,
      "🔗 طلب وصل جديد",
      "قام أحد المستخدمين بإرسال طلب وصل إليك.",
      "connect_request",
      { sender_id: userId }
    );

    res.json({ ok: true, message: "✅ تم إرسال طلب الوصل بنجاح" });
  } catch (err) {
    console.error("connect/send:", err);
    res.status(500).json({ error: "فشل إرسال الطلب" });
  }
});

// 🔹 3. فك الوصل أو إلغاء الطلب
app.delete("/api/connect", auth, async (req, res) => {
  try {
    const userId = req.user.id;
    const { target_id } = req.body;
    const targetId = +target_id;
    if (!targetId || userId === targetId)
      return res.status(400).json({ error: "طلب غير صالح" });

    await pool.query(
      `DELETE FROM connections 
       WHERE (user_id=$1 AND target_id=$2) OR (user_id=$2 AND target_id=$1)`,
      [userId, targetId]
    );

    res.json({ ok: true, message: "💔 تم فك الوصل بنجاح" });
  } catch (err) {
    console.error("connect/delete:", err);
    res.status(500).json({ error: "فشل فك الوصل" });
  }
});

// =======================================
// ✅ قبول أو رفض طلب الوصل
// =======================================
app.post("/api/connect/respond", auth, async (req, res) => {
  try {
    const userId = req.user.id;
    const { requester_id, action } = req.body;
    const now = Date.now();

    if (!requester_id || !["accept", "reject"].includes(action))
      return res.status(400).json({ error: "طلب غير صالح" });

    const { rows } = await pool.query(
      `SELECT * FROM connections WHERE user_id=$1 AND target_id=$2 AND status='pending'`,
      [requester_id, userId]
    );

    if (!rows.length)
      return res.status(404).json({ error: "لم يتم العثور على الطلب" });

    if (action === "accept") {
      await pool.query(
        `UPDATE connections SET status='connected', updated_at=$1 WHERE user_id=$2 AND target_id=$3`,
        [now, requester_id, userId]
      );

      await pool.query(
        `INSERT INTO connections (user_id, target_id, status, created_at, updated_at)
         VALUES ($1, $2, 'connected', $3, $3)
         ON CONFLICT (user_id, target_id) DO NOTHING`,
        [userId, requester_id, now]
      );

      await notifyUser(
        requester_id,
        "🤝 تم قبول طلب الوصل",
        "قام المستخدم بقبول طلبك بالوصل!",
        "connect_accept",
        { sender_id: userId }
      );

      res.json({ ok: true, message: "✅ تم قبول الطلب بنجاح" });
    } else {
      await pool.query(
        `DELETE FROM connections WHERE user_id=$1 AND target_id=$2 AND status='pending'`,
        [requester_id, userId]
      );

      await notifyUser(
        requester_id,
        "❌ تم رفض طلب الوصل",
        "قام المستخدم برفض طلبك بالوصل.",
        "connect_reject",
        { sender_id: userId }
      );

      res.json({ ok: true, message: "❌ تم رفض الطلب" });
    }
  } catch (err) {
    console.error("connect/respond:", err);
    res.status(500).json({ error: "خطأ في قاعدة البيانات" });
  }
});

// =======================================
// 🔢 جلب عدد الموصولين + نظام البونص للمطور
// =======================================
const DEV_EMAIL = "hothaifaalsamri@gmail.com";

// 🔸 دالة لجلب العدد الكلي للمستخدمين
async function getTotalUsers() {
  const { rows } = await pool.query(`SELECT COUNT(*) AS total FROM users`);
  return +rows[0].total || 0;
}

// 🔸 1. جلب عدد الموصولين لمستخدم محدد
app.get("/api/connect/count/:userId", auth, async (req, res) => {
  try {
    const targetId = +req.params.userId;
    if (!targetId)
      return res.status(400).json({ error: "رقم المستخدم غير صالح" });

    const { rows } = await pool.query(
      `SELECT COUNT(*) AS total FROM connections
       WHERE (user_id=$1 OR target_id=$1) AND status='connected'`,
      [targetId]
    );

    const connectedCount = +rows[0].total || 0;

    const { rows: userRow } = await pool.query(
      `SELECT email FROM users WHERE id=$1`,
      [targetId]
    );

    if (userRow.length && userRow[0].email === DEV_EMAIL) {
      const totalUsers = await getTotalUsers();
      const bonus = Math.max(0, totalUsers - 1) * 5;
      return res.json({
        ok: true,
        count: connectedCount,
        bonus,
        display_count: connectedCount + bonus
      });
    }

    res.json({ ok: true, count: connectedCount, bonus: 0, display_count: connectedCount });
  } catch (err) {
    console.error("connect/count:", err);
    res.status(500).json({ error: "فشل جلب عدد الموصولين" });
  }
});
// =======================================
// 🔥 نظام الإيمان (الشعلات والشارات) + إعدادات الحساب
// =======================================

// 🔸 2. جلب عدد الموصولين للمستخدم الحالي
app.get("/api/connect/count/me", auth, async (req, res) => {
  try {
    const myId = req.user.id;
    const { rows } = await pool.query(
      `SELECT COUNT(*) AS total FROM connections
       WHERE (user_id=$1 OR target_id=$1) AND status='connected'`,
      [myId]
    );
    const connectedCount = +rows[0].total || 0;

    const { rows: urow } = await pool.query(
      `SELECT email FROM users WHERE id=$1`,
      [myId]
    );

    if (urow.length && urow[0].email === DEV_EMAIL) {
      const totalUsers = await getTotalUsers();
      const bonus = Math.max(0, totalUsers - 1) * 5;
      return res.json({
        ok: true,
        count: connectedCount,
        bonus,
        display_count: connectedCount + bonus,
      });
    }

    res.json({ ok: true, count: connectedCount, bonus: 0, display_count: connectedCount });
  } catch (err) {
    console.error("connect/count/me:", err);
    res.status(500).json({ error: "فشل جلب عدد الموصولين" });
  }
});

// 🔥 تحديث عدد الشعلات والشارة الحالية
app.post("/api/faith/update", auth, async (req, res) => {
  try {
    const userId = req.user.id;
    const { flames, faith_rank } = req.body || {};
    if (typeof flames === "undefined" && typeof faith_rank === "undefined")
      return res.status(400).json({ error: "لا يوجد بيانات للتحديث" });

    await pool.query(
      `UPDATE users 
       SET flames = COALESCE($1, flames),
           faith_rank = COALESCE($2, faith_rank),
           last_faith_activity = EXTRACT(EPOCH FROM NOW())
       WHERE id=$3`,
      [flames, faith_rank, userId]
    );

    // 📨 إشعار الترقية
    if (typeof faith_rank === "string" && faith_rank.trim()) {
      await notifyUser(
        userId,
        "🎖️ ترقية شارتك",
        `🎉 تمت ترقيتك إلى ${faith_rank}! استمر في نشر الخير 🔥`,
        "rank_upgrade",
        { sender_id: userId, faith_rank }
      );
    }

    // 💎 تحديد نوع الشارة
    let rankTier = null;
    const rankName = (faith_rank || "").toString();
    if (rankName.includes("مساهم")) rankTier = "silver";
    else if (rankName.includes("ناشر")) rankTier = "gold";
    else if (rankName.includes("لا يترك")) rankTier = "diamond";

    if (rankTier) {
      await pool.query(
        `UPDATE users SET rank_tier=$1 WHERE id=$2`,
        [rankTier, userId]
      );
      console.log(`🏅 تم تحديث rank_tier للمستخدم ${userId} → ${rankTier}`);
    }

    res.json({ ok: true, message: "✅ تم تحديث الشعلات بنجاح" });
  } catch (err) {
    console.error("faith/update:", err);
    res.status(500).json({ error: "خطأ في قاعدة البيانات" });
  }
});

app.get("/api/faith/me", auth, async (req, res) => {
  try {
    const userId = req.user.id;
    const { rows } = await pool.query(
      `SELECT flames, faith_rank FROM users WHERE id=$1`,
      [userId]
    );
    res.json({ ok: true, faith: rows[0] || { flames: 0, faith_rank: "" } });
  } catch (err) {
    console.error("faith/me:", err);
    res.status(500).json({ error: "فشل في قاعدة البيانات" });
  }
});

app.post("/api/faith/check_reset", auth, async (req, res) => {
  try {
    const userId = req.user.id;
    const { rows } = await pool.query(
      `SELECT last_faith_activity, flames, faith_rank 
       FROM users WHERE id=$1`,
      [userId]
    );
    if (!rows.length) return res.json({ ok: false });

    const row = rows[0];
    const now = Math.floor(Date.now() / 1000);
    const diffDays = (now - (row.last_faith_activity || now)) / 86400;

    if (diffDays >= 3 && row.flames > 0) {
      await pool.query(
        `UPDATE users 
         SET flames=0, faith_rank='', last_faith_activity=EXTRACT(EPOCH FROM NOW()) 
         WHERE id=$1`,
        [userId]
      );

      await notifyUser(
        userId,
        "⏳ استئناف نشاطك الإيماني",
        "تم تصفير الشعلات بعد غياب 3 أيام. نورتنا! ابدأ من جديد 🤍",
        "faith_reset",
        { sender_id: userId }
      );

      return res.json({
        ok: true,
        reset: true,
        message: "🔥 تم تصفير الشعلات بعد غيابك 3 أيام",
      });
    }

    res.json({ ok: true, reset: false });
  } catch (err) {
    console.error("faith/check_reset:", err);
    res.status(500).json({ ok: false, error: "فشل التصفير" });
  }
});

// 🛰️ إرجاع حالة الإيمان (الشعلات والشارة والرفيق) - تم توحيده ليتضمن الرفيق
app.get("/api/faith/status", auth, async (req, res) => {
    try {
        const userId = req.user.id;
        if (!userId) return res.status(401).json({ error: "جلسة غير صالحة" });

        // 1. جلب بيانات المستخدم (الشعلات والترتيب)
        const userRes = await pool.query( // استخدام pool.query
            `SELECT flames AS total_flames, faith_rank AS rank 
             FROM users WHERE id = $1`,
            [userId]
        );
        const userStatus = userRes.rows[0];

        if (!userStatus) return res.json({ ok: false, error: "User not found" });

        // 2. جلب بيانات الرفيق
        let companion = null;
        const companionRes = await pool.query( // استخدام pool.query
            `SELECT xp, level, evolution_stage, visits_count 
             FROM companion WHERE user_id = $1`,
            [userId]
        );

        // 💡 إذا لم يكن هناك رفيق، نقوم بإنشاء واحد تلقائياً
        if (companionRes.rows.length === 0) {
            // إنشاء رفيق ابتدائي
            await pool.query( // استخدام pool.query
                `INSERT INTO companion (user_id) VALUES ($1)`,
                [userId]
            );
            companion = { xp: 0, level: 1, evolution_stage: 1, visits_count: 0 };
        } else {
            companion = companionRes.rows[0];
        }

        // 3. إرسال البيانات المجمعة
        return res.json({
            ok: true,
            status: {
                ...userStatus,
                companion: companion // ⬅️ إضافة بيانات الرفيق إلى الرد
            }
        });

    } catch (err) {
        console.error("faith/status:", err);
        res.json({ ok: false, error: "Server error" });
    }
});

// ✅ تغيير كلمة المرور
app.post("/api/change_password", auth, async (req, res) => {
  try {
    const { oldPassword, newPassword } = req.body;
    const userId = req.user.id;

    if (!oldPassword || !newPassword)
      return res.status(400).json({ ok: false, error: "الرجاء إدخال جميع الحقول" });

    const { rows } = await pool.query(`SELECT password FROM users WHERE id=$1`, [userId]);
    if (!rows.length) return res.status(404).json({ ok: false, error: "المستخدم غير موجود" });

    const bcrypt = require("bcryptjs");
    const match = await bcrypt.compare(oldPassword, rows[0].password);
    if (!match)
      return res.json({ ok: false, error: "❌ كلمة المرور القديمة غير صحيحة" });

    const hashed = await bcrypt.hash(newPassword, 10);
    await pool.query(`UPDATE users SET password=$1 WHERE id=$2`, [hashed, userId]);
    res.json({ ok: true, message: "✅ تم تغيير كلمة المرور بنجاح" });
  } catch (err) {
    console.error("change_password:", err);
    res.status(500).json({ ok: false, error: "فشل تحديث كلمة المرور" });
  }
});

app.post("/api/delete_account", auth, async (req, res) => {
  const { password } = req.body;
  const userId = req.user.id;
  if (!password) {
    return res.status(400).json({ ok: false, error: "الرجاء إدخال كلمة المرور" });
  }
  const client = await pool.connect();
  try {
    const { rows } = await client.query(`SELECT password FROM users WHERE id=$1`, [userId]);
    if (!rows.length) {
      return res.status(404).json({ ok: false, error: "المستخدم غير موجود" });
    }
    const match = await bcrypt.compare(password, rows[0].password);
    if (!match) {
      return res.json({ ok: false, error: "❌ كلمة المرور غير صحيحة!" });
    }
    await client.query('BEGIN');
    await client.query(`DELETE FROM reactions WHERE user_id=$1`, [userId]);
    await client.query(`DELETE FROM connections WHERE user_id=$1 OR target_id=$1`, [userId]);
    await client.query(`DELETE FROM refresh_tokens WHERE user_id=$1`, [userId]);
    await client.query(`DELETE FROM saved_posts WHERE user_id=$1`, [userId]);
    await client.query(`DELETE FROM users WHERE id=$1`, [userId]);
    await client.query('COMMIT');
    console.log(`🗑️ تم حذف المستخدم ${userId} بنجاح`);
    res.json({ ok: true, message: "تم حذف الحساب بنجاح." });

  } catch (err) {
    
    await client.query('ROLLBACK');
    console.error("❌ خطأ فادح أثناء حذف الحساب:", err);
    res.status(500).json({ ok: false, error: "فشل حذف الحساب بسبب خطأ داخلي" });
  } finally {
    
    client.release();
  }
});

const fetch = require("node-fetch");

async function sendEmailBrevo(to, subject, html) {
  try {
    const res = await fetch("https://api.brevo.com/v3/smtp/email", {
      method: "POST",
      headers: {
        accept: "application/json",
        "api-key": process.env.BREVO_API_KEY,
        "content-type": "application/json",
      },
      body: JSON.stringify({
        sender: { name: "Hajjen Mojtama", email: "darauemaror@gmail.com" },
        to: [{ email: to }],
        subject,
        htmlContent: html,
      }),
    });

    const data = await res.json();
    console.log("📬 رد Brevo:", data); // 🟢 راقب هذا في الـ logs

    if (res.ok) {
      console.log(`📩 تم إرسال البريد إلى ${to}`);
    } else {
      console.error("❌ فشل إرسال البريد:", data);
    }
  } catch (err) {
    console.error("🚫 خطأ في الاتصال بـ Brevo:", err);
  }
}
app.post("/api/auth/devices", auth, async (req, res) => {
  try {
    const userId = req.user.id;
    const { current_refresh_token } = req.body; 

    if (!current_refresh_token) {
      return res.status(400).json({ error: "التوكن الحالي مطلوب" });
    }

    const { rows } = await runQuery(
      `SELECT id, device_info, created_at, token 
       FROM refresh_tokens 
       WHERE user_id = $1 AND revoked = 0 
       ORDER BY created_at DESC`,
      [userId]
    );

    const devices = rows.map(device => ({
      id: device.id,
      device_info: device.device_info,
      created_at: device.created_at,
      is_current: (device.token === current_refresh_token) 
    }));
    
   
    res.json({ ok: true, devices: devices });

  } catch (err) {
    console.error("❌ خطأ أثناء جلب الأجهزة:", err);
    res.status(500).json({ error: "فشل جلب الأجهزة المتصلة" });
  }
});


// 1. بدء إعداد التحقق (إنشاء المفتاح السري والـ QR Code)
app.post("/api/2fa/setup", auth, async (req, res) => {
  try {
    const userId = req.user.id;
    const email = req.user.email;

    // إنشاء مفتاح سري جديد وفريد
    const secret = authenticator.generateSecret();
    
    // إنشاء رابط QR Code (لتطبيق Google Authenticator)
    const appName = "HEQ_Mojtama";
    const otpAuthUrl = authenticator.keyuri(email, appName, secret);

    // تخزين المفتاح السري "مؤقتاً" في قاعدة البيانات (أو إرساله مباشرة)
    // الأفضل هو تخزينه هنا
    await runQuery("UPDATE users SET two_fa_secret = $1 WHERE id = $2", [
      secret, // (لاحقاً سنقوم بتشفير هذا المفتاح قبل حفظه)
      userId,
    ]);

    res.json({
      ok: true,
      secret: secret, // للاختبار (يمكن إزالته لاحقاً)
      qrCodeUrl: otpAuthUrl, // الواجهة ستستخدم هذا لإنشاء الـ QR
    });
  } catch (err) {
    console.error("❌ خطأ أثناء إعداد 2FA:", err);
    res.status(500).json({ error: "فشل إنشاء رمز التحقق" });
  }
});


app.post("/api/2fa/verify", auth, async (req, res) => {
  try {
    const userId = req.user.id;
    const { token } = req.body; // الرمز السداسي (6 أرقام)

    if (!token) {
      return res.status(400).json({ error: "الرمز مطلوب" });
    }

    // جلب المفتاح السري من قاعدة البيانات
    const { rows } = await runQuery(
      "SELECT two_fa_secret FROM users WHERE id = $1",
      [userId]
    );
    if (!rows.length || !rows[0].two_fa_secret) {
      return res.status(400).json({ error: "لم يتم بدء إعداد التحقق" });
    }
    const secret = rows[0].two_fa_secret;

    // التحقق من صحة الرمز
    const isValid = authenticator.check(token, secret);

    if (isValid) {
      // الرمز صحيح -> تفعيل الميزة بشكل دائم
      await runQuery("UPDATE users SET two_fa_enabled = 1 WHERE id = $1", [
        userId,
      ]);
      res.json({ ok: true, message: "✅ تم تفعيل التحقق بخطوتين بنجاح!" });
    } else {
      // الرمز خاطئ
      res.status(400).json({ error: "❌ الرمز غير صحيح، حاول مرة أخرى" });
    }
  } catch (err) {
    console.error("❌ خطأ أثناء تفعيل 2FA:", err);
    res.status(500).json({ error: "فشل تفعيل الميزة" });
  }
});

// 3. نقطة النهاية لإكمال تسجيل الدخول (عندما تكون 2FA مفعلة)
app.post("/api/2fa/login", async (req, res) => {
  try {
    const { email, password, token } = req.body; // الرمز السداسي + الإيميل والباسورد

    if (!email || !password || !token) {
      return res.status(400).json({ error: "البيانات ناقصة" });
    }

    // 1. التحقق من الإيميل والباسورد (مرة أخرى للأمان)
    const userRes = await pool.query("SELECT * FROM users WHERE email = $1", [email]);
    if (!userRes.rows.length) {
      return res.status(400).json({ error: "الحساب غير موجود" });
    }
    const user = userRes.rows[0];

    const match = await bcrypt.compare(password, user.password);
    if (!match) {
      return res.status(400).json({ error: "كلمة المرور غير صحيحة" });
    }

    // 2. التحقق من الرمز السداسي (2FA)
    const secret = user.two_fa_secret;
    const isValid = authenticator.check(token, secret);

    if (!isValid) {
      return res.status(400).json({ error: "❌ الرمز غير صحيح" });
    }

    // 3. كل شيء صحيح -> إصدار التوكنات (نفس كود /api/login)
    const payload = { id: user.id, email: user.email };
    const accessToken = signAccessToken(payload);
    const refreshToken = signRefreshToken(payload);
    
    const userAgent = req.headers['user-agent'] || 'Unknown Device';
    await storeRefreshToken(user.id, refreshToken, userAgent);

    res.json({
      ok: true,
      message: "✅ تم تسجيل الدخول بنجاح",
      token: accessToken,
      refreshToken: refreshToken,
    });

  } catch (err) {
    console.error("❌ خطأ أثناء تسجيل الدخول بـ 2FA:", err);
    res.status(500).json({ error: "فشل عملية الدخول" });
  }
});
// 4. إلغاء تفعيل الميزة
app.post("/api/2fa/disable", auth, async (req, res) => {
  try {
    const userId = req.user.id;
    const { password } = req.body;

    if (!password) {
      return res.status(400).json({ error: "كلمة المرور مطلوبة" });
    }

    // 1. التحقق من كلمة المرور
    const { rows } = await pool.query(
      "SELECT password FROM users WHERE id = $1",
      [userId]
    );
    if (!rows.length) {
      return res.status(404).json({ error: "المستخدم غير موجود" });
    }
    
    const match = await bcrypt.compare(password, rows[0].password);
    if (!match) {
      return res.status(400).json({ error: "❌ كلمة المرور غير صحيحة" });
    }

    // 2. كلمة المرور صحيحة -> إلغاء التفعيل
    await runQuery(
      "UPDATE users SET two_fa_enabled = 0, two_fa_secret = '' WHERE id = $1",
      [userId]
    );

    res.json({ ok: true, message: "✅ تم إلغاء تفعيل الميزة بنجاح" });

  } catch (err) {
    console.error("❌ خطأ أثناء إلغاء تفعيل 2FA:", err);
    res.status(500).json({ error: "فشل إلغاء التفعيل" });
  }
});
app.post("/api/auth/revoke-device", auth, async (req, res) => {
  try {
    const userId = req.user.id;
    const { device_id } = req.body;

    if (!device_id) {
      return res.status(400).json({ error: "معرف الجهاز (الجلسة) مطلوب" });
    }
    const result = await runQuery(
      `UPDATE refresh_tokens 
       SET revoked = 1 
       WHERE id = $1 AND user_id = $2`,
      [device_id, userId]
    );

    if (result.rowCount === 0) {
      return res.status(404).json({ error: "الجلسة غير موجودة أو لا تملك صلاحية حذفها" });
    }

    res.json({ ok: true, message: "✅ تم تسجيل الخروج من الجهاز بنجاح" });

  } catch (err) {
    console.error("❌ خطأ أثناء حذف الجهاز:", err);
    res.status(500).json({ error: "فشل حذف الجهاز" });
  }
});

app.post("/api/auth/logout-all", auth, async (req, res) => {
  try {
    const userId = req.user.id;
    const { current_refresh_token } = req.body; 

    if (!current_refresh_token) {
      return res.status(400).json({ error: "التوكن الحالي مطلوب لتحديد الجلسة" });
    }

    
    const result = await runQuery(
      `UPDATE refresh_tokens 
       SET revoked = 1 
       WHERE user_id = $1 AND token != $2`,
      [userId, current_refresh_token]
    );

    res.json({ 
      ok: true, 
      message: `✅ تم تسجيل الخروج من ${result.rowCount} جهاز آخر بنجاح` 
    });

  } catch (err) {
    console.error("❌ خطأ أثناء تسجيل الخروج من الكل:", err);
    res.status(500).json({ error: "فشل العملية" });
  }
});
app.post('/api/companion/update', auth, async (req, res) => {
    const userId = req.user.id;
    if (!userId) {
        return res.status(401).json({ message: 'Authorization required.' });
    }

    const { xp_earned } = req.body;
    if (typeof xp_earned !== 'number' || xp_earned <= 0) {
        return res.status(400).json({ message: 'Invalid XP amount.' });
    }

    try {
        
        let companionResult = await pool.query( 
            'SELECT xp, level, evolution_stage, visits_count FROM companion WHERE user_id = $1', 
            [userId]
        );
        
        let companion = companionResult.rows[0];
        if (!companion) {
             await pool.query(`INSERT INTO companion (user_id) VALUES ($1)`, [userId]);
             companion = { xp: 0, level: 1, evolution_stage: 1, visits_count: 0 };
        }
        
        let newXP = companion.xp + xp_earned;
        let newLevel = companion.level;
        let newEvolutionStage = companion.evolution_stage;
        let newVisitsCount = companion.visits_count + 1; // زيادة عدد الإكمالات
        let leveledUp = false;

        // 2. منطق رفع المستوى
        const XP_NEEDED_FOR_LEVEL_UP = 100;

        while (newXP >= XP_NEEDED_FOR_LEVEL_UP) {
            newXP -= XP_NEEDED_FOR_LEVEL_UP;
            newLevel++;
            leveledUp = true;

            // 3. منطق التطور (التطور في المستوى 5 و 10)
            if (newLevel === 5) {
                newEvolutionStage = 2; // التطور الأول
            } else if (newLevel === 10) {
                newEvolutionStage = 3; // التطور الثاني
            }
        }

        // 4. تحديث جدول الرفيق - استخدام $1, $2, ... لـ PostgreSQL
        await pool.query(
            'UPDATE companion SET xp = $1, level = $2, evolution_stage = $3, visits_count = $4 WHERE user_id = $5',
            [newXP, newLevel, newEvolutionStage, newVisitsCount, userId]
        );
        
        // 5. إرسال استجابة بنجاح
        res.json({ 
            message: 'XP updated successfully.', 
            new_xp: newXP, 
            new_level: newLevel,
            new_evolution_stage: newEvolutionStage,
            leveled_up: leveledUp,
            new_visits_count: newVisitsCount
        });

    } catch (err) {
        console.error('Error updating companion XP:', err);
        res.status(500).json({ message: 'Server error while updating companion XP.' });
    }
});

// Companion / Profile Visits
// ====== تسجيل زيارة للملف الشخصي (لزيادة عداد visits_count للرفيق) ======
app.post("/api/profile/visit/:targetId", auth, async (req, res) => {
    const targetId = parseInt(req.params.targetId);
    const visitorId = req.user.id;
    const now = Date.now();
    const VISIT_COOLDOWN_MS = 24 * 60 * 60 * 1000; // 24 ساعة فترة تبريد بين الزيارات

    if (isNaN(targetId) || targetId <= 0) {
        return res.status(400).json({ error: "معرّف المستخدم الهدف غير صحيح." });
    }

    // 1. لا تسجل الزيارة إذا كان الزائر هو صاحب الملف الشخصي
    if (targetId === visitorId) {
        return res.json({ ok: true, message: "الزيارة من المالك، تم التخطي." });
    }

    try {
        // 2. التحقق من آخر زيارة مسجلة بين الزائر والمزار
        const logRes = await runQuery(
            `SELECT last_visit_at FROM profile_visits_log WHERE visitor_id = $1 AND visited_id = $2`,
            [visitorId, targetId]
        );

        let shouldCountVisit = true;
        let lastVisitAt = 0;

        if (logRes.rows.length > 0) {
            lastVisitAt = logRes.rows[0].last_visit_at;
            if (now - lastVisitAt < VISIT_COOLDOWN_MS) {
                // الزيارة مسجلة خلال فترة التبريد (24 ساعة)، لا تقم بالعد.
                shouldCountVisit = false;
            }
        }

        if (!shouldCountVisit) {
            return res.json({ ok: true, message: "تم تسجيل هذه الزيارة مسبقاً خلال الـ 24 ساعة." });
        }

        // 3. تحديث أو إدراج سجل الزيارة في profile_visits_log
        await runQuery(
            `INSERT INTO profile_visits_log (visitor_id, visited_id, last_visit_at)
             VALUES ($1, $2, $3)
             ON CONFLICT (visitor_id, visited_id) DO UPDATE SET last_visit_at = EXCLUDED.last_visit_at`,
            [visitorId, targetId, now]
        );

        // 4. زيادة عداد visits_count في جدول companion للمستخدم الهدف
        const updateRes = await runQuery(
            `UPDATE companion
             SET visits_count = visits_count + 1, last_visit_check = $1
             WHERE user_id = $2
             RETURNING visits_count`,
            [now, targetId]
        );

        // 5. إنشاء سجل للـ companion إذا لم يكن موجوداً (للمستخدمين القدامى)
        if (updateRes.rowCount === 0) {
            await runQuery(
                `INSERT INTO companion (user_id, visits_count, last_activity, last_visit_check)
                 VALUES ($1, 1, $2, $3)`,
                [targetId, now, now]
            );
        }

        console.log(`👤 تم تسجيل زيارة جديدة من ${visitorId} إلى الملف الشخصي ${targetId}.`);

        res.json({ ok: true, message: "✅ تم تسجيل زيارة الملف الشخصي بنجاح." });
    } catch (err) {
        console.error("❌ خطأ أثناء تسجيل زيارة الملف الشخصي:", err.message);
        res.status(500).json({ error: "فشل في تسجيل الزيارة." });
    }
});
// =======================================
// ====== جلب قائمة زوار الملف الشخصي ======
// =======================================
app.get("/api/profile/visitors", auth, async (req, res) => {
    const userId = req.user.id; // ID المستخدم الحالي (صاحب الحساب)

    try {
        const { rows } = await pool.query(
            `SELECT
                pvl.visitor_id,
                pvl.last_visit_at,
                u.name AS visitor_name,
                u.avatar AS visitor_avatar
             FROM profile_visits_log pvl
             JOIN users u ON u.id = pvl.visitor_id
             WHERE pvl.visited_id = $1  -- جلب زوار هذا المستخدم
               AND pvl.visitor_id != $1 -- استثناء زيارات المستخدم لنفسه
             ORDER BY pvl.last_visit_at DESC -- الأحدث أولاً
             LIMIT 20`, // حد أقصى لعدد الزوار
            [userId]
        );

        // تحويل timestamp إلى رقم (إذا كان BigInt) وتنسيق بسيط
        const visitors = rows.map(v => ({
            id: v.visitor_id,
            name: v.visitor_name || "مستخدم غير معروف",
            avatar: v.visitor_avatar || "assets/default-avatar.png",
            lastVisitAt: parseInt(v.last_visit_at, 10) // تأكد أنه رقم
        }));

        res.json({ ok: true, visitors: visitors });

    } catch (err) {
        console.error("❌ خطأ أثناء جلب زوار الملف الشخصي (/api/profile/visitors):", err);
        res.status(500).json({ ok: false, error: "فشل في جلب قائمة الزوار." });
    }
});

//  Health check  تشغيل السيرفر

app.get("/", (_, res) => {
  res.json({ ok: true, message: "🚀 HEQ server is running smoothly!" });
});

app.listen(PORT, () => {
  console.log(`✅ Server running on port ${PORT}`);
});























































