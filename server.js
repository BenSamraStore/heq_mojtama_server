
const express = require("express");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const fs = require("fs");
const path = require("path");
const multer = require("multer");
const { Pool } = require("pg");
const cloudinary = require("cloudinary").v2;
const app = express();
cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET,
  secure: true, 
});

// ✅ متغيرات البيئة
const PORT = process.env.PORT;
const SECRET_KEY = process.env.SECRET_KEY;
const REFRESH_SECRET = process.env.REFRESH_SECRET;
const EMAIL_USER = process.env.EMAIL_USER;
const EMAIL_PASS = process.env.EMAIL_PASS;
const ACCESS_EXPIRES_IN = "2h";
const REFRESH_EXPIRES_DAYS = 30;

// ✅ PostgreSQL
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

// helper صغير (اختياري)
function runQuery(q, params = []) {
  return pool.query(q, params);
}

// ✅ إعداد الرفع والستاتيك
const UPLOADS_DIR = path.join(__dirname, "uploads");
if (!fs.existsSync(UPLOADS_DIR)) fs.mkdirSync(UPLOADS_DIR, { recursive: true });
const upload = multer({ dest: UPLOADS_DIR });

// ✅ ميدلويرز
app.use(cors());
app.use(express.json({ limit: "5mb" }));
app.use("/uploads", express.static(UPLOADS_DIR));

// ─────────────────────────────────────────
// Auth + Helpers
// ─────────────────────────────────────────
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
async function storeRefreshToken(userId, refreshToken) {
  const createdAt = Date.now();
  const expiresAt = Date.now() + REFRESH_EXPIRES_DAYS * 24 * 60 * 60 * 1000;
  await runQuery(
    `INSERT INTO refresh_tokens (user_id, token, expires_at, created_at)
     VALUES ($1, $2, $3, $4)`,
    [userId, refreshToken, expiresAt, createdAt]
  );
}

// إشعار
async function notifyUser(toUserId, title, body, type = "system", meta = {}) {
  const createdAt = Date.now();
  let finalTitle = title;
  let finalBody = body;
  let senderName = "مستخدم";

  try {
    // الخطوة 1: جلب اسم المرسل إذا كان موجوداً
    if (meta.sender_id) {
      const { rows } = await runQuery("SELECT name FROM users WHERE id = $1", [meta.sender_id]);
      if (rows.length > 0) {
        senderName = rows[0].name;
      }
    }

    // الخطوة 2: تخصيص الرسائل حسب نوع الإشعار
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
      
      // يمكنك إضافة أنواع أخرى هنا مستقبلاً
    }

    // الخطوة 3: إدراج الإشعار المخصص في قاعدة البيانات
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

// ✅ اختبار بسيط
app.get("/api/test", (_req, res) => {
  res.json({ ok: true, message: "✅ API + DB (PG) ready", time: new Date().toISOString() });
});

// ─────────────────────────────────────────
// إنشاء الجداول (نفس الأسماء/الأعمدة القديمة)
// ─────────────────────────────────────────
(async () => {
  try {
    await runQuery("SELECT NOW()");
    console.log("🟢 تم الاتصال بـ PostgreSQL");

    // users
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

    // refresh_tokens
    await runQuery(`
      CREATE TABLE IF NOT EXISTS refresh_tokens (
        id SERIAL PRIMARY KEY,
        user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        token TEXT NOT NULL UNIQUE,
        expires_at BIGINT NOT NULL,
        created_at BIGINT NOT NULL,
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
        to_user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
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
    //  (الشعلة الحيّة/العقاب/الفينيق)
    await runQuery(`
      CREATE TABLE IF NOT EXISTS companion (
        id SERIAL PRIMARY KEY,
        user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE UNIQUE,
        xp INTEGER DEFAULT 0,                 
        level INTEGER DEFAULT 1,             
        evolution_stage TEXT DEFAULT 'egg',   
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

    // إدخاله ضمن المستخدمين الرسميين
    const insertRes = await pool.query(
      `INSERT INTO users (email, password, name, bio, avatar, joined_at, verified)
       VALUES ($1, $2, $3, '', '', $4, 1) RETURNING id`,
      [userRow.email, userRow.password, userRow.name, joinedAt]
    );
    const userId = insertRes.rows[0].id;

    // 🎫 توليد HEQ-ID المنسق
    const heqId = `HEQ${String(userId).padStart(5, "0")}`;
    await pool.query("UPDATE users SET heq_id = $1 WHERE id = $2", [heqId, userId]);
    console.log(`🆔 تم تعيين HEQ-ID: ${heqId}`);

    // تنظيف الجداول المؤقتة
    await pool.query("DELETE FROM pending_users WHERE email = $1", [email]);
    await pool.query("DELETE FROM otp_codes WHERE email = $1", [email]);

    // إنشاء التوكنات
    const payload = { email: userRow.email, id: userId };
    const token = signAccessToken(payload);
    const refreshToken = signRefreshToken(payload);

    await storeRefreshToken(userId, refreshToken);

    console.log(`✅ تم تفعيل حساب: ${email}`);

    // 🧩 زيادة عداد الموصولين للمطور تلقائياً
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
// ===== تسجيل الدخول (مع الحظر التلقائي بعد 5 محاولات) =====
app.post("/api/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password)
      return res.status(400).json({ error: "أدخل البريد وكلمة المرور" });

    // جلب المستخدم
    const userRes = await pool.query("SELECT * FROM users WHERE email = $1", [email]);
    if (!userRes.rows.length)
      return res.status(400).json({ error: "الحساب غير موجود" });

    const user = userRes.rows[0];

    if (user.disabled)
      return res.status(403).json({
        error: "🚫 تم تعطيل حسابك. يرجى التواصل مع المطوّر لاستعادة الوصول."
      });

    // تحقق من حالة الحظر
    if (user.lock_until && user.lock_until > Date.now()) {
      const remainingMs = user.lock_until - Date.now();
      const hours = Math.floor(remainingMs / (1000 * 60 * 60));
      const minutes = Math.floor((remainingMs % (1000 * 60 * 60)) / (1000 * 60));
      return res.status(403).json({
        error: `🚫 الحساب محظور مؤقتًا. أعد المحاولة بعد ${hours} ساعة و${minutes} دقيقة.`
      });
    }

    // تحقق من كلمة المرور
    const match = await bcrypt.compare(password, user.password);
    if (!match) {
      const newFails = (user.failed_attempts || 0) + 1;
      if (newFails >= 5) {
        const lockUntil = Date.now() + 12 * 60 * 60 * 1000; // 12 ساعة
        await pool.query(
          "UPDATE users SET failed_attempts = $1, lock_until = $2 WHERE email = $3",
          [newFails, lockUntil, email]
        );
        return res.status(403).json({
          error: "🚫 تم تجاوز الحد المسموح من المحاولات. الحساب محظور لمدة 12 ساعة."
        });
      } else {
        await pool.query(
          "UPDATE users SET failed_attempts = $1 WHERE email = $2",
          [newFails, email]
        );
        return res.status(400).json({
          error: `❌ كلمة المرور غير صحيحة. المحاولة ${newFails} من 5.`
        });
      }
    }

    // نجاح تسجيل الدخول
    await pool.query(
      "UPDATE users SET failed_attempts = 0, lock_until = 0 WHERE email = $1",
      [email]
    );

    if (!user.verified)
      return res.status(403).json({ error: "الحساب غير مفعّل بعد" });

    // 🎫 إنشاء توكنات جديدة
    const payload = { id: user.id, email: user.email };
    const token = signAccessToken(payload);
    const refreshToken = signRefreshToken(payload);

    await storeRefreshToken(user.id, refreshToken);

    res.json({
      ok: true,
      message: "✅ تم تسجيل الدخول بنجاح",
      token,
      refreshToken
    });
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
// ====== جلب بيانات المستخدم الحالي ======
app.get("/api/me", auth, async (req, res) => {
  try {
    const email = req.user && req.user.email;
    if (!email) return res.status(401).json({ error: "جلسة غير صالحة" });

    const { rows } = await pool.query(
      `SELECT id, heq_id, email, name, bio, avatar, country, residence, age, gender,
              joined_at, show_email, faith_rank, flames, rank_tier
       FROM users WHERE email = $1`,
      [email]
    );

    if (!rows.length)
      return res.status(404).json({ error: "المستخدم غير موجود" });

    const user = rows[0];
    const profileCompleted = Boolean(
      (user.bio && user.bio.trim().length > 0) ||
      (user.avatar && user.avatar.trim().length > 0) ||
      (user.country && user.country.trim().length > 0) ||
      (user.residence && user.residence.trim().length > 0)
    );

    const safeEmail = user.show_email ? user.email : "";

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
        // ✨ التحويل إلى رقم
        joined_at: parseInt(user.joined_at, 10),
        show_email: user.show_email,
        faith_rank: user.faith_rank,
        flames: user.flames,
        rank_tier: user.rank_tier
      },
      profileCompleted
    });
  } catch (err) {
    console.error(err);
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
// ====== نظام تفاعل متطور (تصويت مرة واحدة) ======
app.post("/api/react", auth, async (req, res) => {
  try {
    const { type, targetId, action } = req.body; // type = post | comment
    const userId = req.user.id;

    if (!type || !targetId || !["agree", "disagree"].includes(action)) {
      return res.status(400).json({ error: "طلب غير صالح" });
    }

    // 🧠 فحص حالة الحساب قبل التفاعل
    const userRes = await pool.query("SELECT disabled, lock_until FROM users WHERE id = $1", [userId]);
    const user = userRes.rows[0];
    if (!user)
      return res.status(404).json({ error: "المستخدم غير موجود" });

    if (user.disabled)
      return res.status(403).json({ error: "🚫 حسابك معطّل. لا يمكنك التفاعل." });

    if (user.lock_until && user.lock_until > Date.now()) {
      const diffH = Math.ceil((user.lock_until - Date.now()) / (1000 * 60 * 60));
      return res.status(403).json({ error: `⏳ حسابك محظور مؤقتًا (${diffH} ساعة متبقية).` });
    }

    // 🟢 إذا الحساب سليم نكمل
    const table = type === "post" ? "posts" : type === "comment" ? "comments" : null;
    if (!table)
      return res.status(400).json({ error: "نوع الهدف غير معروف" });

    // التحقق إن كان المستخدم قد تفاعل مسبقًا
    const reactRes = await pool.query(
      "SELECT * FROM reactions WHERE user_id = $1 AND target_type = $2 AND target_id = $3",
      [userId, type, targetId]
    );

    // 🔹 الحالة 1: المستخدم لم يصوت من قبل
    if (reactRes.rows.length === 0) {
      await pool.query(
        "INSERT INTO reactions (user_id, target_type, target_id, action) VALUES ($1, $2, $3, $4)",
        [userId, type, targetId, action]
      );
      await pool.query(
        `UPDATE ${table} SET ${action} = ${action} + 1 WHERE id = $1`,
        [targetId]
      );
      return await sendCounts();
    }

    const row = reactRes.rows[0];

    // 🔹 الحالة 2: ضغط نفس الزر مرة ثانية → حذف التصويت
    if (row.action === action) {
      await pool.query("DELETE FROM reactions WHERE id = $1", [row.id]);
      await pool.query(
        `UPDATE ${table} SET ${action} = CASE WHEN ${action} > 0 THEN ${action} - 1 ELSE 0 END WHERE id = $1`,
        [targetId]
      );
      return await sendCounts();
    }

    // 🔹 الحالة 3: غيّر رأيه
    await pool.query("UPDATE reactions SET action = $1 WHERE id = $2", [action, row.id]);
    const opposite = action === "agree" ? "disagree" : "agree";
    await pool.query(
      `UPDATE ${table} 
       SET ${action} = ${action} + 1, 
           ${opposite} = CASE WHEN ${opposite} > 0 THEN ${opposite} - 1 ELSE 0 END 
       WHERE id = $1`,
      [targetId]
    );
    return await sendCounts();

    // دالة لجلب القيم الجديدة بعد أي تعديل
    async function sendCounts() {
      try {
        const updatedRes = await pool.query(
          `SELECT agree, disagree FROM ${table} WHERE id = $1`,
          [targetId]
        );
        const updated = updatedRes.rows[0] || { agree: 0, disagree: 0 };

        const targetTable = type === "post" ? "posts" : "comments";
        const ownerRes = await pool.query(`SELECT user_id FROM ${targetTable} WHERE id = $1`, [targetId]);
        const ownerRow = ownerRes.rows[0];
        const nameRes = await pool.query("SELECT name FROM users WHERE id = $1", [userId]);
        const userRow = nameRes.rows[0];
        const fromUser = userRow ? userRow.name : "مستخدم";
        const targetUserId = ownerRow ? ownerRow.user_id : null;

        res.json({
          ok: true,
          agree: updated.agree,
          disagree: updated.disagree,
          from_user: fromUser,
          target_user_id: targetUserId
        });

        // 🔔 إرسال الإشعار فقط إذا كان "إعجاب"
        if (action === "agree" && ownerRow && ownerRow.user_id !== userId) {
          const notifTitle = type === "post"
            ? "👍 تفاعل مع منشورك"
            : "👍 تفاعل مع تعليقك";
          const notifBody = type === "post"
            ? "قام أحد المستخدمين بالإعجاب بمنشورك."
            : "قام أحد المستخدمين بالإعجاب بتعليقك.";

          await notifyUser(
            ownerRow.user_id,
            notifTitle,
            notifBody,
            "reaction",
            { target_type: type, target_id: targetId, sender_id: userId }
          );
        }
      } catch (e) {
        console.error("❌ sendCounts error:", e.message);
        res.status(500).json({ error: "فشل جلب البيانات الجديدة" });
      }
    }
  } catch (err) {
    console.error("❌ خطأ في نظام التفاعل:", err);
    res.status(500).json({ error: "حدث خطأ أثناء المعالجة" });
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



app.post("/api/saved", auth, async (req, res) => {
  try {
    const { post_id } = req.body;
    const userId = req.user.id;

    if (!post_id)
      return res.status(400).json({ error: "رقم المنشور مطلوب" });

    const savedAt = Date.now();
    await pool.query(
      `INSERT INTO saved_posts (user_id, post_id, saved_at)
       VALUES ($1, $2, $3)
       ON CONFLICT (user_id, post_id) DO NOTHING`,
      [userId, post_id, savedAt]
    );

    res.json({ ok: true, message: "💾 تم حفظ المنشور في المفضلة!" });
  } catch (err) {
    console.error("❌ خطأ أثناء حفظ المنشور:", err);
    res.status(500).json({ error: "فشل حفظ المنشور" });
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

// ====== جلب مستخدم بالمعرّف ======
app.get("/api/users/:id", async (req, res) => {
  try {
    const userId = parseInt(req.params.id);
    if (Number.isNaN(userId)) return res.json({ ok: false, error: "رقم مستخدم غير صالح" });

    const { rows } = await pool.query(
      `SELECT id, heq_id, name, email, bio, country, age, gender, avatar, show_email, faith_rank, flames, rank_tier
       FROM users WHERE id = $1`,
      [userId]
    );

    if (!rows.length) return res.json({ ok: false, error: "لم يتم العثور على المستخدم." });

    const user = rows[0];
    if (!user.show_email) user.email = null;

    res.json({ ok: true, user });
  } catch (err) {
    console.error("get /users/:id:", err);
    res.json({ ok: false, error: "خطأ في قاعدة البيانات" });
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

// 🛰️ إرجاع حالة الإيمان (الشعلات والشارة)
app.get("/api/faith/status", auth, async (req, res) => {
  try {
    const { rows } = await pool.query(
      `SELECT flames AS total_flames, faith_rank AS rank 
       FROM users WHERE id=$1`,
      [req.user.id]
    );
    if (!rows.length)
      return res.json({ ok: false, error: "User not found" });
    res.json({ ok: true, status: rows[0] });
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

// 🗑️ حذف الحساب بالكامل (نسخة محسنة تتعامل مع SET NULL)
app.post("/api/delete_account", auth, async (req, res) => {
  const { password } = req.body;
  const userId = req.user.id;

  if (!password) {
    return res.status(400).json({ ok: false, error: "الرجاء إدخال كلمة المرور" });
  }

  const client = await pool.connect(); // ✨ نستخدم Transaction لضمان الأمان

  try {
    // 1. التحقق من كلمة المرور
    const { rows } = await client.query(`SELECT password FROM users WHERE id=$1`, [userId]);
    if (!rows.length) {
      return res.status(404).json({ ok: false, error: "المستخدم غير موجود" });
    }
    const match = await bcrypt.compare(password, rows[0].password);
    if (!match) {
      return res.json({ ok: false, error: "❌ كلمة المرور غير صحيحة!" });
    }

    // ✨ بدء الـ Transaction
    await client.query('BEGIN');

    // 2. حذف السجلات التي لها علاقة CASCADE (يجب حذفها أولاً)
    await client.query(`DELETE FROM reactions WHERE user_id=$1`, [userId]);
    await client.query(`DELETE FROM connections WHERE user_id=$1 OR target_id=$1`, [userId]);
    await client.query(`DELETE FROM refresh_tokens WHERE user_id=$1`, [userId]);
    await client.query(`DELETE FROM saved_posts WHERE user_id=$1`, [userId]);
    
    // 3. الآن يمكننا حذف المستخدم بأمان.
    // الجداول الأخرى (posts, comments, notifications, system_chat)
    // ستقوم تلقائياً بتحديث user_id إلى NULL بسبب قاعدة ON DELETE SET NULL.
    await client.query(`DELETE FROM users WHERE id=$1`, [userId]);

    // ✨ تأكيد الـ Transaction
    await client.query('COMMIT');

    console.log(`🗑️ تم حذف المستخدم ${userId} بنجاح`);
    res.json({ ok: true, message: "تم حذف الحساب بنجاح." });

  } catch (err) {
    // 롤백 في حالة حدوث أي خطأ
    await client.query('ROLLBACK');
    console.error("❌ خطأ فادح أثناء حذف الحساب:", err);
    res.status(500).json({ ok: false, error: "فشل حذف الحساب بسبب خطأ داخلي" });
  } finally {
    // تحرير الاتصال بقاعدة البيانات
    client.release();
  }
});
// ============================================
// ✉️ إرسال البريد عبر Brevo (SendinBlue سابقاً)
// ============================================
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
// 📌 المسار 2: جلب بيانات الشعلات والرفيق للمستخدم الحالي
app.get("/api/companion/me", auth, async (req, res) => {
  try {
    const userId = req.user.id;

    // جلب بيانات الشعلات والرفيق
    const { rows: compRows } = await pool.query(
      `SELECT xp, level, evolution_stage, current_companion, visits_count FROM companion WHERE user_id = $1`,
      [userId]
    );

   
    const { rows: userRows } = await pool.query(
        `SELECT heq_id, name, flames, faith_rank, rank_tier, joined_at FROM users WHERE id = $1`,
        [userId]
    );
    
    
    let companionData = compRows.length > 0 ? compRows[0] : null;
    if (!companionData) {
        await pool.query(
            `INSERT INTO companion (user_id, xp, level, evolution_stage) VALUES ($1, 0, 1, 'egg')`,
            [userId]
        );
        companionData = { xp: 0, level: 1, evolution_stage: 'egg', current_companion: 'phoenix', visits_count: 0 };
    }

    if (!userRows.length)
        return res.status(404).json({ error: "المستخدم غير موجود" });

    res.json({
        ok: true,
        user: userRows[0],
        companion: companionData
    });

  } catch (err) {
    console.error("❌ خطأ في جلب بيانات الرفيق:", err);
    res.status(500).json({ error: "فشل جلب بيانات الرفيق" });
  }
});


// 📌 مسار تحديث معلومات الرفيق (XP)
app.post('/api/companion/update', async (req, res) => {
    const userId = req.session.userId; // افتراض أن لديك جلسة مستخدم
    if (!userId) {
        return res.status(401).json({ message: 'Authorization required.' });
    }

    const { xp_earned } = req.body;
    if (typeof xp_earned !== 'number' || xp_earned <= 0) {
        return res.status(400).json({ message: 'Invalid XP amount.' });
    }

    try {
        // 1. جلب معلومات الرفيق الحالية
        // نستخدم علامات الاستفهام '?' لـ MySQL
        let companionResult = await db.query( 
            'SELECT xp, level, evolution_stage, visits_count FROM companion WHERE user_id = ?', 
            [userId]
        );
        // تأكد من أن الرد يحتوي على الصفوف (مثل companionResult[0][0] أو companionResult[0])
        // هنا نفترض أنها مصفوفة من الصفوف، و الصف الأول هو البيانات
        let companion = companionResult[0] ? companionResult[0][0] : { xp: 0, level: 1, evolution_stage: 1, visits_count: 0 };
        
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

        // 4. تحديث جدول الرفيق - استخدام علامات الاستفهام '?' لـ MySQL
        await db.query(
            'UPDATE companion SET xp = ?, level = ?, evolution_stage = ?, visits_count = ? WHERE user_id = ?',
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
// =======================================
// 🧠 Health check + تشغيل السيرفر
// =======================================
app.get("/", (_, res) => {
  res.json({ ok: true, message: "🚀 HEQ server is running smoothly!" });
});

app.listen(PORT, () => {
  console.log(`✅ Server running on port ${PORT}`);
});





















