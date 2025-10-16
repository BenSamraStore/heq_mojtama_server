// ========================================  
// HEQ Server (v2) - قاعدة بيانات متقدمة  
// ========================================  
const express = require("express");  
const cors = require("cors");  
const sqlite3 = require("sqlite3").verbose();  
const bcrypt = require("bcryptjs");  
const nodemailer = require("nodemailer");  
const jwt = require("jsonwebtoken");  
const fs = require("fs");          
const path = require("path");       

const app = express();  
const PORT = 3000;  
const SECRET_KEY = "HEQ_SUPER_SECRET_KEY";
const REFRESH_SECRET = "HEQ_REFRESH_SECRET_KEY";  
const ACCESS_EXPIRES_IN = "2h";                    
const REFRESH_EXPIRES_DAYS = 30;                  

// إعداد مجلد الرفع + serve static  
const UPLOADS_DIR = path.join(__dirname, "uploads");  
if (!fs.existsSync(UPLOADS_DIR)) {  
  fs.mkdirSync(UPLOADS_DIR, { recursive: true });  
}  
 

// 🧩 بعد المجلد مباشرة نفعّل multer  
const multer = require("multer");
const upload = multer({ dest: UPLOADS_DIR });  

// middlewares  
app.use(cors());  
app.use(express.json({ limit: "5mb" }));

app.use("/uploads", express.static(UPLOADS_DIR));  
  
// ====== قاعدة البيانات ======  
const db = new sqlite3.Database("./heq_mojtama.db", (err) => {  
  if (err) console.error("❌ فشل الاتصال بقاعدة البيانات:", err);  
  else console.log("📦 قاعدة بيانات HEQ جاهزة");  
}); 
function ensureColumn(table, columnDef) {  
  const colName = columnDef.split(" ")[0];  
  db.all(`PRAGMA table_info(${table})`, (err, cols) => {  
    if (err) return console.error("PRAGMA error:", err.message);  
    const exists = Array.isArray(cols) && cols.some(c => c.name === colName);  
    if (!exists) {  
      db.run(`ALTER TABLE ${table} ADD COLUMN ${columnDef}`, (e) => {  
        if (e) console.error(`ALTER TABLE add ${colName} error:`, e.message);  
        else console.log(`🧱 Added column ${colName} to ${table}`);  
      });  
    }  
  });  
}   
  
// ====== إنشاء الجداول المتقدمة ======  
db.serialize(() => {  
  // جدول المستخدمين الفعليين  
  db.run(`  
    CREATE TABLE IF NOT EXISTS users (  
      id INTEGER PRIMARY KEY AUTOINCREMENT,  
      email TEXT UNIQUE NOT NULL,  
      password TEXT NOT NULL,  
      name TEXT NOT NULL,  
      bio TEXT DEFAULT '',  
      avatar TEXT DEFAULT '',  
      joined_at INTEGER NOT NULL,  
      verified INTEGER DEFAULT 1  
    )  
  `);  
  
  // جدول المستخدمين المعلّقين قبل التفعيل  
  db.run(`  
    CREATE TABLE IF NOT EXISTS pending_users (  
      id INTEGER PRIMARY KEY AUTOINCREMENT,  
      email TEXT UNIQUE NOT NULL,  
      password TEXT NOT NULL,  
      name TEXT NOT NULL,  
      otp_code TEXT NOT NULL,  
      created_at INTEGER NOT NULL  
    )  
  `);  
  
  // جدول الأكواد (OTP) الإضافي  
  db.run(`  
    CREATE TABLE IF NOT EXISTS otp_codes (  
      id INTEGER PRIMARY KEY AUTOINCREMENT,  
      email TEXT NOT NULL,  
      code TEXT NOT NULL,  
      expires_at INTEGER NOT NULL  
    )  
  `);
  // جدول المنشورات الأساسية
  db.run(`
    CREATE TABLE IF NOT EXISTS posts (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      text TEXT,
      image TEXT,
      agree INTEGER DEFAULT 0,
      disagree INTEGER DEFAULT 0,
      created_at INTEGER NOT NULL,
      FOREIGN KEY(user_id) REFERENCES users(id)
    )
  `);
  // جدول التعليقات (يدعم الردود)
db.run(`
  CREATE TABLE IF NOT EXISTS comments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    post_id INTEGER NOT NULL,
    user_id INTEGER NOT NULL,
    parent_id INTEGER DEFAULT NULL,
    text TEXT NOT NULL,
    agree INTEGER DEFAULT 0,
    disagree INTEGER DEFAULT 0,
    created_at INTEGER NOT NULL,
    FOREIGN KEY(post_id) REFERENCES posts(id),
    FOREIGN KEY(user_id) REFERENCES users(id),
    FOREIGN KEY(parent_id) REFERENCES comments(id)
  )
`);
// جدول تسجيل التفاعلات لكل مستخدم
db.run(`
  CREATE TABLE IF NOT EXISTS reactions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    target_type TEXT NOT NULL, -- 'post' أو 'comment'
    target_id INTEGER NOT NULL,
    action TEXT NOT NULL,      -- 'agree' أو 'disagree'
    UNIQUE(user_id, target_type, target_id)
  )
`);
// جدول الريفريش توكنات
db.run(`
  CREATE TABLE IF NOT EXISTS refresh_tokens (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    token TEXT NOT NULL UNIQUE,
    expires_at INTEGER NOT NULL,
    created_at INTEGER NOT NULL,
    revoked INTEGER DEFAULT 0,
    FOREIGN KEY(user_id) REFERENCES users(id)
  )
`);
// جدول الإشعارات (notifications)
db.run(`
  CREATE TABLE IF NOT EXISTS notifications (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    to_user_id INTEGER,
    title TEXT NOT NULL,
    body TEXT NOT NULL,
    type TEXT DEFAULT 'system',
    meta TEXT DEFAULT '{}',
    is_read INTEGER DEFAULT 0,
    created_at INTEGER NOT NULL,
    FOREIGN KEY(to_user_id) REFERENCES users(id)
  )
`);
// جدول محادثة النظام (system_chat)
db.run(`
  CREATE TABLE IF NOT EXISTS system_chat (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    message TEXT NOT NULL,
    from_admin INTEGER DEFAULT 0,
    created_at INTEGER NOT NULL,
    FOREIGN KEY(user_id) REFERENCES users(id)
  )
`);
// جدول نظام الوصل الحقيقي بين المستخدمين
db.run(`
  CREATE TABLE IF NOT EXISTS connections (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    target_id INTEGER NOT NULL,
    status TEXT DEFAULT 'pending', -- pending | connected | rejected
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    UNIQUE(user_id, target_id),
    FOREIGN KEY(user_id) REFERENCES users(id),
    FOREIGN KEY(target_id) REFERENCES users(id)
  )
`);

// تأمين أعمدة إضافية للبلاغات
ensureColumn("reports", `status TEXT DEFAULT 'open'`);
ensureColumn("reports", `resolution_note TEXT DEFAULT ''`);
ensureColumn("reports", `resolved_at INTEGER DEFAULT 0`);
ensureColumn("reports", `resolver_id INTEGER DEFAULT NULL`);
ensureColumn("users", `show_email INTEGER DEFAULT 0`);


// عمود لتعطيل المستخدمين بدل الحذف النهائي
ensureColumn("users", `disabled INTEGER DEFAULT 0`);
ensureColumn("users", "heq_id TEXT DEFAULT ''");
ensureColumn("users", `flames INTEGER DEFAULT 0`);
ensureColumn("users", `faith_rank TEXT DEFAULT ''`);
ensureColumn("users", `last_faith_activity INTEGER DEFAULT 0`);
ensureColumn("users", `rank_tier TEXT DEFAULT ''`);
// 🧱 تأكد من وجود عمود display_count
db.run(`ALTER TABLE users ADD COLUMN display_count INTEGER DEFAULT 0`, (err) => {
  if (err && !String(err).includes("duplicate column name")) {
    console.error("❌ فشل إضافة العمود display_count:", err.message);
  } else if (!err) {
    console.log("🧩 تمت إضافة العمود display_count بنجاح");
  }
});
// 🔍 تحسين الأداء بالفهرسة
db.run("CREATE INDEX IF NOT EXISTS idx_posts_created ON posts(created_at)");
db.run("CREATE INDEX IF NOT EXISTS idx_comments_post ON comments(post_id)");
db.run("CREATE INDEX IF NOT EXISTS idx_react_target ON reactions(target_type, target_id)");
db.run("CREATE INDEX IF NOT EXISTS idx_notif_to ON notifications(to_user_id, is_read, created_at)");
db.run("CREATE INDEX IF NOT EXISTS idx_chat_user ON system_chat(user_id, created_at)");  
  
  console.log("✅ جميع الجداول جاهزة بنجاح");  
});
// 🧑‍💻 إنشاء حساب أدمن افتراضي (مرة واحدة فقط)
db.get("SELECT id FROM users WHERE is_admin = 1 LIMIT 1", (err, row) => {
  if (err) return console.error("❌ خطأ أثناء التحقق من الأدمن:", err.message);
  if (row) {
    console.log("ℹ️ يوجد أدمن مسبقاً — لن يتم الإنشاء مجدداً");
    return;
  }

  try {
    const adminEmail = "hothaifaalsamri@gmail.com"; // ← استبدل بنسختك الكاملة
    const adminPass = "Toka2003So4753268951server"; // ← كلمة مرورك الفعلية مؤقتًا
    const hashed = bcrypt.hashSync(adminPass, 10);

    db.run(
      "INSERT INTO users (email, password, name, is_admin, verified, joined_at) VALUES (?, ?, ?, 1, 1, ?)",
      [adminEmail, hashed, "المطور الرئيسي", Date.now()],
      (e2) => {
        if (e2) console.error("❌ فشل إنشاء حساب الأدمن:", e2.message);
        else console.log(`✅ تم إنشاء حساب الأدمن (${adminEmail}) بنجاح!`);
      }
    );
  } catch (e) {
    console.error("❌ فشل توليد كلمة مرور الأدمن:", e.message);
  }
});

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
// 🔐 ميدلوير للتحقق من أن المستخدم مطور (أدمن رئيسي)
function requireAdmin(req, res, next) {
  const email = req.user && req.user.email;
  if (!email) return res.status(401).json({ error: "جلسة غير صالحة" });

  db.get("SELECT is_admin FROM users WHERE email = ?", [email], (err, row) => {
    if (err) return res.status(500).json({ error: "خطأ في قاعدة البيانات" });
    if (!row || row.is_admin !== 1)
      return res.status(403).json({ error: "🚫 الوصول مرفوض: صلاحيات غير كافية" });

    next(); // ✅ المستخدم مطور فعلاً
  });
}
// 📨 دالة مساعدة لإرسال الإشعارات مع اسم المرسل
function notifyUser(toUserId, title, body, type = "system", meta = {}) {
  const createdAt = Date.now();

  // إذا كان meta فيه sender_id، نجيب اسمه من جدول users
  if (meta.sender_id) {
    db.get(`SELECT name FROM users WHERE id = ?`, [meta.sender_id], (err, sender) => {
      const senderName = (!err && sender) ? sender.name : "مستخدم";

      // نحاول نعدّل النصوص العامة حسب النوع
      let newTitle = title;
      let newBody = body;

      if (type === "comment")
        newBody = `💬 ${senderName} علّق على منشورك`;
      else if (type === "reply")
        newBody = `↩️ ${senderName} ردّ على تعليقك`;
      else if (type === "reaction")
        newBody = `👍 ${senderName} تفاعل مع منشورك`;
      else if (type === "moderation" || type === "system")
        newBody = body; // نخليها كما هي للأنواع الإدارية

      db.run(
        `INSERT INTO notifications (to_user_id, title, body, type, meta, created_at)
         VALUES (?, ?, ?, ?, ?, ?)`,
        [toUserId ?? null, newTitle, newBody, type, JSON.stringify(meta), createdAt],
        (err2) => {
          if (err2) console.error("❌ خطأ أثناء إدخال الإشعار:", err2.message);
          else console.log(`📢 إشعار مرسل إلى المستخدم ${toUserId || "الكل"} من ${senderName}: ${newBody}`);
        }
      );
    });
  } else {
    // في حال ما فيه sender_id (إشعار إداري)
    db.run(
      `INSERT INTO notifications (to_user_id, title, body, type, meta, created_at)
       VALUES (?, ?, ?, ?, ?, ?)`,
      [toUserId ?? null, title, body, type, JSON.stringify(meta), createdAt],
      (err) => {
        if (err) console.error("❌ خطأ أثناء إدخال الإشعار:", err.message);
        else console.log(`📢 إشعار إداري أُرسل إلى ${toUserId || "الكل"}: ${title}`);
      }
    );
  }
}
// 🎫 توليد AccessToken و RefreshToken
function signAccessToken(payload) {
  return jwt.sign(payload, SECRET_KEY, { expiresIn: ACCESS_EXPIRES_IN });
}

function signRefreshToken(payload) {
  return jwt.sign(payload, REFRESH_SECRET, { expiresIn: `${REFRESH_EXPIRES_DAYS}d` });
}

// 🧾 حفظ الريفريش توكن في قاعدة البيانات
function storeRefreshToken(userId, refreshToken, cb) {
  const createdAt = Date.now();
  const expiresAt = Date.now() + REFRESH_EXPIRES_DAYS * 24 * 60 * 60 * 1000;
  db.run(
    `INSERT INTO refresh_tokens (user_id, token, expires_at, created_at) VALUES (?, ?, ?, ?)`,
    [userId, refreshToken, expiresAt, createdAt],
    (err) => cb && cb(err)
  );
}  
// أعمدة جديدة للبروفايل  
ensureColumn("users", `country TEXT DEFAULT ''`);  
ensureColumn("users", `residence TEXT DEFAULT ''`);  
ensureColumn("users", `age INTEGER`);  
ensureColumn("users", `gender TEXT DEFAULT ''`);  
ensureColumn("users", `failed_attempts INTEGER DEFAULT 0`);  
ensureColumn("users", `lock_until INTEGER DEFAULT 0`);
ensureColumn("users", `is_admin INTEGER DEFAULT 0`);  
// ====== اختبار بسيط ======  
app.get("/api/test", (req, res) => {  
  res.json({  
    ok: true,  
    message: "✅ API + DB (v2) ready",  
    time: new Date().toISOString(),  
  });  
});  
  
// ====== إعداد البريد الإلكتروني (Nodemailer) ======  
const transporter = nodemailer.createTransport({  
  service: "gmail",  
  auth: {  
    user: "hajeenheq@gmail.com", // ← غيّرها لاحقًا لإيميلك  
    pass: "nybbokijgakumhjf"  
  }  
});  
  
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
  
    // تحقق من صيغة البريد  
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;  
    if (!emailRegex.test(email)) return res.status(400).json({ error: "صيغة البريد غير صالحة" });  
  
    // تحقق إن كان البريد مسجل مسبقاً  
    db.get("SELECT * FROM users WHERE email = ?", [email], async (err, userRow) => {  
      if (err) return res.status(500).json({ error: "خطأ في قاعدة البيانات" });  
      if (userRow) return res.status(400).json({ error: "هذا البريد مستخدم بالفعل" });  
  
      // تحقق من المعلقين أيضًا  
      db.get("SELECT * FROM pending_users WHERE email = ?", [email], async (err, pendingRow) => {  
        if (err) return res.status(500).json({ error: "خطأ في قاعدة البيانات" });  
        if (pendingRow) return res.status(400).json({ error: "رمز التفعيل أُرسل مسبقاً، تحقق من بريدك" });  
  
        // تشفير كلمة السر  
        const hashed = await bcrypt.hash(password, 10);  
        const otp = generateOTP();  
        const createdAt = Date.now();  
  
        // إدخال المستخدم المؤقت  
        db.run(  
          "INSERT INTO pending_users (email, password, name, otp_code, created_at) VALUES (?, ?, ?, ?, ?)",  
          [email, hashed, name, otp, createdAt],  
          async (err2) => {  
            if (err2) {  
              console.error(err2);  
              return res.status(500).json({ error: "فشل إنشاء الحساب المؤقت" });  
            }  
  
            // إرسال الإيميل  
            const mailOptions = {  
              from: "HEQ المجتمع <heq.verify@gmail.com>",  
              to: email,  
              subject: "رمز التفعيل لحسابك في HEQ",  
              html: `  
                <div style="font-family:Arial;padding:20px;">  
                  <h2>رمز تفعيل حسابك في HEQ المجتمع</h2>  
                  <p>مرحبًا ${name} 👋،</p>  
                  <p>رمز التفعيل الخاص بك هو:</p>  
                  <h1 style="color:#007BFF;letter-spacing:3px;">${otp}</h1>  
                  <p>ينتهي الرمز خلال <b>10 دقائق</b>.</p>  
                </div>  
              `  
            };  
  
            transporter.sendMail(mailOptions, (error, info) => {  
              if (error) {  
                console.error(error);  
                return res.status(500).json({ error: "فشل إرسال رمز التفعيل" });  
              }  
  
              // تخزين الكود في جدول otp_codes  
              const expiresAt = Date.now() + 10 * 60 * 1000; // 10 دقائق  
              db.run(  
                "INSERT INTO otp_codes (email, code, expires_at) VALUES (?, ?, ?)",  
                [email, otp, expiresAt]  
              );  
  
              res.json({  
                ok: true,  
                message: "📧 تم إرسال رمز التفعيل إلى بريدك الإلكتروني",  
                email  
              });  
            });  
          }  
        );  
      });  
    });  
  } catch (err) {  
    console.error(err);  
    res.status(500).json({ error: "حدث خطأ داخلي في الخادم" });  
  }  
});  
// ====== تأكيد رمز التفعيل ======  
// ====== تأكيد رمز التفعيل ======  
app.post("/api/verify", (req, res) => {  
  const { email, code } = req.body;  
  if (!email || !code)  
    return res.status(400).json({ error: "يرجى إدخال البريد الإلكتروني والرمز" });  
  
  // التحقق من وجود الكود وصلاحيته  
  db.get(  
    "SELECT * FROM otp_codes WHERE email = ? AND code = ?",  
    [email, code],  
    (err, otpRow) => {  
      if (err) return res.status(500).json({ error: "خطأ في قاعدة البيانات" });  
      if (!otpRow) return res.status(400).json({ error: "رمز غير صحيح ❌" });  
  
      if (Date.now() > otpRow.expires_at)  
        return res.status(400).json({ error: "⏳ انتهت صلاحية الرمز" });  
  
      // جلب المستخدم المؤقت  
      db.get(  
        "SELECT * FROM pending_users WHERE email = ?",  
        [email],  
        (err2, userRow) => {  
          if (err2) return res.status(500).json({ error: "فشل في جلب المستخدم" });  
          if (!userRow)  
            return res.status(400).json({ error: "لم يتم العثور على المستخدم المؤقت" });  
  
         // إدخاله ضمن المستخدمين الرسميين  
const joinedAt = Date.now();  
db.run(  
  "INSERT INTO users (email, password, name, bio, avatar, joined_at, verified) VALUES (?, ?, ?, '', '', ?, 1)",  
  [userRow.email, userRow.password, userRow.name, joinedAt],  
  function (err3) {
  // 🎫 توليد HEQ-ID المنسق للمستخدم الجديد
const heqId = `HEQ${String(this.lastID).padStart(5, '0')}`;
db.run("UPDATE users SET heq_id = ? WHERE id = ?", [heqId, this.lastID], (err) => {
  if (err) console.error("⚠️ فشل تحديث HEQ-ID:", err.message);
  else console.log(`🆔 تم تعيين HEQ-ID: ${heqId}`);
}); // ← انتبه: function عادية مش سهم  
    if (err3) {  
      console.error("❌ خطأ أثناء النقل:", err3.message);  
      return res.status(500).json({ error: "فشل أثناء إنشاء الحساب النهائي" });  
    }  
  
    // تنظيف الجداول المؤقتة بعد النجاح  
    db.run("DELETE FROM pending_users WHERE email = ?", [email]);  
    db.run("DELETE FROM otp_codes WHERE email = ?", [email]);  
  
   // 🎫 إنشاء توكنات الدخول
const payload = { email: userRow.email, id: this.lastID };
const token = signAccessToken(payload);
const refreshToken = signRefreshToken(payload);

// 🧾 تخزين الريفريش توكن بقاعدة البيانات
storeRefreshToken(this.lastID, refreshToken, (err4) => {
  if (err4) console.error("⚠️ خطأ أثناء حفظ الريفريش:", err4.message);
});

console.log(`✅ تم تفعيل حساب: ${email}`);
// 🧩 زيادة عدد الموصولين للمطور تلقائياً (نظام عددي فقط)
const DEV_EMAIL = "hajeenheq@gmail.com";
db.get(`SELECT id FROM users WHERE email = ?`, [DEV_EMAIL], (errDev, devRow) => {
  if (!errDev && devRow) {
    db.get(`SELECT COUNT(*) AS total FROM users`, (errCount, rowCount) => {
      if (!errCount && rowCount.total > 0) {
        const addValue = 5;
        const updated = (rowCount.total - 1) * addValue; // ناقص 1 حتى لا يحسب المطور نفسه
        db.run(`UPDATE users SET display_count = ? WHERE id = ?`, [updated, devRow.id]);
        console.log(`🔢 تم تحديث عداد الموصولين للمطور إلى ${updated}`);
      }
    });
  }
});
return res.json({
  ok: true,
  message: "✅ تم تفعيل الحساب بنجاح! جاري توجيهك لإكمال الملف الشخصي.",
  token,
  refreshToken
});
  }  
);  
        }  
      );  
    }  
  );  
});  
// ===== تسجيل الدخول (مع الحظر التلقائي بعد 5 محاولات) =====  
app.post("/api/login", (req, res) => {  
  const { email, password } = req.body;  
  if (!email || !password)  
    return res.status(400).json({ error: "أدخل البريد وكلمة المرور" });  
  
  db.get("SELECT * FROM users WHERE email = ?", [email], async (err, user) => {  
    if (err) return res.status(500).json({ error: "خطأ في قاعدة البيانات" });  
    if (!user) return res.status(400).json({ error: "الحساب غير موجود" });
    if (user.disabled) {
    return res.status(403).json({
      error: "🚫 تم تعطيل حسابك. يرجى التواصل مع المطوّر لاستعادة الوصول."
    });
  }  

  
  
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
        db.run(  
          "UPDATE users SET failed_attempts = ?, lock_until = ? WHERE email = ?",  
          [newFails, lockUntil, email]  
        );  
        return res.status(403).json({  
          error: "🚫 تم تجاوز الحد المسموح من المحاولات. الحساب محظور لمدة 12 ساعة."  
        });  
      } else {  
        db.run("UPDATE users SET failed_attempts = ? WHERE email = ?", [newFails, email]);  
        return res.status(400).json({  
          error: `❌ كلمة المرور غير صحيحة. المحاولة ${newFails} من 5.`  
        });  
      }  
    }  
  
    // في حال النجاح  
    db.run("UPDATE users SET failed_attempts = 0, lock_until = 0 WHERE email = ?", [email]);  
  
    if (!user.verified)  
      return res.status(403).json({ error: "الحساب غير مفعّل بعد" });  
  
    // 🎫 إنشاء توكنات جديدة
const payload = { id: user.id, email: user.email };
const token = signAccessToken(payload);
const refreshToken = signRefreshToken(payload);

// 🧾 تخزين الريفريش توكن بقاعدة البيانات
storeRefreshToken(user.id, refreshToken, (err4) => {
  if (err4) console.error("⚠️ فشل تخزين الريفريش:", err4.message);
});

// ✅ إعادة الاستجابة
res.json({
  ok: true,
  message: "✅ تم تسجيل الدخول بنجاح",
  token,
  refreshToken
});
  });  
});
// ====== تجديد التوكن باستخدام Refresh Token ======
app.post("/api/refresh", (req, res) => {
  const { refreshToken } = req.body;
  if (!refreshToken) return res.status(400).json({ error: "refreshToken مفقود" });

  // التحقق من وجوده في قاعدة البيانات
  db.get(
    "SELECT * FROM refresh_tokens WHERE token = ? AND revoked = 0",
    [refreshToken],
    (err, row) => {
      if (err) return res.status(500).json({ error: "خطأ في قاعدة البيانات" });
      if (!row) return res.status(401).json({ error: "توكن غير معروف أو ملغى" });
      if (Date.now() > row.expires_at)
        return res.status(401).json({ error: "انتهت صلاحية الـ Refresh Token" });

      // التحقق من سلامة التوقيع
      jwt.verify(refreshToken, REFRESH_SECRET, (err2, payload) => {
        if (err2) return res.status(401).json({ error: "توكن غير صالح" });

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
    }
  );
});
// ====== نسيان كلمة المرور (إرسال رمز إعادة التعيين) ======
app.post("/api/forgot_password", (req, res) => {
  const { email } = req.body;
  if (!email) return res.status(400).json({ error: "يرجى إدخال البريد الإلكتروني" });

  // التحقق من وجود المستخدم
  db.get("SELECT * FROM users WHERE email = ?", [email], (err, user) => {
    if (err) return res.status(500).json({ error: "خطأ في قاعدة البيانات" });
    if (!user) return res.status(404).json({ error: "لم يتم العثور على هذا البريد" });

    // حذف أي أكواد قديمة له
    db.run("DELETE FROM otp_codes WHERE email = ?", [email]);

    // توليد رمز جديد
    const otp = generateOTP();
    const expiresAt = Date.now() + 10 * 60 * 1000; // 10 دقائق

    // تخزين الرمز في جدول otp_codes
    db.run(
      "INSERT INTO otp_codes (email, code, expires_at) VALUES (?, ?, ?)",
      [email, otp, expiresAt],
      (err2) => {
        if (err2) {
          console.error(err2);
          return res.status(500).json({ error: "فشل إنشاء رمز الاستعادة" });
        }

        // إرسال الإيميل
        const mailOptions = {
          from: "HEQ المجتمع <heq.verify@gmail.com>",
          to: email,
          subject: "رمز استعادة كلمة المرور - HEQ المجتمع",
          html: `
            <div style="font-family:Arial;padding:20px;">
              <h2>طلب استعادة كلمة المرور</h2>
              <p>مرحبًا 👋، لقد طلبت إعادة تعيين كلمة المرور لحسابك.</p>
              <p>رمز التفعيل الخاص بك هو:</p>
              <h1 style="color:#007BFF;letter-spacing:3px;">${otp}</h1>
              <p>ينتهي الرمز خلال <b>10 دقائق</b>.</p>
              <p>إذا لم تطلب هذا، يمكنك تجاهل هذه الرسالة.</p>
            </div>
          `
        };

        transporter.sendMail(mailOptions, (error, info) => {
          if (error) {
            console.error(error);
            return res.status(500).json({ error: "فشل إرسال البريد الإلكتروني" });
          }

          console.log(`📧 تم إرسال رمز استعادة لكلمة المرور إلى ${email}: ${otp}`);
          res.json({ ok: true, message: "📨 تم إرسال رمز الاستعادة إلى بريدك الإلكتروني" });
        });
      }
    );
  });
});
// ====== التحقق من رمز استعادة كلمة المرور ======
app.post("/api/verify_reset_code", (req, res) => {
  const { email, code } = req.body;
  if (!email || !code)
    return res.status(400).json({ error: "يرجى إدخال البريد الإلكتروني والرمز" });

  db.get(
    "SELECT * FROM otp_codes WHERE email = ? AND code = ?",
    [email, code],
    (err, otpRow) => {
      if (err) return res.status(500).json({ error: "خطأ في قاعدة البيانات" });
      if (!otpRow) return res.status(400).json({ error: "رمز غير صحيح ❌" });

      if (Date.now() > otpRow.expires_at)
        return res.status(400).json({ error: "⏳ انتهت صلاحية الرمز، اطلب رمزاً جديداً" });

      // ✅ الرمز صالح
      res.json({ ok: true, message: "✅ الرمز صالح، يمكنك الآن تعيين كلمة مرور جديدة." });
    }
  );
}); 
// ====== إعادة تعيين كلمة المرور ======
app.post("/api/reset_password", async (req, res) => {
  try {
    const { email, newPassword, confirmPassword } = req.body;

    if (!email || !newPassword || !confirmPassword)
      return res.status(400).json({ error: "يرجى إدخال جميع الحقول المطلوبة" });

    if (newPassword !== confirmPassword)
      return res.status(400).json({ error: "❌ كلمتا المرور غير متطابقتين" });

    // تحقق من الطول
    if (newPassword.length < 12)
      return res.status(400).json({ error: "⚠️ كلمة المرور يجب أن تحتوي على 12 رمز على الأقل." });

    // تحقق من احتوائها على أحرف وأرقام
    const hasLetters = /[A-Za-z]/.test(newPassword);
    const hasNumbers = /\d/.test(newPassword);
    if (!hasLetters || !hasNumbers)
      return res.status(400).json({ error: "⚠️ كلمة المرور يجب أن تحتوي على أحرف وأرقام معاً." });

    // تحقق من وجود المستخدم
    db.get("SELECT * FROM users WHERE email = ?", [email], async (err, user) => {
      if (err) return res.status(500).json({ error: "خطأ في قاعدة البيانات" });
      if (!user) return res.status(404).json({ error: "لم يتم العثور على هذا البريد" });

      // تشفير الكلمة الجديدة
      const hashed = await bcrypt.hash(newPassword, 10);

      // تحديث كلمة المرور
      db.run("UPDATE users SET password = ? WHERE email = ?", [hashed, email], (err2) => {
        if (err2) return res.status(500).json({ error: "فشل في تحديث كلمة المرور" });

        // حذف أي رموز OTP متبقية له
        db.run("DELETE FROM otp_codes WHERE email = ?", [email]);

        console.log(`🔐 تم تغيير كلمة المرور بنجاح للمستخدم: ${email}`);
        res.json({ ok: true, message: "✅ تم تحديث كلمة المرور بنجاح! يمكنك الآن تسجيل الدخول." });
      });
    });
  } catch (err) {
    console.error("❌ خطأ داخلي:", err);
    res.status(500).json({ error: "حدث خطأ داخلي في الخادم" });
  }
}); 
// فحص المستخدمين الموجودين  
app.get("/api/debug/users", (req, res) => {  
  db.all("SELECT * FROM users", (err, rows) => {  
    if (err) return res.status(500).json({ error: err.message });  
    res.json(rows);  
  });  
});  
  
// فحص المعلقين  
app.get("/api/debug/pending", (req, res) => {  
  db.all("SELECT * FROM pending_users", (err, rows) => {  
    if (err) return res.status(500).json({ error: err.message });  
    res.json(rows);  
  });  
});
// ====== ترقيه مستخدم ليصبح مطوّر (مرة واحدة فقط) ======
app.post("/api/make_admin", (req, res) => {
  const { email } = req.body;
  if (!email) return res.status(400).json({ error: "يرجى إدخال البريد الإلكتروني" });

  db.run("UPDATE users SET is_admin = 1 WHERE email = ?", [email], function (err) {
    if (err) return res.status(500).json({ error: "خطأ في قاعدة البيانات" });
    if (this.changes === 0)
      return res.status(404).json({ error: "لم يتم العثور على هذا البريد" });

    res.json({ ok: true, message: `✅ تمت ترقية ${email} ليصبح مطوراً` });
  });
});  
// ====== تحديث الملف الشخصي بعد التفعيل ======
app.post("/api/profile", auth, async (req, res) => {
  try {
    const email = req.user.email;
    if (!email) return res.status(401).json({ error: "جلسة غير صالحة" });

    const { name, bio, country, residence, age, gender, avatarBase64, show_email } = req.body;

    // حضّر الـ SET بشكل ديناميكي حسب الحقول المرسلة فقط
    const setClauses = [];
    const params = [];
    if (typeof name !== "undefined") { 
  setClauses.push("name = ?"); 
  params.push(name); 
}
    if (typeof bio !== "undefined")       { setClauses.push("bio = ?");        params.push(bio); }
    if (typeof country !== "undefined")   { setClauses.push("country = ?");    params.push(country); }
    if (typeof residence !== "undefined") { setClauses.push("residence = ?");  params.push(residence); }
    if (typeof age !== "undefined")       { setClauses.push("age = ?");        params.push(age ?? null); }
    if (typeof gender !== "undefined")    { setClauses.push("gender = ?");     params.push(gender); }
    if (typeof show_email !== "undefined"){ setClauses.push("show_email = ?"); params.push(show_email ? 1 : 0); }

    // حفظ الصورة فقط إذا وصلت
    if (avatarBase64 && avatarBase64.startsWith("data:image")) {
      const fileName = `avatar_${Date.now()}.png`;
      const avatarPath = `${req.protocol}://${req.get("host")}/uploads/${fileName}`;
      const base64Data = avatarBase64.replace(/^data:image\/\w+;base64,/, "");
      fs.writeFileSync(path.join(UPLOADS_DIR, fileName), base64Data, "base64");
      setClauses.push("avatar = ?");
      params.push(avatarPath);
    }

    if (setClauses.length === 0) {
      return res.json({ ok: true, message: "لا توجد تغييرات للتحديث." });
    }

    params.push(email);
    const sql = `UPDATE users SET ${setClauses.join(", ")} WHERE email = ?`;

    db.run(sql, params, function (err) {
      if (err) {
        console.error("❌ خطأ أثناء تحديث الملف الشخصي:", err);
        return res.status(500).json({ error: "فشل تحديث البيانات" });
      }
      res.json({ ok: true, message: "✅ تم تحديث الملف الشخصي بنجاح" });
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "حدث خطأ داخلي في الخادم" });
  }
});
app.get("/api/me", auth, (req, res) => {  
  const email = req.user && req.user.email;  
  if (!email) return res.status(401).json({ error: "جلسة غير صالحة" });  
  
  db.get(`SELECT id, heq_id, email, name, bio, avatar, country, residence, age, gender,
joined_at, show_email, faith_rank, flames, rank_tier
FROM users WHERE email = ?`, 
  [email], 
  (err, row) => {
    if (err) return res.status(500).json({ error: "خطأ في قاعدة البيانات" });  
    if (!row) return res.status(404).json({ error: "المستخدم غير موجود" });  
  
    const profileCompleted = Boolean(  
      (row.bio && row.bio.trim().length > 0) ||  
      (row.avatar && row.avatar.trim().length > 0) ||  
      (row.country && row.country.trim().length > 0) ||  
      (row.residence && row.residence.trim().length > 0)  
    );  
  
    const safeEmail = row.show_email ? row.email : ""; 
  
    return res.json({  
      ok: true,  
      user: {  
        id: row.id,
        heq_id: row.heq_id,  
        email: safeEmail,  
        name: row.name,  
        bio: row.bio,  
        avatar: row.avatar,  
        country: row.country,  
        residence: row.residence,  
        age: row.age,  
        gender: row.gender,  
        joined_at: row.joined_at,  
        show_email: row.show_email,
        faith_rank: row.faith_rank,
flames: row.flames,
rank_tier: row.rank_tier  
      },  
      profileCompleted  
    });  
  });  
});
// ====== جلب جميع المنشورات (عام) ======
app.get("/api/posts", (req, res) => {
  db.all(
    `SELECT 
  p.id, p.user_id, p.text, p.image, p.agree, p.disagree, p.created_at,
  u.name AS author_name,
u.avatar AS author_avatar,
u.faith_rank AS author_rank,
u.rank_tier AS author_tier,       -- ✅ نوع الشارة (فضية، ذهبية، ألماسية)
u.flames AS author_flames
FROM posts p
JOIN users u ON u.id = p.user_id
ORDER BY p.created_at DESC`,
    [],
    (err, rows) => {
      if (err) {
        console.error("❌ خطأ في جلب المنشورات:", err);
        return res.status(500).json({ error: "خطأ في جلب المنشورات" });
      }
      res.json({ ok: true, posts: rows });
    }
  );
});
app.post("/api/posts", auth, upload.single("image"), (req, res) => {
  const { text } = req.body;
  const userId = req.user.id;

  // 🧠 فحص الحظر أو التعطيل
  db.get("SELECT disabled, lock_until FROM users WHERE id = ?", [userId], (err, user) => {
    if (err) return res.status(500).json({ error: "فشل التحقق من صلاحيات المستخدم" });

    if (user.disabled) {
      return res.status(403).json({ error: "🚫 حسابك معطّل. لا يمكنك النشر أو التفاعل." });
    }

    if (user.lock_until && user.lock_until > Date.now()) {
      const diffH = Math.ceil((user.lock_until - Date.now()) / (1000 * 60 * 60));
      return res.status(403).json({ error: `⏳ حسابك محظور مؤقتًا (${diffH} ساعة متبقية).` });
    }

    // تابع عملية النشر كالمعتاد ⤵️
    if (!text && !req.file)
      return res.status(400).json({ error: "يرجى كتابة نص أو رفع صورة" });

    let imagePath = null;
    if (req.file)
      imagePath = `${req.protocol}://${req.get("host")}/uploads/${req.file.filename}`;

    const createdAt = Date.now();
    db.run(
      `INSERT INTO posts (user_id, text, image, created_at) VALUES (?, ?, ?, ?)`,
      [userId, text || "", imagePath, createdAt],
      function (err2) {
        if (err2)
          return res.status(500).json({ error: "فشل إنشاء المنشور" });
        res.json({
          ok: true,
          id: this.lastID,
          message: "✅ تم نشر المنشور بنجاح",
          image: imagePath,
        });
      }
    );
  });
});
// إنشاء تعليق جديد
app.post("/api/comments", auth, (req, res) => {
  const { post_id, parent_id, text } = req.body;
  const userId = req.user.id;

  if (!text || !post_id)
    return res.status(400).json({ error: "النص والمعرف مطلوبان" });

  // 🧠 فحص الحظر أو التعطيل
  db.get("SELECT disabled, lock_until FROM users WHERE id = ?", [userId], (err, user) => {
    if (err) return res.status(500).json({ error: "فشل التحقق من صلاحيات المستخدم" });

    if (user.disabled) {
      return res.status(403).json({ error: "🚫 حسابك معطّل. لا يمكنك التعليق." });
    }

    if (user.lock_until && user.lock_until > Date.now()) {
      const diffH = Math.ceil((user.lock_until - Date.now()) / (1000 * 60 * 60));
      return res.status(403).json({ error: `⏳ حسابك محظور مؤقتًا (${diffH} ساعة متبقية).` });
    }

    // 🟢 مسموح له بالتعليق
    const createdAt = Date.now();
    db.run(
      `INSERT INTO comments (post_id, user_id, parent_id, text, created_at)
       VALUES (?, ?, ?, ?, ?)`,
      [post_id, userId, parent_id || null, text, createdAt],
      function (err2) {
        if (err2) {
          console.error("❌ خطأ أثناء إضافة التعليق:", err2);
          return res.status(500).json({ error: "فشل إنشاء التعليق" });
        }
        // 🧠 بعد نجاح إنشاء التعليق، أرسل إشعار لصاحب المنشور أو التعليق
if (!parent_id) {
  // 📢 تعليق جديد على منشور
  db.get(`SELECT user_id FROM posts WHERE id = ?`, [post_id], (err3, postOwner) => {
    if (!err3 && postOwner && postOwner.user_id !== userId) {
      notifyUser(
        postOwner.user_id,
        "💬 تعليق جديد على منشورك",
        "قام أحد المستخدمين بالتعليق على منشورك.",
        "comment",
        { post_id, comment_id: this.lastID, sender_id: userId }
      );
    }
  });
} else {
  // 📢 رد على تعليق
  db.get(`SELECT user_id FROM comments WHERE id = ?`, [parent_id], (err4, parentOwner) => {
    if (!err4 && parentOwner && parentOwner.user_id !== userId) {
      notifyUser(
        parentOwner.user_id,
        "↩️ رد على تعليقك",
        "قام أحد المستخدمين بالرد على تعليقك.",
        "reply",
        { post_id, parent_id, comment_id: this.lastID, sender_id: userId }
      );
    }
  });
}

       // 🧩 جلب اسم المرسل لواجهة العميل
db.get(`SELECT name FROM users WHERE id = ?`, [userId], (errName, userRow) => {
  const fromUser = (!errName && userRow) ? userRow.name : "مستخدم";
  res.json({
    ok: true,
    id: this.lastID,
    message: "✅ تم إضافة التعليق بنجاح",
    target_user_id: parent_id ? null : post_id, // (placeholder، سنعدله لاحقًا إذا أردت)
    author_name: fromUser
  });
});
      }
    );
  });
});
// جلب جميع التعليقات لمنشور معين
app.get("/api/comments/:postId", (req, res) => {
  const postId = req.params.postId;

  db.all(
    `SELECT 
   c.*, 
   u.name AS author_name, 
u.avatar AS author_avatar,
u.faith_rank AS author_rank,
u.rank_tier AS author_tier,       -- ✅ إضافة نفس العمود
u.flames AS author_flames
 FROM comments c
 JOIN users u ON u.id = c.user_id
 WHERE c.post_id = ?
 ORDER BY c.created_at ASC`,
    [postId],
    (err, rows) => {
      if (err) {
        console.error("❌ خطأ في جلب التعليقات:", err);
        return res.status(500).json({ error: "فشل في جلب التعليقات" });
      }
      res.json({ ok: true, comments: rows });
    }
  );
});
// ====== نظام تفاعل متطور (تصويت مرة واحدة) ======
app.post("/api/react", auth, (req, res) => {
  const { type, targetId, action } = req.body; // type = post | comment
  const userId = req.user.id;

  if (!type || !targetId || !["agree", "disagree"].includes(action)) {
    return res.status(400).json({ error: "طلب غير صالح" });
  }

  // 🧠 فحص حالة الحساب قبل التفاعل
  db.get("SELECT disabled, lock_until FROM users WHERE id = ?", [userId], (err, user) => {
    if (err) return res.status(500).json({ error: "فشل التحقق من حالة الحساب" });

    if (user.disabled) {
      return res.status(403).json({ error: "🚫 حسابك معطّل. لا يمكنك التفاعل." });
    }

    if (user.lock_until && user.lock_until > Date.now()) {
      const diffH = Math.ceil((user.lock_until - Date.now()) / (1000 * 60 * 60));
      return res.status(403).json({ error: `⏳ حسابك محظور مؤقتًا (${diffH} ساعة متبقية).` });
    }

    // 🟢 إذا الحساب سليم نكمل
    let table;
if (type === "post") table = "posts";
else if (type === "comment") table = "comments";
else return res.status(400).json({ error: "نوع الهدف غير معروف" });

    db.get(
      `SELECT * FROM reactions WHERE user_id = ? AND target_type = ? AND target_id = ?`,
      [userId, type, targetId],
      (err2, row) => {
        if (err2) return res.status(500).json({ error: "خطأ في قاعدة البيانات" });

        // 🔹 الحالة 1: المستخدم لم يصوت من قبل
        if (!row) {
          db.run(
            `INSERT INTO reactions (user_id, target_type, target_id, action) VALUES (?, ?, ?, ?)`,
            [userId, type, targetId, action],
            (err3) => {
              if (err3)
                return res.status(500).json({ error: "فشل تسجيل التصويت" });

              db.run(
                `UPDATE ${table} SET ${action} = ${action} + 1 WHERE id = ?`,
                [targetId],
                function (err4) {
                  if (err4)
                    return res.status(500).json({ error: "فشل تحديث العدّاد" });
                  sendCounts();
                }
              );
            }
          );
        }

        // 🔹 الحالة 2: ضغط نفس الزر مرة ثانية → حذف التصويت
        else if (row.action === action) {
          db.run(`DELETE FROM reactions WHERE id = ?`, [row.id], (err5) => {
            if (err5)
              return res.status(500).json({ error: "فشل حذف التصويت" });

            db.run(
              `UPDATE ${table} SET ${action} = ${action} - 1 WHERE id = ? AND ${action} > 0`,
              [targetId],
              function (err6) {
                if (err6)
                  return res.status(500).json({ error: "فشل تعديل العدّاد" });
                sendCounts();
              }
            );
          });
        }

        // 🔹 الحالة 3: غيّر رأيه
        else {
          db.run(
            `UPDATE reactions SET action = ? WHERE id = ?`,
            [action, row.id],
            (err7) => {
              if (err7)
                return res.status(500).json({ error: "فشل تعديل التصويت" });

              const opposite = action === "agree" ? "disagree" : "agree";
              db.run(
                `UPDATE ${table} 
                 SET ${action} = ${action} + 1, ${opposite} = CASE WHEN ${opposite} > 0 THEN ${opposite} - 1 ELSE 0 END 
                 WHERE id = ?`,
                [targetId],
                function (err8) {
                  if (err8)
                    return res.status(500).json({ error: "فشل تحديث العدّاد" });
                  sendCounts();
                }
              );
            }
          );
        }

        // دالة لجلب القيم الجديدة بعد أي تعديل
        function sendCounts() {
          db.get(
            `SELECT agree, disagree FROM ${table} WHERE id = ?`,
            [targetId],
            (err9, updated) => {
              if (err9)
                return res.status(500).json({ error: "فشل جلب البيانات الجديدة" });

              const targetTable = type === "post" ? "posts" : "comments";
const ownerQuery = `SELECT user_id FROM ${targetTable} WHERE id = ?`;

db.get(ownerQuery, [targetId], (errOwner, ownerRow) => {
  db.get(`SELECT name FROM users WHERE id = ?`, [userId], (errName, userRow) => {
    const fromUser = (!errName && userRow) ? userRow.name : "مستخدم";
    const targetUserId = (!errOwner && ownerRow) ? ownerRow.user_id : null;

    res.json({
      ok: true,
      agree: updated.agree,
      disagree: updated.disagree,
      from_user: fromUser,
      target_user_id: targetUserId
    });
  });

  // 🔔 إرسال الإشعار بعد الرد مباشرة
  if (!errOwner && ownerRow && ownerRow.user_id !== userId && action === "agree") {
    const notifTitle = type === "post"
      ? "👍 تفاعل مع منشورك"
      : "👍 تفاعل مع تعليقك";
    const notifBody = type === "post"
      ? "قام أحد المستخدمين بالإعجاب بمنشورك."
      : "قام أحد المستخدمين بالإعجاب بتعليقك.";

    notifyUser(
      ownerRow.user_id,
      notifTitle,
      notifBody,
      "reaction",
      { target_type: type, target_id: targetId, sender_id: userId }
    );
  }
});
              // 🔔 إرسال إشعار لصاحب المنشور أو التعليق
if (action === "agree") {
  const targetTable = type === "post" ? "posts" : "comments";
  const ownerQuery = `SELECT user_id FROM ${targetTable} WHERE id = ?`;

  db.get(ownerQuery, [targetId], (errOwner, ownerRow) => {
    if (!errOwner && ownerRow && ownerRow.user_id !== userId) {
      const notifTitle = type === "post" 
        ? "👍 تفاعل مع منشورك" 
        : "👍 تفاعل مع تعليقك";
      const notifBody = type === "post" 
        ? "قام أحد المستخدمين بالإعجاب بمنشورك." 
        : "قام أحد المستخدمين بالإعجاب بتعليقك.";

      notifyUser(
        ownerRow.user_id,
        notifTitle,
        notifBody,
        "reaction",
        { target_type: type, target_id: targetId, sender_id: userId }
      );
    }
  });
}
            }
          );
        }
      }
    );
  });
});

// ====== تعديل منشور ======
app.put("/api/posts/:id", auth, upload.single("image"), (req, res) => {
  const postId = req.params.id;
  const userId = req.user.id;
  const { text } = req.body;

  db.get("SELECT * FROM posts WHERE id = ?", [postId], (err, post) => {
    if (err) return res.status(500).json({ error: "خطأ في قاعدة البيانات" });
    if (!post) return res.status(404).json({ error: "المنشور غير موجود" });
    if (post.user_id !== userId)
      return res.status(403).json({ error: "❌ لا يمكنك تعديل منشور غيرك" });

    let imagePath = post.image;
    if (req.file) {
      imagePath = `${req.protocol}://${req.get("host")}/uploads/${req.file.filename}`;
    }

    db.run(
      "UPDATE posts SET text = ?, image = ? WHERE id = ?",
      [text || post.text, imagePath, postId],
      (err2) => {
        if (err2) return res.status(500).json({ error: "فشل تعديل المنشور" });
        res.json({ ok: true, message: "✅ تم تعديل المنشور بنجاح", image: imagePath });
      }
    );
  });
});
// ====== حذف منشور ======
app.delete("/api/posts/:id", auth, (req, res) => {
  const postId = req.params.id;
  const userId = req.user.id;

  db.get("SELECT * FROM posts WHERE id = ?", [postId], (err, post) => {
    if (err) return res.status(500).json({ error: "خطأ في قاعدة البيانات" });
    if (!post) return res.status(404).json({ error: "المنشور غير موجود" });
    if (post.user_id !== userId)
      return res.status(403).json({ error: "❌ لا يمكنك حذف منشور غيرك" });

    db.run("DELETE FROM posts WHERE id = ?", [postId], (err2) => {
      if (err2) return res.status(500).json({ error: "فشل حذف المنشور" });
      res.json({ ok: true, message: "🗑️ تم حذف المنشور بنجاح" });
    });
  });
});
// ====== إرسال بلاغ ======
db.run(`
  CREATE TABLE IF NOT EXISTS reports (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    post_id INTEGER NOT NULL,
    reason TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    FOREIGN KEY(user_id) REFERENCES users(id),
    FOREIGN KEY(post_id) REFERENCES posts(id)
  )
`);

app.post("/api/report", auth, (req, res) => {
  const { post_id, reason } = req.body;
  const userId = req.user.id;

  if (!post_id || !reason)
    return res.status(400).json({ error: "يجب إدخال سبب الإبلاغ ومعرف المنشور" });

  const createdAt = Date.now();
  db.run(
    "INSERT INTO reports (user_id, post_id, reason, created_at) VALUES (?, ?, ?, ?)",
    [userId, post_id, reason, createdAt],
    function (err) {
      if (err) {
        console.error("❌ فشل إرسال البلاغ:", err);
        return res.status(500).json({ error: "فشل إرسال البلاغ" });
      }
      res.json({ ok: true, message: "🚩 تم إرسال البلاغ بنجاح" });
    }
  );
});
// ====== حفظ منشور ======
db.run(`
  CREATE TABLE IF NOT EXISTS saved_posts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    post_id INTEGER NOT NULL,
    saved_at INTEGER NOT NULL,
    UNIQUE(user_id, post_id),
    FOREIGN KEY(user_id) REFERENCES users(id),
    FOREIGN KEY(post_id) REFERENCES posts(id)
  )
`);

app.post("/api/saved", auth, (req, res) => {
  const { post_id } = req.body;
  const userId = req.user.id;

  if (!post_id) return res.status(400).json({ error: "رقم المنشور مطلوب" });

  const savedAt = Date.now();
  db.run(
    "INSERT OR IGNORE INTO saved_posts (user_id, post_id, saved_at) VALUES (?, ?, ?)",
    [userId, post_id, savedAt],
    (err) => {
      if (err) {
        console.error("❌ خطأ أثناء حفظ المنشور:", err);
        return res.status(500).json({ error: "فشل حفظ المنشور" });
      }
      res.json({ ok: true, message: "💾 تم حفظ المنشور في المفضلة!" });
    }
  );
});
// ====== فحص صلاحية المطور ======
app.get("/api/check_admin", auth, (req, res) => {
  const email = req.user.email;
  db.get("SELECT is_admin FROM users WHERE email = ?", [email], (err, row) => {
    if (err) return res.status(500).json({ error: "خطأ في قاعدة البيانات" });
    if (!row || row.is_admin !== 1)
      return res.status(403).json({ ok: false, message: "ليس مطوراً" });

    res.json({ ok: true, message: "المستخدم مطور معتمد ✅" });
  });
});
// ====== إدارة المستخدمين ======
app.get("/api/admin/users", auth, requireAdmin, (req, res) => {
  db.all(`SELECT id, email, name, is_admin, verified, disabled, failed_attempts, lock_until, joined_at FROM users ORDER BY joined_at DESC`, [], (err, rows) => {
    if (err) return res.status(500).json({ error: "خطأ في قاعدة البيانات" });
    res.json({ ok: true, users: rows });
  });
});

// حظر مؤقت
app.post("/api/admin/users/:id/ban", auth, requireAdmin, (req, res) => {
  const uid = +req.params.id;
  const hours = Math.max(1, +req.body.hours || 12);
  const reason = (req.body.reason || "مخالفة القواعد").trim();
  const lockUntil = Date.now() + hours * 3600 * 1000;

  db.run(`UPDATE users SET lock_until=? WHERE id=?`, [lockUntil, uid], function (err) {
    if (err || this.changes === 0) return res.status(500).json({ error: "فشل الحظر" });
    notifyUser(uid, "تم حظرك مؤقتًا", `تم حظر حسابك لمدة ${hours} ساعة.\nالسبب: ${reason}`, "moderation");
    res.json({ ok: true, message: "تم الحظر المؤقت وإرسال إشعار" });
  });
});

// رفع الحظر
app.post("/api/admin/users/:id/unban", auth, requireAdmin, (req, res) => {
  const uid = +req.params.id;
  db.run(`UPDATE users SET lock_until=0, failed_attempts=0 WHERE id=?`, [uid], function (err) {
    if (err || this.changes === 0) return res.status(500).json({ error: "فشل رفع الحظر" });
    notifyUser(uid, "تم رفع الحظر", "أصبح حسابك فعّالًا من جديد.", "moderation");
    res.json({ ok: true });
  });
});

// تعطيل حساب نهائي
app.post("/api/admin/users/:id/disable", auth, requireAdmin, (req, res) => {
  const uid = +req.params.id;
  const reason = (req.body.reason || "مخالفة القواعد").trim();
  db.run(`UPDATE users SET disabled=1 WHERE id=?`, [uid], function (err) {
    if (err || this.changes === 0) return res.status(500).json({ error: "فشل التعطيل" });
    notifyUser(uid, "تم تعطيل حسابك", `السبب: ${reason}`, "moderation");
    res.json({ ok: true });
  });
});
// ✅ تمكين حساب (فك التعطيل)
app.post("/api/admin/users/:id/enable", auth, requireAdmin, (req, res) => {
  const uid = +req.params.id;
  db.run(`UPDATE users SET disabled=0 WHERE id=?`, [uid], function (err) {
    if (err || this.changes === 0)
      return res.status(500).json({ error: "فشل في تمكين الحساب أو الحساب غير موجود" });

    notifyUser(uid, "✅ تم تفعيل حسابك من جديد", "يمكنك الآن استخدام المجتمع بحرية.", "moderation");
    res.json({ ok: true, message: "✅ تم تمكين الحساب بنجاح" });
  });
});

// ترقية إلى مطور
app.post("/api/admin/users/:id/promote", auth, requireAdmin, (req, res) => {
  const uid = +req.params.id;
  db.run(`UPDATE users SET is_admin=1 WHERE id=?`, [uid], function (err) {
    if (err || this.changes === 0) return res.status(500).json({ error: "فشل الترقية" });
    notifyUser(uid, "ترقية حسابك", "🎉 تمت ترقيتك إلى مطوّر النظام", "system");
    res.json({ ok: true });
  });
});
// ====== إدارة المنشورات ======
app.get("/api/admin/posts", auth, requireAdmin, (req, res) => {
  db.all(`
    SELECT p.id, p.user_id, u.name AS author_name, p.text, p.image, p.agree, p.disagree, p.created_at
    FROM posts p JOIN users u ON u.id = p.user_id
    ORDER BY p.created_at DESC
  `, [], (err, rows) => {
    if (err) return res.status(500).json({ error: "فشل جلب المنشورات" });
    res.json({ ok: true, posts: rows });
  });
});

app.post("/api/admin/posts/:id/delete", auth, requireAdmin, (req, res) => {
  const pid = +req.params.id;
  const reason = (req.body.reason || "مخالفة القواعد").trim();
  db.get(`SELECT user_id FROM posts WHERE id=?`, [pid], (err, row) => {
    if (err || !row) return res.status(404).json({ error: "المنشور غير موجود" });
    const owner = row.user_id;

    db.run(`DELETE FROM posts WHERE id=?`, [pid], (err2) => {
      if (err2) return res.status(500).json({ error: "فشل الحذف" });
      notifyUser(owner, "تم حذف منشورك", `السبب: ${reason}`, "moderation", { post_id: pid });
      res.json({ ok: true, message: "تم حذف المنشور وإشعار صاحبه" });
    });
  });
});
// ====== إدارة البلاغات ======
app.get("/api/admin/reports", auth, requireAdmin, (req, res) => {
  db.all(`
    SELECT r.*, u.name AS reporter_name, p.text AS post_text
    FROM reports r
    JOIN users u ON u.id = r.user_id
    JOIN posts p ON p.id = r.post_id
    ORDER BY r.created_at DESC
  `, [], (err, rows) => {
    if (err) return res.status(500).json({ error: "فشل جلب البلاغات" });
    res.json({ ok: true, reports: rows });
  });
});

app.post("/api/admin/reports/:id/resolve", auth, requireAdmin, (req, res) => {
  const rid = +req.params.id;
  const action = (req.body.action || "تم التحقق").trim();
  const note = (req.body.note || "").trim();
  const resolverId = req.user.id;

  db.get(`SELECT user_id FROM reports WHERE id=?`, [rid], (err, rp) => {
    if (err || !rp) return res.status(404).json({ error: "البلاغ غير موجود" });

    db.run(
      `UPDATE reports SET status='resolved', resolution_note=?, resolved_at=?, resolver_id=? WHERE id=?`,
      [note || action, Date.now(), resolverId, rid],
      function (err2) {
        if (err2) return res.status(500).json({ error: "فشل تحديث البلاغ" });
        notifyUser(rp.user_id, "تمت معالجة بلاغك", `النتيجة: ${action}\n${note}`, "moderation");
        res.json({ ok: true, message: "تم إنهاء البلاغ وإشعار المبلّغ" });
      }
    );
  });
});
// ====== إرسال إشعار عام أو موجه ======
app.post("/api/admin/notify", auth, requireAdmin, (req, res) => {
  const { to_user_id = null, title, body, type = "broadcast", meta = {} } = req.body || {};
  if (!title || !body) return res.status(400).json({ error: "العنوان والمحتوى مطلوبان" });
  notifyUser(to_user_id ? +to_user_id : null, title, body, type, meta);
  res.json({ ok: true, message: "تم إرسال الإشعار بنجاح" });
});
// ====== جلب إشعارات المستخدم ======
app.get("/api/notifications", auth, (req, res) => {
  const uid = req.user.id;
  db.all(
    `SELECT * FROM notifications 
     WHERE to_user_id IS NULL OR to_user_id = ?
     ORDER BY created_at DESC LIMIT 100`,
    [uid],
    (err, rows) => {
      if (err) return res.status(500).json({ error: "فشل جلب الإشعارات" });
      res.json({ ok: true, notifications: rows });
    }
  );
});
// 💻 3. المطور يجلب كل المحادثات مع المستخدمين
app.get("/api/admin/chat/users", auth, requireAdmin, (req, res) => {
  db.all(
    `SELECT DISTINCT u.id, u.name, u.email, u.avatar
     FROM users u
     JOIN system_chat s ON s.user_id = u.id
     ORDER BY u.name ASC`,
    [],
    (err, rows) => {
      if (err) return res.status(500).json({ error: "فشل جلب المستخدمين" });
      res.json({ ok: true, users: rows });
    }
  );
});

// 📜 4. المطور يفتح محادثة مستخدم محدد
app.get("/api/admin/chat/:user_id", auth, requireAdmin, (req, res) => {
  const uid = +req.params.user_id;
  db.all(
    `SELECT * FROM system_chat WHERE user_id = ? ORDER BY created_at ASC`,
    [uid],
    (err, rows) => {
      if (err) return res.status(500).json({ error: "فشل جلب المحادثة" });
      res.json({ ok: true, messages: rows });
    }
  );
});

// 📨 5. المطور يرد على مستخدم
app.post("/api/admin/chat/reply", auth, requireAdmin, (req, res) => {
  const { to_user_id, message } = req.body;
  if (!to_user_id || !message?.trim())
    return res.status(400).json({ error: "بيانات ناقصة" });

  const createdAt = Date.now();
  db.run(
    `INSERT INTO system_chat (user_id, message, from_admin, created_at)
     VALUES (?, ?, 1, ?)`,
    [to_user_id, message.trim(), createdAt],
    function (err) {
      if (err) {
        console.error("❌ خطأ أثناء إرسال الرد:", err.message);
        return res.status(500).json({ error: "فشل إرسال الرد" });
      }

      // 🔔 إشعار فوري للمستخدم
      notifyUser(
        to_user_id,
        "💬 رد من النظام",
        message.trim(),
        "system",
        { chat_reply: true }
      );

      res.json({ ok: true, message: "✅ تم إرسال الرد للمستخدم" });
    }
  );
});
// ====== تعليم جميع إشعارات المستخدم كمقروءة ======
app.post("/api/notifications/read_all", auth, (req, res) => {
  const uid = req.user.id;
  db.run(
    `UPDATE notifications SET is_read = 1 WHERE to_user_id = ?`,
    [uid],
    function (err) {
      if (err) {
        console.error("❌ فشل تحديث حالة الإشعارات:", err);
        return res.status(500).json({ error: "فشل تحديث حالة الإشعارات" });
      }
      res.json({
        ok: true,
        message: `✅ تم تعليم ${this.changes} إشعار كمقروء.`,
      });
    }
  );
});
// ====== 🧩 نظام المحادثة الإدارية (System Chat) ======

// 📨 1. المستخدم يرسل رسالة للمطور
app.post("/api/chat/send", auth, (req, res) => {
  const { message } = req.body;
  const userId = req.user.id;
  const msg = (message || "").trim();
  if (!msg) return res.status(400).json({ error: "الرسالة فارغة" });
  if (msg.length > 2000) return res.status(400).json({ error: "الرسالة طويلة جدًا (الحد الأقصى 2000 حرف)" });

 

  const createdAt = Date.now();
  db.run(
    `INSERT INTO system_chat (user_id, message, from_admin, created_at)
     VALUES (?, ?, 0, ?)`,
    [userId, message.trim(), createdAt],
    function (err) {
      if (err) {
        console.error("❌ خطأ أثناء إرسال الرسالة:", err.message);
        return res.status(500).json({ error: "فشل إرسال الرسالة" });
      }
      res.json({ ok: true, message: "✅ تم إرسال الرسالة للمطور" });
    }
  );
});

// 💬 2. المستخدم يجلب سجل المحادثة الخاص به
app.get("/api/chat/history", auth, (req, res) => {
  const userId = req.user.id;
  db.all(
    `SELECT * FROM system_chat WHERE user_id = ? ORDER BY created_at ASC`,
    [userId],
    (err, rows) => {
      if (err) {
        console.error("❌ خطأ في جلب المحادثة:", err.message);
        return res.status(500).json({ error: "فشل جلب المحادثة" });
      }
      res.json({ ok: true, messages: rows });
    }
  );
});
// ====== 📬 إنشاء إشعار من واجهة المستخدم (مثلاً عند التفاعل أو التعليق) ======
app.post("/api/notifications", auth, (req, res) => {
  const { to_user_id, title, body, type = "system", meta = {} } = req.body;
  const senderId = req.user.id;

  if (!to_user_id || !body) {
    return res.status(400).json({ error: "الحقول المطلوبة ناقصة" });
  }

  notifyUser(to_user_id, title || "إشعار جديد", body, type, { ...meta, sender_id: senderId });
  res.json({ ok: true, message: "✅ تم إرسال الإشعار بنجاح" });
});
app.get("/api/users/:id", (req, res) => {
  const userId = parseInt(req.params.id);
  if (isNaN(userId)) return res.json({ ok: false, error: "رقم مستخدم غير صالح" });

  db.get(
    "SELECT id, heq_id, name, email, bio, country, age, gender, avatar, show_email, faith_rank, flames, rank_tier FROM users WHERE id = ?",
    [userId],
    (err, user) => {
      if (err) {
        console.error("خطأ في قاعدة البيانات:", err);
        return res.json({ ok: false, error: "خطأ في قاعدة البيانات" });
      }

      if (!user) return res.json({ ok: false, error: "لم يتم العثور على المستخدم." });

      if (!user.show_email) user.email = null;

      res.json({ ok: true, user });
    }
  );
});
// =========================================
// 🔍 البحث عن المستخدمين بالاسم أو HEQ-ID
// =========================================
app.get("/api/search", auth, (req, res) => {
  const q = (req.query.query || "").trim();
  if (!q) return res.json({ ok: false, error: "الكلمة فارغة" });

  const likeQuery = `%${q}%`;
  db.all(
    `SELECT id, heq_id, name, avatar 
     FROM users 
     WHERE name LIKE ? OR heq_id LIKE ? 
     LIMIT 5`,
    [likeQuery, likeQuery],
    (err, rows) => {
      if (err) return res.status(500).json({ ok: false, error: "خطأ في قاعدة البيانات" });
      if (!rows || rows.length === 0) {
        return res.json({ ok: true, users: [] });
      }

      // تنظيف النتائج
      const cleanUsers = rows.map(u => ({
        id: u.id,
        heq_id: u.heq_id,
        name: u.name || "مستخدم بدون اسم",
        avatar: u.avatar || "assets/default-avatar.png"
      }));

      return res.json({ ok: true, users: cleanUsers });
    }
  );
});
// =======================================
// 🤝 نظام الوصل الحقيقي بين المستخدمين
// =======================================

// 🔹 1. فحص الحالة الحالية بين المستخدمين
app.get("/api/connect/status/:targetId", auth, (req, res) => {
  const userId = req.user.id;
  const targetId = +req.params.targetId;

  if (userId === targetId)
    return res.json({ status: "self", direction: "self" });

  db.get(
    `SELECT * FROM connections 
     WHERE (user_id=? AND target_id=?) OR (user_id=? AND target_id=?)`,
    [userId, targetId, targetId, userId],
    (err, row) => {
      if (err) return res.status(500).json({ error: "خطأ في قاعدة البيانات" });
      if (!row) return res.json({ status: "none", direction: "none" });

      // 🔍 تحديد اتجاه الطلب
      let direction = "none";
      if (row.user_id === userId && row.target_id === targetId) direction = "outgoing";
      else if (row.user_id === targetId && row.target_id === userId) direction = "incoming";

      // 🔹 نرجع الاستجابة كاملة مع الـ direction
      res.json({
        status: row.status,        // pending | connected | rejected
        direction,                 // incoming | outgoing
        requester_id: row.user_id, // لمعرفة الطرف الآخر
        target_id: row.target_id
      });
    }
  );
});

// 🔹 2. إرسال طلب وصل
app.post("/api/connect", auth, (req, res) => {
  const userId = req.user.id;
  const { target_id } = req.body;
  const targetId = +target_id;

  if (!targetId || userId === targetId)
    return res.status(400).json({ error: "طلب غير صالح" });

  const now = Date.now();

  db.run(
    `INSERT OR REPLACE INTO connections (user_id, target_id, status, created_at, updated_at)
     VALUES (?, ?, 'pending', ?, ?)`,
    [userId, targetId, now, now],
    function (err) {
      if (err) return res.status(500).json({ error: "فشل إرسال الطلب" });

      // 🔔 إشعار لصاحب الحساب الآخر
      notifyUser(
        targetId,
        "🔗 طلب وصل جديد",
        "قام أحد المستخدمين بإرسال طلب وصل إليك.",
        "connect_request",
        { sender_id: userId }
      );

      res.json({ ok: true, message: "✅ تم إرسال طلب الوصل بنجاح" });
    }
  );
});

// 🔹 3. فك الوصل أو إلغاء الطلب
app.delete("/api/connect", auth, (req, res) => {
  const userId = req.user.id;
  const { target_id } = req.body;
  const targetId = +target_id;

  if (!targetId || userId === targetId)
    return res.status(400).json({ error: "طلب غير صالح" });

  db.run(
    `DELETE FROM connections 
     WHERE (user_id=? AND target_id=?) OR (user_id=? AND target_id=?)`,
    [userId, targetId, targetId, userId],
    function (err) {
      if (err) return res.status(500).json({ error: "فشل فك الوصل" });
      res.json({ ok: true, message: "💔 تم فك الوصل بنجاح" });
    }
  );
});
// =======================================
// ✅ قبول أو رفض طلب الوصل
// =======================================
app.post("/api/connect/respond", auth, (req, res) => {
  const userId = req.user.id;
  const { requester_id, action } = req.body; // action = accept | reject
  const now = Date.now();

  if (!requester_id || !["accept", "reject"].includes(action))
    return res.status(400).json({ error: "طلب غير صالح" });

  // تحقق إن فعلاً في طلب وصل موجه له
  db.get(
    `SELECT * FROM connections WHERE user_id=? AND target_id=? AND status='pending'`,
    [requester_id, userId],
    (err, row) => {
      if (err) return res.status(500).json({ error: "خطأ في قاعدة البيانات" });
      if (!row) return res.status(404).json({ error: "لم يتم العثور على الطلب" });

      if (action === "accept") {
        // تحديث الحالة إلى connected + إنشاء سجل معاكس لضمان التناسق
        db.serialize(() => {
          db.run(
            `UPDATE connections SET status='connected', updated_at=? WHERE id=?`,
            [now, row.id]
          );

          // إدخال السجل العكسي إن لم يكن موجودًا
          db.run(
            `INSERT OR IGNORE INTO connections (user_id, target_id, status, created_at, updated_at)
             VALUES (?, ?, 'connected', ?, ?)`,
            [userId, requester_id, now, now]
          );

          // إشعار لصاحب الطلب الأصلي
          notifyUser(
            requester_id,
            "🤝 تم قبول طلب الوصل",
            "قام المستخدم بقبول طلبك بالوصل!",
            "connect_accept",
            { sender_id: userId }
          );

          res.json({ ok: true, message: "✅ تم قبول الطلب بنجاح" });
        });
      } else {
        // رفض الطلب
        db.run(
          `DELETE FROM connections WHERE user_id=? AND target_id=? AND status='pending'`,
          [requester_id, userId],
          function (err2) {
            if (err2)
              return res.status(500).json({ error: "فشل حذف الطلب" });

            notifyUser(
              requester_id,
              "❌ تم رفض طلب الوصل",
              "قام المستخدم برفض طلبك بالوصل.",
              "connect_reject",
              { sender_id: userId }
            );

            res.json({ ok: true, message: "❌ تم رفض الطلب" });
          }
        );
      }
    }
  );
});
// =======================================
// 🔢 جلب عدد الموصولين مع نظام العدّ الذكي للمطور
// =======================================
const DEV_EMAIL = "hothaifaalsamri@gmail.com"; // ← غيّرها لو الإيميل تغيّر لاحقاً

// دالة مساعدة لجلب العدد الكلي للمستخدمين
function getTotalUsers(callback) {
  db.get(`SELECT COUNT(*) AS total FROM users`, [], (err, row) => {
    if (err) return callback(err, 0);
    callback(null, row.total);
  });
}

// 🔸 1. جلب عدد الموصولين لمستخدم محدد
app.get("/api/connect/count/:userId", auth, (req, res) => {
  const targetId = +req.params.userId;
  if (!targetId) return res.status(400).json({ error: "رقم المستخدم غير صالح" });

  db.get(
    `SELECT COUNT(*) AS total FROM connections
     WHERE (user_id = ? OR target_id = ?) AND status = 'connected'`,
    [targetId, targetId],
    (err, row) => {
      if (err) return res.status(500).json({ error: "فشل جلب عدد الموصولين" });
      const connectedCount = row.total || 0;

      // نتحقق إن كان المستخدم هو المطور
      db.get(`SELECT email FROM users WHERE id = ?`, [targetId], (err2, urow) => {
        if (err2) return res.status(500).json({ error: "خطأ في قاعدة البيانات" });
        if (urow && urow.email === DEV_EMAIL) {
          // حساب البونص للمطور
          getTotalUsers((err3, totalUsers) => {
            if (err3) return res.status(500).json({ error: "فشل حساب عدد المستخدمين" });
            const bonus = Math.max(0, totalUsers - 1) * 5;
            res.json({
              ok: true,
              count: connectedCount,
              bonus,
              display_count: connectedCount + bonus,
            });
          });
        } else {
          res.json({ ok: true, count: connectedCount, bonus: 0, display_count: connectedCount });
        }
      });
    }
  );
});

// 🔸 2. جلب عدد الموصولين للمستخدم الحالي
app.get("/api/connect/count/me", auth, (req, res) => {
  const myId = req.user.id;
  db.get(
    `SELECT COUNT(*) AS total FROM connections
     WHERE (user_id = ? OR target_id = ?) AND status = 'connected'`,
    [myId, myId],
    (err, row) => {
      if (err) return res.status(500).json({ error: "فشل جلب عدد الموصولين" });
      const connectedCount = row.total || 0;

      db.get(`SELECT email FROM users WHERE id = ?`, [myId], (err2, urow) => {
        if (err2) return res.status(500).json({ error: "خطأ في قاعدة البيانات" });
        if (urow && urow.email === DEV_EMAIL) {
          getTotalUsers((err3, totalUsers) => {
            if (err3) return res.status(500).json({ error: "فشل حساب عدد المستخدمين" });
            const bonus = Math.max(0, totalUsers - 1) * 5;
            res.json({
              ok: true,
              count: connectedCount,
              bonus,
              display_count: connectedCount + bonus,
            });
          });
        } else {
          res.json({ ok: true, count: connectedCount, bonus: 0, display_count: connectedCount });
        }
      });
    }
  );
});
// 🔥 تحديث عدد الشعلات والشارة الحالية
app.post("/api/faith/update", auth, (req, res) => {
  const userId = req.user.id;
  const { flames, faith_rank } = req.body || {};

  if (typeof flames === "undefined" && typeof faith_rank === "undefined")
    return res.status(400).json({ error: "لا يوجد بيانات للتحديث" });

  db.run(
    `UPDATE users 
     SET 
       flames = COALESCE(?, flames), 
       faith_rank = COALESCE(?, faith_rank),
       last_faith_activity = strftime('%s','now')
     WHERE id = ?`,
    [flames, faith_rank, userId],
    function (err) {
      if (err) {
        console.error("❌ فشل تحديث الشعلات:", err.message);
        return res.status(500).json({ error: "خطأ في قاعدة البيانات" });
      }

      // 📨 إشعار عند الترقية إلى شارة جديدة
      if (typeof faith_rank === "string" && faith_rank.trim()) {
        notifyUser(
          userId,
          "🎖️ ترقية شارتك",
          `🎉 تمت ترقيتك إلى ${faith_rank}! استمر في نشر الخير 🔥`,
          "rank_upgrade",
          { sender_id: userId, faith_rank }
        );
      }

      // 💎 تحديد نوع الشارة بأمان
      let rankTier = null;
      const rankName = (faith_rank || "").toString();
      if (rankName.includes("مساهم")) rankTier = "silver";
      else if (rankName.includes("ناشر")) rankTier = "gold";
      else if (rankName.includes("لا يترك")) rankTier = "diamond";

      // ⚠️ لا تعمل ALTER TABLE هنا كل مرة (تظل كما هي إن بدك تبقيها، بس الأفضل تكون بأعلى الملف)
      // تحديث نوع الشارة إذا متوفر
      if (rankTier) {
        db.run(
          `UPDATE users SET rank_tier = ? WHERE id = ?`,
          [rankTier, userId],
          (errTier) => {
            if (errTier)
              console.error("⚠️ فشل تحديث نوع الشارة:", errTier.message);
            else
              console.log(`🏅 تم تحديث rank_tier للمستخدم ${userId} → ${rankTier}`);
          }
        );
      }

      res.json({ ok: true, message: "✅ تم تحديث الشعلات بنجاح" });
    }
  );
});
app.get("/api/faith/me", auth, (req, res) => {
  const userId = req.user.id;

  db.get(
    "SELECT flames, faith_rank FROM users WHERE id = ?",
    [userId],
    (err, row) => {
      if (err) {
        console.error("❌ فشل جلب بيانات الشعلات:", err.message);
        return res.status(500).json({ error: "فشل في قاعدة البيانات" });
      }

      res.json({
        ok: true,
        faith: row || { flames: 0, faith_rank: "" },
      });
    }
  );
});
app.post("/api/faith/check_reset", auth, (req, res) => {
  const userId = req.user.id;

  db.get(
    "SELECT last_faith_activity, flames, faith_rank FROM users WHERE id = ?",
    [userId],
    (err, row) => {
      if (err || !row) return res.json({ ok: false });

      const now = Math.floor(Date.now() / 1000);
      const diffDays = (now - row.last_faith_activity) / 86400;

      // 🕒 إذا غاب أكثر من 3 أيام وكان عنده شعلات فعلاً
      if (diffDays >= 3 && row.flames > 0) {
        db.run(
          "UPDATE users SET flames = 0, faith_rank = '', last_faith_activity = strftime('%s','now') WHERE id = ?",
          [userId],
          (err2) => {
            if (err2) {
              console.error("❌ فشل تصفير الشعلات:", err2.message);
              return res.status(500).json({ ok: false, error: "فشل التصفير" });
            }

            // 📨 إشعار للمستخدم بعد التصفير
            notifyUser(
              userId,
              "⏳ استئناف نشاطك الإيماني",
              "تم تصفير الشعلات بعد غياب 3 أيام. نورتنا! ابدأ من جديد 🤍",
              "faith_reset",
              { sender_id: userId }
            );

            res.json({
              ok: true,
              reset: true,
              message: "🔥 تم تصفير الشعلات بعد غيابك 3 أيام",
            });
          }
        );
      } else {
        res.json({ ok: true, reset: false });
      }
    }
  );
});
// 🛰️ إرجاع حالة الإيمان (الشعلات والشارة)
app.get("/api/faith/status", auth, (req, res) => {
  db.get(
    "SELECT flames AS total_flames, faith_rank AS rank FROM users WHERE id = ?",
    [req.user.id],
    (err, row) => {
      if (err) {
        console.error("❌ خطأ أثناء جلب حالة الإيمان:", err.message);
        return res.json({ ok: false, error: "Server error" });
      }
      if (!row) return res.json({ ok: false, error: "User not found" });
      res.json({ ok: true, status: row });
    }
  );
});
app.post("/api/change_password", auth, async (req, res) => {
  const { oldPassword, newPassword } = req.body;
  const userId = req.user.id;

  if (!oldPassword || !newPassword) {
    return res.status(400).json({ ok: false, error: "الرجاء إدخال جميع الحقول" });
  }

  db.get("SELECT password FROM users WHERE id = ?", [userId], async (err, row) => {
    if (err) return res.status(500).json({ ok: false, error: "خطأ في قاعدة البيانات" });
    if (!row) return res.status(404).json({ ok: false, error: "المستخدم غير موجود" });

    const bcrypt = require("bcryptjs");
    const match = await bcrypt.compare(oldPassword, row.password);
    if (!match) return res.json({ ok: false, error: "❌ كلمة المرور القديمة غير صحيحة" });

    const hashed = await bcrypt.hash(newPassword, 10);
    db.run("UPDATE users SET password = ? WHERE id = ?", [hashed, userId], (err2) => {
      if (err2) return res.status(500).json({ ok: false, error: "فشل تحديث كلمة المرور" });
      res.json({ ok: true, message: "✅ تم تغيير كلمة المرور بنجاح" });
    });
  });
});
app.post("/api/delete_account", auth, (req, res) => {
  const { password } = req.body;
  const userId = req.user.id;

  if (!password) {
    return res.status(400).json({ ok: false, error: "الرجاء إدخال كلمة المرور" });
  }

  db.get("SELECT password FROM users WHERE id = ?", [userId], async (err, row) => {
    if (err) return res.status(500).json({ ok: false, error: "فشل الوصول لقاعدة البيانات" });
    if (!row) return res.status(404).json({ ok: false, error: "المستخدم غير موجود" });

    const bcrypt = require("bcryptjs");
    const match = await bcrypt.compare(password, row.password); // أو == إذا غير مشفرة
    if (!match) return res.json({ ok: false, error: "❌ كلمة المرور غير صحيحة!" });

    // حذف المستخدم
    const tablesToClean = ["posts", "comments", "connections", "notifications", "reactions", "saved_posts", "reports"];
    let done = 0;
    tablesToClean.forEach((table) => {
      db.run(`DELETE FROM ${table} WHERE user_id = ?`, [userId], () => {
        if (++done === tablesToClean.length) {
          db.run(`DELETE FROM users WHERE id = ?`, [userId], (err2) => {
            if (err2) return res.status(500).json({ ok: false, error: "فشل حذف الحساب" });
            console.log(`🗑️ حذف المستخدم ${userId} وجميع بياناته`);
            res.json({ ok: true });
          });
        }
      });
    });
  });
});
// ====== تشغيل الخادم ======  
app.listen(PORT, () => {  
  console.log(`🚀 خادم HEQ يعمل على: http://localhost:${PORT}`);  
});