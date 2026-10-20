const express = require("express");
const session = require("express-session");
const bcrypt = require("bcryptjs");
const Database = require("better-sqlite3");
const multer = require("multer");
const helmet = require("helmet");
const path = require("path");
const fs = require("fs");
const crypto = require("crypto");

const app = express();
const PORT = process.env.PORT || 3000;

const DATA_DIR = path.join(__dirname, "data");
const UPLOAD_DIR = path.join(__dirname, "uploads");
const PUBLIC_DIR = path.join(__dirname, "public");

for (const dir of [DATA_DIR, UPLOAD_DIR, PUBLIC_DIR]) {
  fs.mkdirSync(dir, { recursive: true });
}

const db = new Database(path.join(DATA_DIR, "qalbi.db"));
db.pragma("journal_mode = WAL");
db.pragma("foreign_keys = ON");

db.exec(`
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT UNIQUE NOT NULL,
  display_name TEXT NOT NULL,
  password_hash TEXT NOT NULL,
  role TEXT NOT NULL DEFAULT 'user'
);

CREATE TABLE IF NOT EXISTS media (
  id TEXT PRIMARY KEY,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  type TEXT NOT NULL,
  title TEXT NOT NULL,
  filename TEXT NOT NULL,
  mime TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS messages (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  message TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS surprises (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  title TEXT NOT NULL,
  body TEXT NOT NULL
);
`);

// ترقية قاعدة البيانات الحالية دون حذف الحسابات أو المحتوى.
const columns = db.prepare("PRAGMA table_info(users)").all();

if (!columns.some(column => column.name === "public_token")) {
  db.exec("ALTER TABLE users ADD COLUMN public_token TEXT");
}

const getUsersWithoutToken = db.prepare(`
  SELECT id FROM users
  WHERE public_token IS NULL OR public_token = ''
`);

const setToken = db.prepare(`
  UPDATE users SET public_token = ? WHERE id = ?
`);

const migrateTokens = db.transaction(() => {
  for (const user of getUsersWithoutToken.all()) {
    setToken.run(crypto.randomBytes(32).toString("hex"), user.id);
  }
});

migrateTokens();

db.exec(`
CREATE UNIQUE INDEX IF NOT EXISTS idx_users_public_token
ON users(public_token)
WHERE public_token IS NOT NULL;
`);

// إنشاء حساب افتراضي فقط إذا لم يكن موجودًا.
const existingAdmin = db.prepare(
  "SELECT id FROM users WHERE username = ?"
).get("admin");

if (!existingAdmin) {
  db.prepare(`
    INSERT INTO users
      (username, display_name, password_hash, role, public_token)
    VALUES (?, ?, ?, 'admin', ?)
  `).run(
    "admin",
    "الأدمن",
    bcrypt.hashSync("admin1234", 12),
    crypto.randomBytes(32).toString("hex")
  );

  console.log(
    "Default admin created. Change its password before deployment."
  );
}

app.disable("x-powered-by");

app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", "data:", "blob:"],
      mediaSrc: ["'self'", "blob:"],
      connectSrc: ["'self'"]
    }
  }
}));

app.use(express.json({ limit: "100kb" }));
app.use(express.urlencoded({ extended: false }));

if (process.env.TRUST_PROXY === "1") {
  app.set("trust proxy", 1);
}

if (
  process.env.NODE_ENV === "production" &&
  !process.env.SESSION_SECRET
) {
  throw new Error("Set SESSION_SECRET before production deployment.");
}

app.use(session({
  name: "qalbi.sid",
  secret:
    process.env.SESSION_SECRET ||
    "local-development-only-change-before-deployment",
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    sameSite: "lax",
    secure: process.env.NODE_ENV === "production",
    maxAge: 8 * 60 * 60 * 1000
  }
}));

function requireLogin(req, res, next) {
  if (!req.session.user) {
    return res.status(401).json({ error: "سجّل الدخول الأول" });
  }
  next();
}

function requireAdmin(req, res, next) {
  if (
    !req.session.user ||
    req.session.user.role !== "admin"
  ) {
    return res.status(403).json({
      error: "الصلاحية دي للأدمن فقط"
    });
  }
  next();
}

function requireRegularUser(req, res, next) {
  if (!req.session.user) {
    return res.status(401).json({ error: "سجّل الدخول الأول" });
  }

  if (req.session.user.role !== "user") {
    return res.status(403).json({
      error: "الصفحة دي للمستخدمين فقط"
    });
  }

  next();
}

function cleanUser(user) {
  return {
    id: user.id,
    username: user.username,
    displayName: user.display_name,
    role: user.role
  };
}

function startSession(req, res, user) {
  req.session.regenerate(err => {
    if (err) {
      return res.status(500).json({
        error: "تعذر بدء جلسة الدخول"
      });
    }

    req.session.user = cleanUser(user);

    req.session.save(saveError => {
      if (saveError) {
        return res.status(500).json({
          error: "تعذر حفظ جلسة الدخول"
        });
      }

      res.json({ ok: true, user: req.session.user });
    });
  });
}

const upload = multer({
  storage: multer.diskStorage({
    destination: (req, file, cb) => cb(null, UPLOAD_DIR),
    filename: (req, file, cb) => {
      const ext = path.extname(file.originalname).toLowerCase();
      cb(null, crypto.randomUUID() + ext);
    }
  }),
  limits: {
    fileSize: 100 * 1024 * 1024,
    files: 1
  },
  fileFilter: (req, file, cb) => {
    const allowed = {
      audio: /^audio\/(mpeg|mp4|ogg|wav|webm|aac|x-wav|flac)$/,
      image: /^image\/(jpeg|png|webp|gif)$/,
      video: /^video\/(mp4|webm|ogg|quicktime|x-matroska)$/
    };

    const type = req.params.type;

    if (!allowed[type] || !allowed[type].test(file.mimetype)) {
      return cb(new Error("نوع الملف غير مسموح به"));
    }

    cb(null, true);
  }
});

// الصفحة الرئيسية وصفحة دخول الأدمن المنفصلة.
app.get("/", (req, res) => {
  res.sendFile(path.join(PUBLIC_DIR, "index.html"));
});

app.get("/admin-login", (req, res) => {
  if (req.session.user?.role === "admin") {
    return res.redirect("/admin.html");
  }

  res.sendFile(path.join(PUBLIC_DIR, "index.html"));
});

// الرابط الخاص بالمستخدم العادي.
app.get("/u/:token", (req, res) => {
  const user = db.prepare(`
    SELECT id, role FROM users WHERE public_token = ?
  `).get(req.params.token);

  if (!user || user.role !== "user") {
    return res.status(404).send("الرابط غير صحيح أو لم يعد متاحًا.");
  }

  if (
    req.session.user?.role === "user" &&
    req.session.user.id === user.id
  ) {
    return res.redirect("/my-page.html");
  }

  // ملف صفحة الدخول الخاصة سيُضاف في الخطوة التالية.
  res.sendFile(path.join(PUBLIC_DIR, "user-login.html"));
});

// حماية صفحات HTML من الوصول المباشر دون صلاحية.
app.get("/admin.html", (req, res) => {
  if (req.session.user?.role !== "admin") {
    return res.redirect("/admin-login");
  }

  res.sendFile(path.join(PUBLIC_DIR, "admin.html"));
});

app.get("/my-page.html", (req, res) => {
  if (req.session.user?.role !== "user") {
    return res.redirect("/");
  }

  res.sendFile(path.join(PUBLIC_DIR, "my-page.html"));
});

// منع تقديم صفحة دخول المستخدم الخاصة من مسارها الداخلي مباشرة.
app.get("/user-login.html", (req, res) => {
  res.status(404).send("الصفحة غير متاحة بهذا العنوان.");
});

// دخول الأدمن فقط من صفحة الأدمن.
app.post("/api/login", (req, res) => {
  const { username, password } = req.body || {};

  if (
    typeof username !== "string" ||
    typeof password !== "string" ||
    username.length > 100 ||
    password.length > 200
  ) {
    return res.status(400).json({
      error: "بيانات الدخول غير صحيحة"
    });
  }

  const user = db.prepare(
    "SELECT * FROM users WHERE username = ?"
  ).get(username.trim());

  if (
    !user ||
    user.role !== "admin" ||
    !bcrypt.compareSync(password, user.password_hash)
  ) {
    return res.status(401).json({
      error: "بيانات الأدمن غير صحيحة"
    });
  }

  startSession(req, res, user);
});

// دخول المستخدم بكلمة المرور فقط، من رابطه الخاص.
app.post("/api/user-login/:token", (req, res) => {
  const password = req.body?.password;

  if (
    typeof password !== "string" ||
    password.length === 0 ||
    password.length > 200
  ) {
    return res.status(400).json({
      error: "اكتب كلمة المرور"
    });
  }

  const user = db.prepare(`
    SELECT * FROM users
    WHERE public_token = ? AND role = 'user'
  `).get(req.params.token);

  if (!user || !bcrypt.compareSync(password, user.password_hash)) {
    return res.status(401).json({
      error: "كلمة المرور غير صحيحة"
    });
  }

  startSession(req, res, user);
});

app.get("/api/me", requireLogin, (req, res) => {
  res.json({ user: req.session.user });
});

app.post("/api/logout", requireLogin, (req, res) => {
  req.session.destroy(err => {
    if (err) {
      return res.status(500).json({
        error: "تعذر تسجيل الخروج"
      });
    }

    res.clearCookie("qalbi.sid", {
      httpOnly: true,
      sameSite: "lax",
      secure: process.env.NODE_ENV === "production"
    });

    res.json({ ok: true });
  });
});

// قائمة الحسابات: جميع الأدمنز والمستخدمين.
// الرمز الخاص يظهر للأدمن فقط.
app.get("/api/admin/users", requireAdmin, (req, res) => {
  const users = db.prepare(`
    SELECT id, username, display_name, role, public_token
    FROM users ORDER BY id DESC
  `).all().map(user => ({
    ...cleanUser(user),
    publicToken: user.public_token
  }));

  res.json({ users });
});

// إنشاء مستخدم عادي أو أدمن جديد.
app.post("/api/admin/users", requireAdmin, (req, res) => {
  const { username, displayName, password } = req.body || {};
  const role = req.body?.role === "admin" ? "admin" : "user";

  if (
    typeof username !== "string" ||
    !/^[a-zA-Z0-9_.-]{3,40}$/.test(username)
  ) {
    return res.status(400).json({
      error: "اسم الدخول من 3 إلى 40 حرفًا إنجليزيًا أو رقمًا"
    });
  }

  if (
    typeof displayName !== "string" ||
    !displayName.trim() ||
    displayName.length > 100
  ) {
    return res.status(400).json({
      error: "اكتب الاسم الظاهر"
    });
  }

  if (typeof password !== "string" || password.length < 8) {
    return res.status(400).json({
      error: "كلمة المرور لازم تكون 8 أحرف على الأقل"
    });
  }

  try {
    const result = db.prepare(`
      INSERT INTO users
        (username, display_name, password_hash, role, public_token)
      VALUES (?, ?, ?, ?, ?)
    `).run(
      username.trim(),
      displayName.trim(),
      bcrypt.hashSync(password, 12),
      role,
      crypto.randomBytes(32).toString("hex")
    );

    res.json({
      ok: true,
      id: result.lastInsertRowid,
      role
    });
  } catch (err) {
    if (String(err.code || "").startsWith("SQLITE_CONSTRAINT")) {
      return res.status(409).json({
        error: "اسم الدخول مستخدم بالفعل؛ اختار اسمًا مختلفًا"
      });
    }

    throw err;
  }
});

// حذف حساب آخر. لا يمكن للأدمن حذف حسابه الحالي.
app.delete("/api/admin/users/:id", requireAdmin, (req, res) => {
  const id = Number(req.params.id);

  if (!Number.isSafeInteger(id) || id <= 0) {
    return res.status(400).json({
      error: "رقم المستخدم غير صحيح"
    });
  }

  if (id === req.session.user.id) {
    return res.status(400).json({
      error: "لا يمكنك حذف حسابك الذي تستخدمه حاليًا"
    });
  }

  const user = db.prepare(
    "SELECT id, role FROM users WHERE id = ?"
  ).get(id);

  if (!user) {
    return res.status(404).json({
      error: "الحساب غير موجود"
    });
  }

  const files = db.prepare(
    "SELECT filename FROM media WHERE user_id = ?"
  ).all(id);

  db.prepare("DELETE FROM users WHERE id = ?").run(id);

  for (const file of files) {
    try {
      fs.unlinkSync(path.join(UPLOAD_DIR, file.filename));
    } catch (err) {
      console.error("Could not remove uploaded file:", err.message);
    }
  }

  res.json({ ok: true });
});

app.post(
  "/api/admin/media/:type/:userId",
  requireAdmin,
  (req, res, next) => {
    upload.single("file")(req, res, err => {
      if (err) {
        return res.status(400).json({ error: err.message });
      }
      next();
    });
  },
  (req, res) => {
    const userId = Number(req.params.userId);
    const type = req.params.type;

    if (!["audio", "image", "video"].includes(type)) {
      if (req.file) fs.unlink(req.file.path, () => {});
      return res.status(400).json({
        error: "نوع المحتوى غير صحيح"
      });
    }

    const user = db.prepare(`
      SELECT id FROM users WHERE id = ? AND role = 'user'
    `).get(userId);

    if (!user || !req.file) {
      if (req.file) fs.unlink(req.file.path, () => {});
      return res.status(400).json({
        error: "اختار مستخدمًا وملفًا صحيحًا"
      });
    }

    const title = String(
      req.body.title || req.file.originalname
    ).slice(0, 200);

    const id = crypto.randomUUID();

    db.prepare(`
      INSERT INTO media (id, user_id, type, title, filename, mime)
      VALUES (?, ?, ?, ?, ?, ?)
    `).run(id, userId, type, title, req.file.filename, req.file.mimetype);

    res.json({ ok: true, id });
  }
);

app.post("/api/admin/messages/:userId", requireAdmin, (req, res) => {
  const userId = Number(req.params.userId);
  const message = req.body?.message;

  if (!Number.isSafeInteger(userId) || userId <= 0) {
    return res.status(400).json({ error: "المستخدم غير صحيح" });
  }

  if (
    typeof message !== "string" ||
    !message.trim() ||
    message.length > 3000
  ) {
    return res.status(400).json({
      error: "اكتب رسالة بحد أقصى 3000 حرف"
    });
  }

  const user = db.prepare(
    "SELECT id FROM users WHERE id = ? AND role = 'user'"
  ).get(userId);

  if (!user) {
    return res.status(404).json({ error: "المستخدم غير موجود" });
  }

  const result = db.prepare(`
    INSERT INTO messages (user_id, message) VALUES (?, ?)
  `).run(userId, message.trim());

  res.json({ ok: true, id: result.lastInsertRowid });
});

app.post("/api/admin/surprises/:userId", requireAdmin, (req, res) => {
  const userId = Number(req.params.userId);
  const { title, body } = req.body || {};

  if (
    !Number.isSafeInteger(userId) ||
    userId <= 0 ||
    typeof title !== "string" ||
    !title.trim() ||
    title.length > 200 ||
    typeof body !== "string" ||
    !body.trim() ||
    body.length > 3000
  ) {
    return res.status(400).json({
      error: "راجع عنوان وتفاصيل المفاجأة"
    });
  }

  const user = db.prepare(
    "SELECT id FROM users WHERE id = ? AND role = 'user'"
  ).get(userId);

  if (!user) {
    return res.status(404).json({ error: "المستخدم غير موجود" });
  }

  const result = db.prepare(`
    INSERT INTO surprises (user_id, title, body)
    VALUES (?, ?, ?)
  `).run(userId, title.trim(), body.trim());

  res.json({ ok: true, id: result.lastInsertRowid });
});

app.get("/api/my-page", requireRegularUser, (req, res) => {
  const userId = req.session.user.id;

  const messages = db.prepare(`
    SELECT id, message FROM messages
    WHERE user_id = ? ORDER BY id DESC
  `).all(userId);

  const surprises = db.prepare(`
    SELECT id, title, body FROM surprises
    WHERE user_id = ? ORDER BY id DESC
  `).all(userId);

  const media = db.prepare(`
    SELECT id, type, title FROM media
    WHERE user_id = ? ORDER BY rowid DESC
  `).all(userId);

  res.json({
    user: req.session.user,
    messages,
    surprises,
    media
  });
});

app.get("/api/media/:id", requireRegularUser, (req, res) => {
  const media = db.prepare(`
    SELECT * FROM media
    WHERE id = ? AND user_id = ?
  `).get(req.params.id, req.session.user.id);

  if (!media) {
    return res.status(404).json({
      error: "الملف غير موجود"
    });
  }

  const filepath = path.join(UPLOAD_DIR, media.filename);

  if (!fs.existsSync(filepath)) {
    return res.status(404).json({
      error: "ملف الوسائط غير موجود على السيرفر"
    });
  }

  res.type(media.mime);
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("Cache-Control", "private, no-store");
  res.sendFile(filepath);
});

// الملفات الثابتة العامة فقط، بعد تعريف المسارات المحمية.
app.use(express.static(PUBLIC_DIR, {
  index: false,
  dotfiles: "deny"
}));

app.use((err, req, res, next) => {
  console.error(err);

  if (res.headersSent) return next(err);

  res.status(500).json({
    error: "حصل خطأ في السيرفر"
  });
});

app.listen(PORT, () => {
  console.log(`Qalbi Ana running on http://localhost:${PORT}`);
});