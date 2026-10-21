const express = require("express");
const session = require("express-session");
const PgSession = require("connect-pg-simple")(session);
const { Pool } = require("pg");
const bcrypt = require("bcryptjs");
const multer = require("multer");
const helmet = require("helmet");
const path = require("path");
const crypto = require("crypto");
const { createClient } = require("@supabase/supabase-js");

const app = express();
const PORT = process.env.PORT || 3000;
const PUBLIC_DIR = path.join(__dirname, "public");
const BUCKET = "qalbi-media";

const requiredEnv = [
  "DATABASE_URL",
  "SUPABASE_URL",
  "SUPABASE_SECRET_KEY",
  "SESSION_SECRET"
];

if (process.env.NODE_ENV === "production") {
  for (const key of requiredEnv) {
    if (!process.env[key]) {
      throw new Error(`Missing environment variable: ${key}`);
    }
  }
}

if (!process.env.DATABASE_URL) {
  throw new Error("Set DATABASE_URL to your Neon connection string.");
}

if (!process.env.SUPABASE_URL || !process.env.SUPABASE_SECRET_KEY) {
  throw new Error("Set SUPABASE_URL and SUPABASE_SECRET_KEY.");
}

if (!process.env.SESSION_SECRET) {
  throw new Error("Set a strong SESSION_SECRET.");
}

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false },
  max: 5,
  connectionTimeoutMillis: 15000,
  idleTimeoutMillis: 30000
});

const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SECRET_KEY,
  {
    auth: {
      persistSession: false,
      autoRefreshToken: false
    }
  }
);

app.disable("x-powered-by");

if (process.env.TRUST_PROXY === "1") {
  app.set("trust proxy", 1);
}

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

app.use(session({
  store: new PgSession({
    pool,
    tableName: "user_sessions",
    createTableIfMissing: true
  }),
  name: "qalbi.sid",
  secret: process.env.SESSION_SECRET,
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
  if (!req.session.user || req.session.user.role !== "admin") {
    return res.status(403).json({ error: "الصلاحية دي للأدمن فقط" });
  }
  next();
}

function requireRegularUser(req, res, next) {
  if (!req.session.user) {
    return res.status(401).json({ error: "سجّل الدخول الأول" });
  }

  if (req.session.user.role !== "user") {
    return res.status(403).json({ error: "الصفحة دي للمستخدمين فقط" });
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
      return res.status(500).json({ error: "تعذر بدء جلسة الدخول" });
    }

    req.session.user = cleanUser(user);

    req.session.save(saveError => {
      if (saveError) {
        return res.status(500).json({ error: "تعذر حفظ جلسة الدخول" });
      }

      res.json({ ok: true, user: req.session.user });
    });
  });
}

async function initDatabase() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      username TEXT UNIQUE NOT NULL,
      display_name TEXT NOT NULL,
      password_hash TEXT NOT NULL,
      role TEXT NOT NULL DEFAULT 'user',
      public_token TEXT UNIQUE
    );

    CREATE TABLE IF NOT EXISTS media (
      id TEXT PRIMARY KEY,
      user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      type TEXT NOT NULL,
      title TEXT NOT NULL,
      storage_path TEXT NOT NULL,
      mime TEXT NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS messages (
      id SERIAL PRIMARY KEY,
      user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      message TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS surprises (
      id SERIAL PRIMARY KEY,
      user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      title TEXT NOT NULL,
      body TEXT NOT NULL
    );

    CREATE INDEX IF NOT EXISTS idx_media_user_id ON media(user_id);
    CREATE INDEX IF NOT EXISTS idx_messages_user_id ON messages(user_id);
    CREATE INDEX IF NOT EXISTS idx_surprises_user_id ON surprises(user_id);
  `);

  // إنشاء أدمن افتراضي فقط لو مفيش حساب admin.
  // غيّر كلمة المرور فور أول دخول.
  const result = await pool.query(
    "SELECT id FROM users WHERE username = $1",
    ["admin"]
  );

  if (result.rowCount === 0) {
    const password = process.env.INITIAL_ADMIN_PASSWORD;

    if (!password || password.length < 12) {
      console.warn(
        "No admin created. Set INITIAL_ADMIN_PASSWORD to a strong password of at least 12 characters."
      );
      return;
    }

    await pool.query(
      `INSERT INTO users
        (username, display_name, password_hash, role, public_token)
       VALUES ($1, $2, $3, 'admin', $4)`,
      [
        "admin",
        "الأدمن",
        await bcrypt.hash(password, 12),
        crypto.randomBytes(32).toString("hex")
      ]
    );

    console.log("Initial admin account created.");
  }
}

const upload = multer({
  storage: multer.memoryStorage(),
  limits: {
    fileSize: 50 * 1024 * 1024,
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

app.get("/", (req, res) => {
  res.sendFile(path.join(PUBLIC_DIR, "index.html"));
});

app.get("/admin-login", (req, res) => {
  if (req.session.user?.role === "admin") {
    return res.redirect("/admin.html");
  }

  res.sendFile(path.join(PUBLIC_DIR, "index.html"));
});

app.get("/u/:token", async (req, res, next) => {
  try {
    const result = await pool.query(
      "SELECT id, role FROM users WHERE public_token = $1",
      [req.params.token]
    );

    const user = result.rows[0];

    if (!user || user.role !== "user") {
      return res.status(404).send("الرابط غير صحيح أو لم يعد متاحًا.");
    }

    if (
      req.session.user?.role === "user" &&
      req.session.user.id === user.id
    ) {
      return res.redirect("/my-page.html");
    }

    res.sendFile(path.join(PUBLIC_DIR, "user-login.html"));
  } catch (err) {
    next(err);
  }
});

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

app.get("/user-login.html", (req, res) => {
  res.status(404).send("الصفحة غير متاحة بهذا العنوان.");
});

app.post("/api/login", async (req, res, next) => {
  try {
    const { username, password } = req.body || {};

    if (
      typeof username !== "string" ||
      typeof password !== "string" ||
      username.length > 100 ||
      password.length > 200
    ) {
      return res.status(400).json({ error: "بيانات الدخول غير صحيحة" });
    }

    const result = await pool.query(
      "SELECT * FROM users WHERE username = $1",
      [username.trim()]
    );

    const user = result.rows[0];

    if (
      !user ||
      user.role !== "admin" ||
      !(await bcrypt.compare(password, user.password_hash))
    ) {
      return res.status(401).json({ error: "بيانات الأدمن غير صحيحة" });
    }

    startSession(req, res, user);
  } catch (err) {
    next(err);
  }
});

app.post("/api/user-login/:token", async (req, res, next) => {
  try {
    const password = req.body?.password;

    if (
      typeof password !== "string" ||
      password.length === 0 ||
      password.length > 200
    ) {
      return res.status(400).json({ error: "اكتب كلمة المرور" });
    }

    const result = await pool.query(
      `SELECT * FROM users
       WHERE public_token = $1 AND role = 'user'`,
      [req.params.token]
    );

    const user = result.rows[0];

    if (!user || !(await bcrypt.compare(password, user.password_hash))) {
      return res.status(401).json({ error: "كلمة المرور غير صحيحة" });
    }

    startSession(req, res, user);
  } catch (err) {
    next(err);
  }
});

app.get("/api/me", requireLogin, (req, res) => {
  res.json({ user: req.session.user });
});

app.post("/api/logout", requireLogin, (req, res) => {
  req.session.destroy(err => {
    if (err) {
      return res.status(500).json({ error: "تعذر تسجيل الخروج" });
    }

    res.clearCookie("qalbi.sid", {
      httpOnly: true,
      sameSite: "lax",
      secure: process.env.NODE_ENV === "production"
    });

    res.json({ ok: true });
  });
});

app.get("/api/admin/users", requireAdmin, async (req, res, next) => {
  try {
    const result = await pool.query(`
      SELECT id, username, display_name, role, public_token
      FROM users ORDER BY id DESC
    `);

    res.json({
      users: result.rows.map(user => ({
        ...cleanUser(user),
        publicToken: user.public_token
      }))
    });
  } catch (err) {
    next(err);
  }
});

app.post("/api/admin/users", requireAdmin, async (req, res, next) => {
  try {
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
      return res.status(400).json({ error: "اكتب الاسم الظاهر" });
    }

    if (typeof password !== "string" || password.length < 8) {
      return res.status(400).json({
        error: "كلمة المرور لازم تكون 8 أحرف على الأقل"
      });
    }

    const result = await pool.query(
      `INSERT INTO users
        (username, display_name, password_hash, role, public_token)
       VALUES ($1, $2, $3, $4, $5)
       RETURNING id, role`,
      [
        username.trim(),
        displayName.trim(),
        await bcrypt.hash(password, 12),
        role,
        crypto.randomBytes(32).toString("hex")
      ]
    );

    res.json({
      ok: true,
      id: result.rows[0].id,
      role: result.rows[0].role
    });
  } catch (err) {
    if (err.code === "23505") {
      return res.status(409).json({
        error: "اسم الدخول مستخدم بالفعل؛ اختار اسمًا مختلفًا"
      });
    }
    next(err);
  }
});

app.delete("/api/admin/users/:id", requireAdmin, async (req, res, next) => {
  try {
    const id = Number(req.params.id);

    if (!Number.isSafeInteger(id) || id <= 0) {
      return res.status(400).json({ error: "رقم المستخدم غير صحيح" });
    }

    if (id === req.session.user.id) {
      return res.status(400).json({
        error: "لا يمكنك حذف حسابك الذي تستخدمه حاليًا"
      });
    }

    const mediaResult = await pool.query(
      "SELECT storage_path FROM media WHERE user_id = $1",
      [id]
    );

    const deleted = await pool.query(
      "DELETE FROM users WHERE id = $1 RETURNING id",
      [id]
    );

    if (deleted.rowCount === 0) {
      return res.status(404).json({ error: "الحساب غير موجود" });
    }

    const paths = mediaResult.rows.map(row => row.storage_path);

    if (paths.length) {
      const { error } = await supabase.storage.from(BUCKET).remove(paths);
      if (error) console.error("Storage cleanup failed:", error.message);
    }

    res.json({ ok: true });
  } catch (err) {
    next(err);
  }
});

app.post(
  "/api/admin/media/:type/:userId",
  requireAdmin,
  (req, res, next) => {
    upload.single("file")(req, res, err => {
      if (err) return res.status(400).json({ error: err.message });
      next();
    });
  },
  async (req, res, next) => {
    let storagePath;

    try {
      const userId = Number(req.params.userId);
      const type = req.params.type;

      if (
        !Number.isSafeInteger(userId) ||
        userId <= 0 ||
        !["audio", "image", "video"].includes(type)
      ) {
        return res.status(400).json({ error: "بيانات الملف غير صحيحة" });
      }

      if (!req.file) {
        return res.status(400).json({ error: "اختار ملفًا أولًا" });
      }

      const userResult = await pool.query(
        "SELECT id FROM users WHERE id = $1 AND role = 'user'",
        [userId]
      );

      if (!userResult.rowCount) {
        return res.status(400).json({
          error: "اختار مستخدمًا صحيحًا"
        });
      }

      const ext = path.extname(req.file.originalname).toLowerCase();
      const id = crypto.randomUUID();
      storagePath = `${userId}/${id}${ext}`;

      const { error: storageError } = await supabase.storage
        .from(BUCKET)
        .upload(storagePath, req.file.buffer, {
          contentType: req.file.mimetype,
          upsert: false
        });

      if (storageError) {
        console.error("Supabase upload failed:", storageError.message);
        return res.status(502).json({
          error: "تعذر رفع الملف إلى مساحة التخزين"
        });
      }

      const title = String(
        req.body.title || req.file.originalname
      ).slice(0, 200);

      try {
        await pool.query(
          `INSERT INTO media
            (id, user_id, type, title, storage_path, mime)
           VALUES ($1, $2, $3, $4, $5, $6)`,
          [id, userId, type, title, storagePath, req.file.mimetype]
        );
      } catch (dbError) {
        await supabase.storage.from(BUCKET).remove([storagePath]);
        throw dbError;
      }

      res.json({ ok: true, id });
    } catch (err) {
      next(err);
    }
  }
);

app.post("/api/admin/messages/:userId", requireAdmin, async (req, res, next) => {
  try {
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

    const user = await pool.query(
      "SELECT id FROM users WHERE id = $1 AND role = 'user'",
      [userId]
    );

    if (!user.rowCount) {
      return res.status(404).json({ error: "المستخدم غير موجود" });
    }

    const result = await pool.query(
      "INSERT INTO messages (user_id, message) VALUES ($1, $2) RETURNING id",
      [userId, message.trim()]
    );

    res.json({ ok: true, id: result.rows[0].id });
  } catch (err) {
    next(err);
  }
});

app.post("/api/admin/surprises/:userId", requireAdmin, async (req, res, next) => {
  try {
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

    const user = await pool.query(
      "SELECT id FROM users WHERE id = $1 AND role = 'user'",
      [userId]
    );

    if (!user.rowCount) {
      return res.status(404).json({ error: "المستخدم غير موجود" });
    }

    const result = await pool.query(
      `INSERT INTO surprises (user_id, title, body)
       VALUES ($1, $2, $3) RETURNING id`,
      [userId, title.trim(), body.trim()]
    );

    res.json({ ok: true, id: result.rows[0].id });
  } catch (err) {
    next(err);
  }
});

app.get("/api/my-page", requireRegularUser, async (req, res, next) => {
  try {
    const userId = req.session.user.id;

    const [messages, surprises, media] = await Promise.all([
      pool.query(
        "SELECT id, message FROM messages WHERE user_id = $1 ORDER BY id DESC",
        [userId]
      ),
      pool.query(
        "SELECT id, title, body FROM surprises WHERE user_id = $1 ORDER BY id DESC",
        [userId]
      ),
      pool.query(
        "SELECT id, type, title FROM media WHERE user_id = $1 ORDER BY created_at DESC",
        [userId]
      )
    ]);

    res.json({
      user: req.session.user,
      messages: messages.rows,
      surprises: surprises.rows,
      media: media.rows
    });
  } catch (err) {
    next(err);
  }
});

app.get("/api/media/:id", requireRegularUser, async (req, res, next) => {
  try {
    const result = await pool.query(
      `SELECT storage_path, mime FROM media
       WHERE id = $1 AND user_id = $2`,
      [req.params.id, req.session.user.id]
    );

    const media = result.rows[0];

    if (!media) {
      return res.status(404).json({ error: "الملف غير موجود" });
    }

    const { data, error } = await supabase.storage
      .from(BUCKET)
      .download(media.storage_path);

    if (error || !data) {
      console.error("Supabase download failed:", error?.message);
      return res.status(404).json({ error: "ملف الوسائط غير موجود" });
    }

    const buffer = Buffer.from(await data.arrayBuffer());

    res.type(media.mime);
    res.setHeader("X-Content-Type-Options", "nosniff");
    res.setHeader("Cache-Control", "private, no-store");
    res.setHeader("Content-Length", buffer.length);
    res.send(buffer);
  } catch (err) {
    next(err);
  }
});

app.use(express.static(PUBLIC_DIR, {
  index: false,
  dotfiles: "deny"
}));

app.use((err, req, res, next) => {
  console.error(err);

  if (res.headersSent) return next(err);

  res.status(500).json({ error: "حصل خطأ في السيرفر" });
});

async function start() {
  await pool.query("SELECT 1");

  const { data: buckets, error } = await supabase.storage.listBuckets();

  if (error) {
    throw new Error(`Supabase connection failed: ${error.message}`);
  }

  if (!buckets.some(bucket => bucket.name === BUCKET)) {
    throw new Error(`Supabase bucket "${BUCKET}" was not found.`);
  }

  await initDatabase();

  app.listen(PORT, () => {
    console.log(`Qalbi Ana running on port ${PORT}`);
  });
}

start().catch(err => {
  console.error("Startup failed:", err);
  process.exit(1);
});