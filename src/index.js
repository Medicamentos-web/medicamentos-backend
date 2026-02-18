const express = require("express");
const bcrypt = require("bcryptjs");
const crypto = require("crypto");
const nodemailer = require("nodemailer");
const webpush = require("web-push");
const { execFile } = require("child_process");
const os = require("os");
const path = require("path");
const fs = require("fs");
const multer = require("multer");
const PDFDocument = require("pdfkit");
const jwt = require("jsonwebtoken");
const cookieParser = require("cookie-parser");
const cors = require("cors");
const pg = require("pg");
const { Pool } = pg;
// Fix: devolver DATE (oid 1082) como string "YYYY-MM-DD" en vez de objeto Date
// Esto previene el bug de timezone donde la fecha pierde un día
pg.types.setTypeParser(1082, (val) => val);
const Stripe = require("stripe");

const app = express();

// ── Stripe config ──
const STRIPE_SECRET_KEY = process.env.STRIPE_SECRET_KEY || "";
const STRIPE_WEBHOOK_SECRET = process.env.STRIPE_WEBHOOK_SECRET || "";
const STRIPE_PRICE_ID = process.env.STRIPE_PRICE_ID || "";
const STRIPE_PRICE_ID_YEARLY = process.env.STRIPE_PRICE_ID_YEARLY || "";
const FRONTEND_URL = process.env.FRONTEND_URL || "http://localhost:3000";
const stripe = STRIPE_SECRET_KEY ? new Stripe(STRIPE_SECRET_KEY) : null;

// Stripe webhook necesita raw body - ANTES de express.json()
app.post("/api/billing/webhook", express.raw({ type: "application/json" }), async (req, res) => {
  if (!stripe || !STRIPE_WEBHOOK_SECRET) {
    return res.status(400).json({ error: "Stripe no configurado" });
  }
  let event;
  try {
    const sig = req.headers["stripe-signature"];
    event = stripe.webhooks.constructEvent(req.body, sig, STRIPE_WEBHOOK_SECRET);
  } catch (err) {
    console.error("[STRIPE WEBHOOK] Firma inválida:", err.message);
    return res.status(400).json({ error: "Firma inválida" });
  }

  console.log(`[STRIPE WEBHOOK] Evento: ${event.type}`);

  try {
    switch (event.type) {
      case "checkout.session.completed": {
        const session = event.data.object;
        const familyId = Number(session.metadata?.family_id);
        if (!familyId) break;
        await pool.query(
          `UPDATE families SET
            stripe_customer_id = $1,
            stripe_subscription_id = $2,
            subscription_status = 'active',
            subscription_start = NOW(),
            subscription_end = NULL
           WHERE id = $3`,
          [session.customer, session.subscription, familyId]
        );
        console.log(`[STRIPE] Familia ${familyId} activada`);
        // Email confirmación
        const fam = await pool.query(`SELECT f.name, u.email FROM families f JOIN users u ON u.family_id = f.id WHERE f.id = $1 AND u.role IN ('admin','superuser') LIMIT 1`, [familyId]);
        if (fam.rows[0]?.email && mailTransport) {
          try {
            await mailTransport.sendMail({
              from: process.env.SMTP_USER, to: fam.rows[0].email,
              subject: "Suscripción activada - MediControl",
              html: `<h2>Su suscripción ha sido activada</h2><p>Familia: ${fam.rows[0].name || familyId}</p><p>Todas las funciones están ahora disponibles.</p>`,
            });
          } catch {}
        }
        break;
      }
      case "customer.subscription.updated": {
        const sub = event.data.object;
        const cust = sub.customer;
        const status = sub.status === "active" || sub.status === "trialing" ? "active" : sub.status === "past_due" ? "past_due" : "cancelled";
        const endDate = sub.current_period_end ? new Date(sub.current_period_end * 1000) : null;
        await pool.query(
          `UPDATE families SET subscription_status = $1, subscription_end = $2 WHERE stripe_customer_id = $3`,
          [status, endDate, cust]
        );
        console.log(`[STRIPE] Suscripción actualizada para customer ${cust}: ${status}`);
        break;
      }
      case "customer.subscription.deleted": {
        const sub = event.data.object;
        await pool.query(
          `UPDATE families SET subscription_status = 'cancelled', subscription_end = NOW() WHERE stripe_customer_id = $1`,
          [sub.customer]
        );
        console.log(`[STRIPE] Suscripción cancelada para customer ${sub.customer}`);
        break;
      }
      case "invoice.payment_failed": {
        const invoice = event.data.object;
        await pool.query(
          `UPDATE families SET subscription_status = 'past_due' WHERE stripe_customer_id = $1`,
          [invoice.customer]
        );
        console.log(`[STRIPE] Pago fallido para customer ${invoice.customer}`);
        break;
      }
    }
  } catch (err) {
    console.error("[STRIPE WEBHOOK] Error procesando:", err.message);
  }

  res.json({ received: true });
});

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
const allowedOrigins = [
  /^http:\/\/localhost:\d+$/,
  /^http:\/\/192\.168\.\d+\.\d+:\d+$/,
  /^https:\/\/medicamentos-backend\.onrender\.com$/,
  /^https:\/\/medicamentos-frontend\.vercel\.app$/,
  /^https:\/\/.*\.vercel\.app$/,
];

// Orígenes adicionales desde variable de entorno (separados por coma)
if (process.env.CORS_EXTRA_ORIGINS) {
  process.env.CORS_EXTRA_ORIGINS.split(",")
    .map((o) => o.trim())
    .filter(Boolean)
    .forEach((o) => allowedOrigins.push(new RegExp("^" + o.replace(/[.*+?^${}()|[\]\\]/g, "\\$&") + "$")));
}

app.use(
  cors({
    origin: (origin, callback) => {
      // Sin origin = same-origin o herramientas (curl, etc.) → permitir
      if (!origin) return callback(null, true);
      const ok = allowedOrigins.some((regex) => regex.test(origin));
      if (!ok) console.warn("[CORS] Bloqueado:", origin);
      // Permitir siempre pero logear los no reconocidos (evita 500 por CORS)
      return callback(null, true);
    },
    credentials: true,
  })
);

const JWT_SECRET = process.env.JWT_SECRET || "dev_secret_change";
const TOKEN_NAME = "medicamentos_token";
const DEV_SHOW_RESET_TOKEN = process.env.DEV_SHOW_RESET_TOKEN === "true";

// Conexión a PostgreSQL: prioriza DATABASE_URL (Render/producción), fallback a vars individuales
const poolConfig = {};

if (process.env.DATABASE_URL) {
  poolConfig.connectionString = process.env.DATABASE_URL;
  // Render PostgreSQL y Supabase requieren SSL
  poolConfig.ssl = process.env.DB_SSL === "false" ? false : { rejectUnauthorized: false };
  console.log("[DB] Usando DATABASE_URL");
} else {
  poolConfig.host = process.env.DB_HOST || "localhost";
  poolConfig.port = Number(process.env.DB_PORT || 5432);
  poolConfig.user = process.env.DB_USER || "medicamentos";
  poolConfig.password = process.env.DB_PASSWORD || "medicamentos_secret";
  poolConfig.database = process.env.DB_NAME || "medicamentos";
  if (process.env.DB_HOST && !process.env.DB_HOST.includes("localhost")) {
    poolConfig.ssl = { rejectUnauthorized: false };
  }
  console.log("[DB] Usando variables individuales, host:", poolConfig.host);
}

// Timeouts para evitar queries colgadas
poolConfig.connectionTimeoutMillis = 10000;  // 10s para conectar
poolConfig.idleTimeoutMillis = 30000;        // 30s idle
poolConfig.max = 10;                         // máx 10 conexiones
poolConfig.application_name = "medicamentos-backend";

const pool = new Pool(poolConfig);

// Evitar crash por errores de pool no manejados
pool.on("error", (err) => {
  console.error("[DB] Error inesperado en el pool:", err.message);
});

// Verificar conexión al iniciar
pool.query("SELECT NOW()")
  .then((r) => console.log("[DB] Conexión OK, hora del servidor:", r.rows[0].now))
  .catch((err) => console.error("[DB] ERROR al conectar:", err.message));

const ADMIN_EMAIL = process.env.ADMIN_EMAIL || "";
const VAPID_PUBLIC_KEY = process.env.VAPID_PUBLIC_KEY || "";
const VAPID_PRIVATE_KEY = process.env.VAPID_PRIVATE_KEY || "";
const DEFAULT_TEMP_PASSWORD = process.env.DEFAULT_TEMP_PASSWORD || "123456";
const LOW_STOCK_THRESHOLD = Number(process.env.LOW_STOCK_THRESHOLD || 10);

// Cookie config adaptativa: secure=true si viene de proxy HTTPS (túnel)
function cookieOpts(req) {
  const isSecure = req.headers["x-forwarded-proto"] === "https" || req.secure;
  return {
    httpOnly: true,
    sameSite: isSecure ? "none" : "lax",
    secure: isSecure,
    maxAge: 7 * 24 * 60 * 60 * 1000,
  };
}

const mailTransport =
  process.env.SMTP_HOST && process.env.SMTP_USER
    ? nodemailer.createTransport({
        host: process.env.SMTP_HOST,
        port: Number(process.env.SMTP_PORT || 587),
        secure: false,
        auth: {
          user: process.env.SMTP_USER,
          pass: process.env.SMTP_PASS,
        },
      })
    : null;

const pushKeys =
  VAPID_PUBLIC_KEY && VAPID_PRIVATE_KEY
    ? { publicKey: VAPID_PUBLIC_KEY, privateKey: VAPID_PRIVATE_KEY }
    : webpush.generateVAPIDKeys();

webpush.setVapidDetails(
  "mailto:" + (ADMIN_EMAIL || "admin@example.com"),
  pushKeys.publicKey,
  pushKeys.privateKey
);

const uploadDir = path.join(os.tmpdir(), "med-imports");
if (!fs.existsSync(uploadDir)) {
  fs.mkdirSync(uploadDir, { recursive: true });
}
const upload = multer({ dest: uploadDir });
const medicalRecordsDir = path.join("/data/imports", "medical_records");
if (!fs.existsSync(medicalRecordsDir)) {
  fs.mkdirSync(medicalRecordsDir, { recursive: true });
}

async function ensureAuthTables() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS password_resets (
      id SERIAL PRIMARY KEY,
      user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      token VARCHAR(64) NOT NULL UNIQUE,
      expires_at TIMESTAMPTZ NOT NULL,
      used_at TIMESTAMPTZ,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
  `);
  await pool.query(
    "CREATE INDEX IF NOT EXISTS idx_password_resets_user_id ON password_resets(user_id)"
  );
}

ensureAuthTables().catch((error) => {
  console.error("ERROR: No se pudo crear password_resets:", error.message);
});

async function ensureUserColumns() {
  await pool.query(
    `ALTER TABLE users ADD COLUMN IF NOT EXISTS must_change_password BOOLEAN NOT NULL DEFAULT false`
  );
  await pool.query(
    `UPDATE users SET must_change_password = false WHERE must_change_password IS NULL`
  );
  // Disclaimer acceptance tracking
  await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS disclaimer_accepted_at TIMESTAMPTZ`);
  await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS disclaimer_ip VARCHAR(100)`);
  await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS disclaimer_lang VARCHAR(10)`);
}

ensureUserColumns().catch((error) => {
  console.error("ERROR: No se pudo actualizar users:", error.message);
});

async function ensureUserProfileColumns() {
  await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS first_name VARCHAR(120)`);
  await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS last_name VARCHAR(120)`);
  await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS birth_date DATE`);
  await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS street VARCHAR(255)`);
  await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS house_number VARCHAR(32)`);
  await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS postal_code VARCHAR(32)`);
  await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS city VARCHAR(120)`);
}

ensureUserProfileColumns().catch((error) => {
  console.error("ERROR: No se pudo actualizar perfil de users:", error.message);
});

async function ensureDoctorTables() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS family_doctors (
      id SERIAL PRIMARY KEY,
      family_id INTEGER NOT NULL REFERENCES families(id) ON DELETE CASCADE,
      first_name VARCHAR(120) NOT NULL,
      last_name VARCHAR(120) NOT NULL,
      email VARCHAR(255),
      street VARCHAR(255),
      house_number VARCHAR(32),
      postal_code VARCHAR(32),
      city VARCHAR(120),
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
  `);
  await pool.query(
    "CREATE INDEX IF NOT EXISTS idx_family_doctors_family_id ON family_doctors(family_id)"
  );
}

ensureDoctorTables().catch((error) => {
  console.error("ERROR: No se pudo crear family_doctors:", error.message);
});

async function ensureAlertTables() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS alerts (
      id SERIAL PRIMARY KEY,
      family_id INTEGER NOT NULL REFERENCES families(id) ON DELETE CASCADE,
      user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
      type VARCHAR(32) NOT NULL,
      level VARCHAR(16) NOT NULL DEFAULT 'info',
      message TEXT NOT NULL,
      med_name VARCHAR(255),
      med_dosage VARCHAR(120),
      dose_time VARCHAR(16),
      alert_date DATE,
      schedule_id INTEGER REFERENCES schedules(id) ON DELETE SET NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      read_at TIMESTAMPTZ
    );
  `);
  await pool.query(`ALTER TABLE alerts ADD COLUMN IF NOT EXISTS med_name VARCHAR(255)`);
  await pool.query(`ALTER TABLE alerts ADD COLUMN IF NOT EXISTS med_dosage VARCHAR(120)`);
  await pool.query(`ALTER TABLE alerts ADD COLUMN IF NOT EXISTS dose_time VARCHAR(16)`);
  await pool.query(`ALTER TABLE alerts ADD COLUMN IF NOT EXISTS alert_date DATE`);
  await pool.query(`ALTER TABLE alerts ADD COLUMN IF NOT EXISTS schedule_id INTEGER`);
  await pool.query(
    "CREATE INDEX IF NOT EXISTS idx_alerts_family_id ON alerts(family_id)"
  );
  await pool.query(
    "CREATE INDEX IF NOT EXISTS idx_alerts_user_id ON alerts(user_id)"
  );
}

ensureAlertTables().catch((error) => {
  console.error("ERROR: No se pudo crear alerts:", error.message);
});

async function ensureAuditTables() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS medicine_audits (
      id SERIAL PRIMARY KEY,
      medicine_id INTEGER REFERENCES medicines(id) ON DELETE SET NULL,
      family_id INTEGER NOT NULL REFERENCES families(id) ON DELETE CASCADE,
      user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
      action VARCHAR(16) NOT NULL,
      notes TEXT,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
  `);
  await pool.query(
    "CREATE INDEX IF NOT EXISTS idx_medicine_audits_family_id ON medicine_audits(family_id)"
  );
}

ensureAuditTables().catch((error) => {
  console.error("ERROR: No se pudo crear medicine_audits:", error.message);
});

async function ensureWeeklyReminders() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS weekly_reminders (
      id SERIAL PRIMARY KEY,
      family_id INTEGER NOT NULL REFERENCES families(id) ON DELETE CASCADE,
      week_start DATE NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      UNIQUE (family_id, week_start)
    );
  `);
}

ensureWeeklyReminders().catch((error) => {
  console.error("ERROR: No se pudo crear weekly_reminders:", error.message);
});

async function ensureScheduleColumns() {
  await pool.query(
    `ALTER TABLE schedules ADD COLUMN IF NOT EXISTS days_of_week VARCHAR(14) DEFAULT '1234567'`
  );
  await pool.query(
    `ALTER TABLE schedules ADD COLUMN IF NOT EXISTS start_date DATE`
  );
  await pool.query(
    `ALTER TABLE schedules ADD COLUMN IF NOT EXISTS end_date DATE`
  );
  await pool.query(
    `UPDATE schedules SET days_of_week = '1234567' WHERE days_of_week IS NULL`
  );
}

ensureScheduleColumns().catch((error) => {
  console.error("ERROR: No se pudo actualizar schedules:", error.message);
});

async function ensureCheckoutTables() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS daily_checkouts (
      id SERIAL PRIMARY KEY,
      user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      family_id INTEGER NOT NULL REFERENCES families(id) ON DELETE CASCADE,
      day DATE NOT NULL,
      sent_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      UNIQUE (user_id, day)
    );
  `);
}

ensureCheckoutTables().catch((error) => {
  console.error("ERROR: No se pudo crear daily_checkouts:", error.message);
});

async function ensurePushTables() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS push_subscriptions (
      id SERIAL PRIMARY KEY,
      user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      family_id INTEGER NOT NULL REFERENCES families(id) ON DELETE CASCADE,
      endpoint TEXT NOT NULL,
      p256dh TEXT NOT NULL,
      auth TEXT NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      UNIQUE (user_id, endpoint)
    );
  `);
}

ensurePushTables().catch((error) => {
  console.error("ERROR: No se pudo crear push_subscriptions:", error.message);
});

async function ensureImportTables() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS import_batches (
      id SERIAL PRIMARY KEY,
      family_id INTEGER NOT NULL REFERENCES families(id) ON DELETE CASCADE,
      user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
      source_file TEXT,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
  `);
  await pool.query(
    `ALTER TABLE medicines ADD COLUMN IF NOT EXISTS import_batch_id INTEGER REFERENCES import_batches(id) ON DELETE SET NULL`
  );
  await pool.query(
    "CREATE INDEX IF NOT EXISTS idx_medicines_import_batch_id ON medicines(import_batch_id)"
  );
}

ensureImportTables().catch((error) => {
  console.error("ERROR: No se pudo crear import_batches:", error.message);
});

async function ensureDeletionLogs() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS deletion_logs (
      id SERIAL PRIMARY KEY,
      family_id INTEGER NOT NULL REFERENCES families(id) ON DELETE CASCADE,
      user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
      deleted_count INTEGER NOT NULL DEFAULT 0,
      snapshot JSONB NOT NULL DEFAULT '[]'::jsonb,
      deleted_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
  `);
  await pool.query(
    "CREATE INDEX IF NOT EXISTS idx_deletion_logs_family_id ON deletion_logs(family_id)"
  );
  await pool.query(
    "CREATE INDEX IF NOT EXISTS idx_deletion_logs_user_id ON deletion_logs(user_id)"
  );
  await pool.query(
    "CREATE INDEX IF NOT EXISTS idx_deletion_logs_deleted_at ON deletion_logs(deleted_at)"
  );
}

ensureDeletionLogs().catch((error) => {
  console.error("ERROR: No se pudo crear deletion_logs:", error.message);
});

async function ensureMedicalRecords() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS medical_records (
      id SERIAL PRIMARY KEY,
      family_id INTEGER NOT NULL REFERENCES families(id) ON DELETE CASCADE,
      user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      title VARCHAR(200) NOT NULL,
      record_date DATE,
      file_path TEXT NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
  `);
  await pool.query(
    "CREATE INDEX IF NOT EXISTS idx_medical_records_family_id ON medical_records(family_id)"
  );
  await pool.query(
    "CREATE INDEX IF NOT EXISTS idx_medical_records_user_id ON medical_records(user_id)"
  );
  await pool.query(
    "CREATE INDEX IF NOT EXISTS idx_medical_records_date ON medical_records(record_date)"
  );
}

ensureMedicalRecords().catch((error) => {
  console.error("ERROR: No se pudo crear medical_records:", error.message);
});

async function ensureDoseChangeRequests() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS dose_change_requests (
      id SERIAL PRIMARY KEY,
      family_id INTEGER NOT NULL REFERENCES families(id) ON DELETE CASCADE,
      user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      schedule_id INTEGER NOT NULL REFERENCES schedules(id) ON DELETE CASCADE,
      medicine_id INTEGER NOT NULL REFERENCES medicines(id) ON DELETE CASCADE,
      current_dosage VARCHAR(120),
      requested_dosage VARCHAR(120) NOT NULL,
      effective_date DATE,
      status VARCHAR(16) NOT NULL DEFAULT 'pending',
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
  `);
  await pool.query(
    "CREATE INDEX IF NOT EXISTS idx_dose_change_family_id ON dose_change_requests(family_id)"
  );
  await pool.query(
    "CREATE INDEX IF NOT EXISTS idx_dose_change_user_id ON dose_change_requests(user_id)"
  );
  await pool.query(
    "CREATE INDEX IF NOT EXISTS idx_dose_change_status ON dose_change_requests(status)"
  );
}

ensureDoseChangeRequests().catch((error) => {
  console.error("ERROR: No se pudo crear dose_change_requests:", error.message);
});

async function ensureFeedbackTable() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS feedback (
      id SERIAL PRIMARY KEY,
      user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
      family_id INTEGER REFERENCES families(id) ON DELETE SET NULL,
      user_name VARCHAR(200),
      user_email VARCHAR(200),
      rating INTEGER NOT NULL CHECK (rating >= 1 AND rating <= 5),
      comment TEXT,
      lang VARCHAR(10) DEFAULT 'es',
      user_agent TEXT,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
  `);
  await pool.query("CREATE INDEX IF NOT EXISTS idx_feedback_created ON feedback(created_at DESC)");
}

ensureFeedbackTable().catch((error) => {
  console.error("ERROR: No se pudo crear feedback:", error.message);
});

async function ensureLeadsTable() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS leads (
      id SERIAL PRIMARY KEY,
      name VARCHAR(200),
      email VARCHAR(200) NOT NULL,
      phone VARCHAR(50),
      lang VARCHAR(10) DEFAULT 'de-CH',
      source VARCHAR(50) DEFAULT 'landing',
      message TEXT,
      ip VARCHAR(50),
      user_agent TEXT,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ
    );
  `);
  await pool.query("ALTER TABLE leads ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ");
  await pool.query("CREATE UNIQUE INDEX IF NOT EXISTS idx_leads_email ON leads(email)");
  await pool.query("CREATE INDEX IF NOT EXISTS idx_leads_created ON leads(created_at DESC)");
}

ensureLeadsTable().catch((error) => {
  console.error("ERROR: No se pudo crear leads:", error.message);
});

async function ensureMedicineUserScope() {
  await pool.query(
    `ALTER TABLE medicines ADD COLUMN IF NOT EXISTS user_id INTEGER REFERENCES users(id) ON DELETE CASCADE`
  );
  await pool.query(
    `UPDATE medicines
     SET user_id = sub.user_id
     FROM (
       SELECT s.medicine_id, MIN(s.user_id) AS user_id
       FROM schedules s
       GROUP BY s.medicine_id
     ) sub
     WHERE medicines.id = sub.medicine_id AND medicines.user_id IS NULL`
  );
  await pool.query(
    "CREATE INDEX IF NOT EXISTS idx_medicines_user_id ON medicines(user_id)"
  );
}

ensureMedicineUserScope().catch((error) => {
  console.error("ERROR: No se pudo actualizar medicines.user_id:", error.message);
});

// Fecha límite de tratamiento (end_date) en medicamentos
async function ensureMedicineEndDate() {
  await pool.query(
    `ALTER TABLE medicines ADD COLUMN IF NOT EXISTS end_date DATE`
  );
  await pool.query(
    `ALTER TABLE medicines ADD COLUMN IF NOT EXISTS end_date_notified BOOLEAN NOT NULL DEFAULT FALSE`
  );
}
ensureMedicineEndDate().catch((error) => {
  console.error("ERROR: No se pudo añadir end_date a medicines:", error.message);
});

// Columna para pausar medicamentos sin stock
async function ensureStockDepleted() {
  await pool.query(`ALTER TABLE medicines ADD COLUMN IF NOT EXISTS stock_depleted BOOLEAN NOT NULL DEFAULT FALSE`);
  // Marcar los que ya tienen stock=0
  await pool.query(`UPDATE medicines SET stock_depleted = TRUE WHERE current_stock = 0 AND stock_depleted = FALSE`);
}
ensureStockDepleted().catch((e) => console.error("ERROR stock_depleted:", e.message));

async function ensureDoctorTables() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS doctors (
      id SERIAL PRIMARY KEY,
      family_id INTEGER NOT NULL REFERENCES families(id) ON DELETE CASCADE,
      user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      first_name VARCHAR(120) NOT NULL,
      last_name VARCHAR(120) NOT NULL,
      email VARCHAR(255),
      phone VARCHAR(50),
      street VARCHAR(255),
      house_number VARCHAR(50),
      postal_code VARCHAR(32),
      city VARCHAR(120),
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      UNIQUE (family_id, user_id)
    );
  `);
}

ensureDoctorTables().catch((error) => {
  console.error("ERROR: No se pudo crear doctors:", error.message);
});

// ── Billing / Stripe columns en families ──
async function ensureBillingColumns() {
  const cols = [
    `ALTER TABLE families ADD COLUMN IF NOT EXISTS stripe_customer_id VARCHAR(255)`,
    `ALTER TABLE families ADD COLUMN IF NOT EXISTS stripe_subscription_id VARCHAR(255)`,
    `ALTER TABLE families ADD COLUMN IF NOT EXISTS subscription_status VARCHAR(50) NOT NULL DEFAULT 'trial'`,
    `ALTER TABLE families ADD COLUMN IF NOT EXISTS subscription_start TIMESTAMPTZ`,
    `ALTER TABLE families ADD COLUMN IF NOT EXISTS subscription_end TIMESTAMPTZ`,
    `ALTER TABLE families ADD COLUMN IF NOT EXISTS trial_ends_at TIMESTAMPTZ DEFAULT (NOW() + INTERVAL '7 days')`,
    `ALTER TABLE families ADD COLUMN IF NOT EXISTS trial_email_sent BOOLEAN DEFAULT FALSE`,
    `ALTER TABLE families ADD COLUMN IF NOT EXISTS max_medicines INTEGER DEFAULT 5`,
  ];
  for (const sql of cols) {
    try { await pool.query(sql); } catch (e) {
      if (!e.message.includes("already exists")) console.error("[BILLING SCHEMA]", e.message);
    }
  }
  // Set trial for existing families without status
  await pool.query(
    `UPDATE families SET trial_ends_at = NOW() + INTERVAL '7 days' WHERE trial_ends_at IS NULL AND subscription_status = 'trial'`
  );
}
ensureBillingColumns().catch((e) => console.error("ERROR billing columns:", e.message));

async function sendAdminAlertEmail(subject, html, attachments) {
  if (!mailTransport || !ADMIN_EMAIL) {
    return false;
  }
  await mailTransport.sendMail({
    from: process.env.SMTP_USER,
    to: ADMIN_EMAIL,
    subject,
    html,
    attachments: attachments && attachments.length ? attachments : undefined,
  });
  return true;
}

async function sendUserEmail(email, subject, html) {
  if (!mailTransport || !email) {
    return false;
  }
  await mailTransport.sendMail({
    from: process.env.SMTP_USER,
    to: email,
    subject,
    html,
  });
  return true;
}

async function logMedicineAudit(familyId, userId, medicineId, action, notes) {
  await pool.query(
    `INSERT INTO medicine_audits (medicine_id, family_id, user_id, action, notes)
     VALUES ($1, $2, $3, $4, $5)`,
    [medicineId, familyId, userId || null, action, notes || null]
  );
}

async function sendPushToFamily(familyId, payload) {
  const subs = await pool.query(
    `SELECT endpoint, p256dh, auth FROM push_subscriptions WHERE family_id = $1`,
    [familyId]
  );
  await Promise.all(
    subs.rows.map((sub) =>
      webpush.sendNotification(
        {
          endpoint: sub.endpoint,
          keys: { p256dh: sub.p256dh, auth: sub.auth },
        },
        JSON.stringify(payload)
      )
    )
  );
}

async function sendPushToUser(userId, payload) {
  const subs = await pool.query(
    `SELECT endpoint, p256dh, auth FROM push_subscriptions WHERE user_id = $1`,
    [userId]
  );
  await Promise.all(
    subs.rows.map((sub) =>
      webpush.sendNotification(
        {
          endpoint: sub.endpoint,
          keys: { p256dh: sub.p256dh, auth: sub.auth },
        },
        JSON.stringify(payload)
      )
    )
  );
}

function runOcrOnPdf(filePath, lang = "deu") {
  return new Promise((resolve, reject) => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "med-ocr-"));
    const prefix = path.join(tmpDir, "page");
    execFile("pdftoppm", ["-png", filePath, prefix], (err) => {
      if (err) return reject(err);
      const files = fs
        .readdirSync(tmpDir)
        .filter((f) => f.endsWith(".png"))
        .map((f) => path.join(tmpDir, f));
      let text = "";
      const runNext = (i) => {
        if (i >= files.length) return resolve(text);
        execFile("tesseract", [files[i], "stdout", "-l", lang], (err2, stdout) => {
          if (err2) return reject(err2);
          text += stdout + "\n";
          runNext(i + 1);
        });
      };
      runNext(0);
    });
  });
}

function runOcrOnImage(filePath, { lang = "deu+eng", psm = "6", oem = "1" } = {}) {
  return new Promise((resolve, reject) => {
    execFile(
      "tesseract",
      [filePath, "stdout", "-l", lang, "--oem", String(oem), "--psm", String(psm)],
      (err, stdout) => {
        if (err) return reject(err);
        resolve(stdout || "");
      }
    );
  });
}

async function runOcrOnImageBest(filePath) {
  const attempts = [
    { psm: "6", oem: "1", lang: "deu+eng" },
    { psm: "11", oem: "1", lang: "deu+eng" },
    { psm: "4", oem: "1", lang: "deu+eng" },
    { psm: "7", oem: "3", lang: "deu+eng" },
    { psm: "8", oem: "3", lang: "deu+eng" },
    { psm: "13", oem: "3", lang: "deu+eng" },
  ];
  let best = "";
  for (const opts of attempts) {
    try {
      const text = await runOcrOnImage(filePath, opts);
      if ((text || "").length > best.length) best = text || "";
    } catch {
      // ignora intento fallido
    }
  }
  return best;
}

function normalizeText(value) {
  const raw = String(value || "")
    .replace(/Ä/g, "Ae")
    .replace(/Ö/g, "Oe")
    .replace(/Ü/g, "Ue")
    .replace(/ä/g, "ae")
    .replace(/ö/g, "oe")
    .replace(/ü/g, "ue")
    .replace(/ß/g, "ss");
  return raw
    .toLowerCase()
    .normalize("NFD")
    .replace(/[\u0300-\u036f]/g, "")
    .replace(/[^a-z0-9]+/g, " ")
    .trim();
}

function patientNameMatches(text, user) {
  const normalized = normalizeText(text);
  const first = normalizeText(user.first_name || user.name?.split(" ")[0]);
  const last = normalizeText(user.last_name || user.name?.split(" ").slice(1).join(" "));
  if (!first || !last) return false;
  if (normalized.includes(first) && normalized.includes(last)) return true;
  const firstInitial = first.slice(0, 1);
  return normalized.includes(last) && normalized.includes(firstInitial);
}

function normalizeDateOnly(value) {
  if (!value) return "";
  // Si ya es string ISO "YYYY-MM-DD", devolver directo (evita timezone shift)
  if (typeof value === "string" && /^\d{4}-\d{2}-\d{2}/.test(value)) {
    return value.slice(0, 10);
  }
  // Si es Date, usar componentes locales (no UTC) para evitar -1 día
  if (value instanceof Date) {
    if (Number.isNaN(value.getTime())) return "";
    const y = value.getFullYear();
    const m = String(value.getMonth() + 1).padStart(2, "0");
    const d = String(value.getDate()).padStart(2, "0");
    return `${y}-${m}-${d}`;
  }
  // Formato DD.MM.YYYY (europeo)
  const euMatch = String(value).match(/^(\d{1,2})\.(\d{1,2})\.(\d{4})$/);
  if (euMatch) {
    return `${euMatch[3]}-${euMatch[2].padStart(2, "0")}-${euMatch[1].padStart(2, "0")}`;
  }
  // Fallback: intentar parsear
  const asDate = new Date(value);
  if (Number.isNaN(asDate.getTime())) return "";
  const y = asDate.getFullYear();
  const m = String(asDate.getMonth() + 1).padStart(2, "0");
  const d = String(asDate.getDate()).padStart(2, "0");
  return `${y}-${m}-${d}`;
}

function safeFilename(name) {
  return String(name || "archivo.pdf")
    .replace(/[^\w.\-]+/g, "_")
    .slice(0, 120);
}

const DISPLAY_TIMEZONE = process.env.TZ || "Europe/Zurich";
const DISPLAY_LOCALE = "de-CH";

function formatDateTime(value) {
  const asDate = value instanceof Date ? value : new Date(value);
  if (Number.isNaN(asDate.getTime())) return "-";
  return asDate.toLocaleString(DISPLAY_LOCALE, {
    timeZone: DISPLAY_TIMEZONE,
    hour12: false,
  });
}

function formatDateOnlyDisplay(value) {
  const asDate = value instanceof Date ? value : new Date(value);
  if (Number.isNaN(asDate.getTime())) return "-";
  return asDate.toLocaleDateString(DISPLAY_LOCALE, { timeZone: DISPLAY_TIMEZONE });
}

function buildCriticalMedsPdf(
  medicines,
  { title = "Medicamentos críticos", patientName = "Paciente" } = {}
) {
  return new Promise((resolve, reject) => {
    try {
      const doc = new PDFDocument({ margin: 40 });
      const chunks = [];
      doc.on("data", (chunk) => chunks.push(chunk));
      doc.on("end", () => resolve(Buffer.concat(chunks)));
      doc.fontSize(16).text(title);
      doc.moveDown(0.5);
      doc.fontSize(11).text(`Fecha: ${formatDateTime(new Date())}`);
      doc.moveDown();
      doc
        .fontSize(12)
        .text(
          "Estimado/a Dr./Dra.,\n\n" +
            `Le escribo para solicitar una cita y revisar la medicacion de ${patientName}. ` +
            "Adjunto a continuacion la lista de medicamentos con stock bajo para su verificacion.\n"
        );
      doc.moveDown();
      doc.fontSize(12).text("Lista de medicamentos críticos:");
      doc.moveDown(0.3);
      if (!medicines.length) {
        doc.text("No hay medicamentos críticos.");
      } else {
        medicines.forEach((med, idx) => {
          const line = `${idx + 1}. ${med.name} ${
            med.dosage ? `(${med.dosage})` : ""
          } - Stock: ${med.current_stock}`;
          doc.text(line);
        });
      }
      doc.moveDown();
      doc
        .fontSize(12)
        .text(
          "Muchas gracias por su apoyo.\n\nAtentamente,\nEquipo MediControl"
        );
      doc.end();
    } catch (error) {
      reject(error);
    }
  });
}

const MED_NAME_HINTS = (process.env.MED_NAME_HINTS || "")
  .split(",")
  .map((v) => v.trim().toLowerCase())
  .filter(Boolean);

const MED_LINE_KEYWORDS =
  /\b(filmtabl|filmtablett|tablett|tablet|tabl|tab|kapsel|caps|capsule|retard|forte|depot|sirup|syrup|tropfen|drops|spray|cream|creme|salbe|gel|loesung|lösung|solution|inj|injekt|suspension|ampul|ampulle|pflaster|patch)\b/i;
const MED_QTY_PATTERN = /\b\d+\s*(stk|tbl|kapsel|caps|pcs|pack|ml)\b/i;
const MED_DOSAGE_PATTERN = /(\d+(?:\.\d+)?)\s*(mg|mcg|g|ml|iu|ie)\b/i;
const OCR_JUNK_PATTERN = /(?:^|\s)(?:[A-Za-zÄÖÜäöüß]\s+){4,}/;
const OCR_JUNK_NO_VOWELS = /^[^aeiouäöüAEIOUÄÖÜ]{6,}$/;
const OCR_PREFIX_PATTERN = /^(sz|ss|ses|ex)\s+/i;
const OCR_SINGLE_TOKEN_PATTERN = /\b[A-Za-zÄÖÜäöüß]\b/g;
const OCR_SHORT_TOKEN_PATTERN = /\b[A-Za-zÄÖÜäöüß]{1,2}\b/g;

function filterOcrLines(lines) {
  const cleaned = [];
  for (const raw of lines || []) {
    const line = String(raw || "").trim();
    if (line.length < 4) continue;
    if (OCR_JUNK_PATTERN.test(line)) continue;
    const singleTokens = (line.match(OCR_SINGLE_TOKEN_PATTERN) || []).length;
    const shortTokens = (line.match(OCR_SHORT_TOKEN_PATTERN) || []).length;
    if (singleTokens >= 4 || shortTokens >= 6) continue;
    if (OCR_JUNK_NO_VOWELS.test(line.replace(/[^A-Za-zÄÖÜäöüß]/g, ""))) continue;
    const normalizedLine = line.replace(OCR_PREFIX_PATTERN, "").trim();
    const lower = normalizedLine.toLowerCase();
    const hasHint = MED_NAME_HINTS.length
      ? MED_NAME_HINTS.some((hint) => lower.includes(hint))
      : false;
    if (
      hasHint ||
      MED_DOSAGE_PATTERN.test(normalizedLine) ||
      MED_QTY_PATTERN.test(normalizedLine) ||
      MED_LINE_KEYWORDS.test(normalizedLine)
    ) {
      cleaned.push(normalizedLine);
      continue;
    }
    const letters = (normalizedLine.match(/[A-Za-zÄÖÜäöüß]/g) || []).length;
    const digits = (normalizedLine.match(/[0-9]/g) || []).length;
    if (letters >= 10 && digits >= 1) {
      cleaned.push(normalizedLine);
      continue;
    }
  }
  return cleaned;
}

function cleanLineForDisplay(line) {
  return String(line || "").replace(OCR_PREFIX_PATTERN, "").trim();
}

function filterOcrLinesForDisplay(lines) {
  return filterOcrLines(lines).map(cleanLineForDisplay);
}

function cleanLineForName(line) {
  return line
    .replace(/^(sz|ss|ses|ex)\s+/i, "")
    .replace(/\s{2,}/g, " ")
    .trim();
}

function extractDosage(lines, preferredIndex = -1) {
  const dosagePattern = /(\d+(?:\.\d+)?)\s*(mg|mcg|g|ml|iu|ie)\b/i;
  const dosagePatternReversed = /\b(mg|mcg|g|ml|iu|ie)\s*(\d+(?:\.\d+)?)/i;
  const dosagePatternCompact = /(\d+(?:\.\d+)?)(mg|mcg|g|ml|iu|ie)\b/i;
  const candidates = [];
  if (preferredIndex >= 0) {
    candidates.push(lines[preferredIndex], lines[preferredIndex + 1], lines[preferredIndex - 1]);
  }
  candidates.push(...lines);
  for (const line of candidates) {
    if (!line) continue;
    const match = line.match(dosagePattern);
    if (match) return `${match[1]} ${match[2]}`;
    const matchCompact = line.match(dosagePatternCompact);
    if (matchCompact) return `${matchCompact[1]} ${matchCompact[2]}`;
    const matchReversed = line.match(dosagePatternReversed);
    if (matchReversed) return `${matchReversed[2]} ${matchReversed[1]}`;
  }
  return "N/A";
}

function extractMedicineName(lines) {
  const datePattern = /\b\d{1,2}\.\d{1,2}\.\d{2,4}\b/;
  const phonePattern = /(tel|telefon|phone|fax|mob|chf|agb|ag|gmbh|spital|klinik)/i;
  const dosagePattern = /\b\d+(?:\.\d+)?\s*(mg|mcg|g|ml|iu|ie)\b/i;
  let best = "Medicamento escaneado";
  let bestScore = -Infinity;
  let hintIndex = -1;
  for (const rawLine of lines) {
    const line = rawLine.trim();
    if (!line || line.length < 4) continue;
    let score = 0;
    if (dosagePattern.test(line)) score += 4;
    const letters = (line.match(/[A-Za-z]/g) || []).length;
    const digits = (line.match(/[0-9]/g) || []).length;
    score += Math.min(6, letters / 2);
    score -= digits > 8 ? 3 : 0;
    if (datePattern.test(line)) score -= 4;
    if (phonePattern.test(line)) score -= 3;
    if (line === line.toUpperCase()) score += 2;
    if (MED_NAME_HINTS.length) {
      const lower = line.toLowerCase();
      if (MED_NAME_HINTS.some((hint) => lower.includes(hint))) {
        score += 8;
        hintIndex = lines.indexOf(rawLine);
      }
    }
    if (score > bestScore) {
      bestScore = score;
      best = line;
    }
  }
  if (hintIndex >= 0) {
    const hinted = cleanLineForName(lines[hintIndex] || best);
    return hinted || best;
  }
  return cleanLineForName(best) || best;
}

async function upsertMedicineForUser({
  familyId,
  userId,
  name,
  dosage,
  qty,
  expiryDate,
  batchId,
}) {
  const normName = normalizeText(name);
  const normDosage = normalizeText(dosage || "");
  const existing = await pool.query(
    `SELECT id, current_stock, name, dosage FROM medicines
     WHERE family_id = $1 AND user_id = $2`,
    [familyId, userId]
  );
  const dup = existing.rows.find(
    (row) =>
      normalizeText(row.name) === normName &&
      normalizeText(row.dosage || "") === normDosage
  );
  if (dup) {
    // Merge: actualizar stock (no cuenta como nuevo medicamento)
    const newStock = Number(dup.current_stock || 0) + Number(qty || 0);
    // Reactivar medicamento si tenía stock agotado
    await pool.query(
      `UPDATE medicines SET current_stock = $1, stock_depleted = FALSE WHERE id = $2`,
      [newStock, dup.id]
    );
    // Borrar alertas de stock existentes para este medicamento (ya no aplican)
    if (newStock > 0) {
      await pool.query(
        `DELETE FROM alerts WHERE family_id = $1 AND type IN ('low_stock', 'stock_low') AND med_name = $2`,
        [familyId, dup.name]
      );
      console.log(`[STOCK] Reactivado: ${dup.name} → stock ${newStock}`);
    }
    return { id: dup.id, action: "merged" };
  }
  // Verificar límite de medicamentos para trial/beta
  try {
    const famResult = await pool.query(
      `SELECT subscription_status, max_medicines, trial_ends_at FROM families WHERE id = $1`,
      [familyId]
    );
    const fam = famResult.rows[0];
    if (fam && fam.subscription_status === "trial") {
      const maxMeds = fam.max_medicines || 5;
      const currentCount = existing.rows.length;
      if (currentCount >= maxMeds) {
        throw new Error(`Límite de ${maxMeds} medicamentos alcanzado en la versión de prueba. Activa tu suscripción para añadir más.`);
      }
    }
  } catch (limitErr) {
    if (limitErr.message.includes("Límite de")) throw limitErr;
    console.error("[MED LIMIT CHECK]", limitErr.message);
  }

  const created = await pool.query(
    `INSERT INTO medicines (family_id, user_id, name, dosage, current_stock, expiration_date, import_batch_id, stock_depleted)
     VALUES ($1, $2, $3, $4, $5, $6, $7, FALSE)
     RETURNING id`,
    [familyId, userId, name, dosage, qty || 0, expiryDate || null, batchId || null]
  );
  return { id: created.rows[0].id, action: "created" };
}

async function ensureDefaultScheduleForMedicine({ familyId, userId, medicineId }) {
  const existing = await pool.query(
    `SELECT id FROM schedules WHERE medicine_id = $1 AND user_id = $2 LIMIT 1`,
    [medicineId, userId]
  );
  if (existing.rows.length) return;
  await pool.query(
    `INSERT INTO schedules (medicine_id, user_id, dose_time, frequency, days_of_week)
     VALUES ($1, $2, $3, $4, $5)`,
    [medicineId, userId, "08:00", "1", "1234567"]
  );
}

function getFamilyId(req) {
  const raw =
    req.query.family_id ||
    req.query.familyId ||
    req.headers["x-family-id"] ||
    req.body?.family_id ||
    req.body?.familyId ||
    req.user?.family_id;
  const parsed = Number(raw);
  return Number.isFinite(parsed) && parsed > 0 ? parsed : null;
}

function signToken(user) {
  return jwt.sign(
    {
      sub: user.id,
      family_id: user.family_id,
      role: user.role,
      name: user.name,
      email: user.email,
      must_change_password: !!user.must_change_password,
    },
    JWT_SECRET,
    { expiresIn: "7d" }
  );
}

function authMiddleware(req, _res, next) {
  const bearer = req.headers.authorization?.startsWith("Bearer ")
    ? req.headers.authorization.slice(7)
    : null;
  const token = req.cookies[TOKEN_NAME] || bearer;
  if (!token) {
    req.user = null;
    return next();
  }
  try {
    req.user = jwt.verify(token, JWT_SECRET);
  } catch {
    req.user = null;
  }
  return next();
}

app.use(authMiddleware);

function requireAuth(req, res, next) {
  if (!req.user) {
    return res.status(401).json({ error: "no autenticado" });
  }
  return next();
}

// Middleware: verifica que la familia tenga suscripción activa o trial vigente
function requireActiveSubscription(req, res, next) {
  if (!req.user) return res.status(401).json({ error: "no autenticado" });
  const familyId = req.user.family_id;
  if (!familyId) return next(); // Si no hay family_id, dejamos pasar (se controlará en el endpoint)
  pool.query(`SELECT subscription_status, trial_ends_at FROM families WHERE id = $1`, [familyId])
    .then((result) => {
      const fam = result.rows[0];
      if (!fam) return next();
      const status = fam.subscription_status;
      const now = new Date();
      const trialOk = status === "trial" && fam.trial_ends_at && new Date(fam.trial_ends_at) > now;
      const subOk = status === "active";
      if (subOk || trialOk) return next();
      return res.status(402).json({
        error: "Suscripción inactiva",
        code: "SUBSCRIPTION_REQUIRED",
        status: status,
        trial_expired: status === "trial",
        message: status === "trial"
          ? "Tu período de prueba ha expirado. Activa tu suscripción para continuar."
          : "Tu suscripción no está activa. Renueva tu plan para continuar.",
      });
    })
    .catch((err) => {
      console.error("[SUB CHECK]", err.message);
      return next(); // En caso de error de DB, dejamos pasar
    });
}

function requireAuthHtml(req, res, next) {
  if (!req.user) {
    return res.redirect("/admin/login");
  }
  return next();
}

function requireRoleHtml(roles) {
  return (req, res, next) => {
    if (!req.user) {
      return res.redirect("/admin/login");
    }
    if (!roles.includes(req.user.role)) {
      const content = `
        <div class="card">
          <h1>Acceso denegado</h1>
          <p class="muted">No tienes permisos para ver esta sección.</p>
          <div style="margin-top:12px;">
            <a class="btn outline" href="/dashboard">Volver</a>
          </div>
        </div>
      `;
      return res.status(403).send(renderShell(req, "Acceso denegado", "", content));
    }
    return next();
  };
}

function escapeHtml(value) {
  if (value === null || value === undefined) return "";
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

function renderShell(req, title, active, content) {
  // Si no hay sesión, renderizar layout mínimo (solo login)
  if (!req.user) {
    return `
    <!doctype html>
    <html lang="es">
      <head>
        <meta charset="utf-8" />
        <meta name="viewport" content="width=device-width, initial-scale=1" />
        <title>${escapeHtml(title)}</title>
        <style>
          :root { color-scheme:light; --bg:#F6F8FC; --card:#FFFFFF; --ink:#0F172A; --muted:#475569; --border:#E2E8F0; --accent:#2563EB; }
          * { box-sizing:border-box; }
          body { margin:0; font-family:"Inter",Arial,sans-serif; background:var(--bg); color:var(--ink); display:flex; align-items:center; justify-content:center; min-height:100vh; }
          .card { background:var(--card); border:1px solid var(--border); border-radius:16px; padding:24px; box-shadow:0 8px 20px -18px rgba(15,23,42,.35); width:100%; max-width:440px; margin:24px; }
          .card h1 { margin:0 0 4px; }
          .muted { color:var(--muted); }
          .form-control { width:100%; border:1px solid var(--border); border-radius:12px; padding:10px 12px; margin-top:6px; font-size:14px; }
          label { display:block; margin-top:14px; font-size:13px; font-weight:600; color:var(--muted); }
          .btn { display:inline-flex; align-items:center; justify-content:center; padding:12px 16px; border-radius:12px; font-weight:600; border:1px solid transparent; cursor:pointer; font-size:14px; }
          .btn.primary { background:var(--accent); color:#fff; }
        </style>
      </head>
      <body>
        ${content}
      </body>
    </html>`;
  }

  const userName = escapeHtml(req.user?.name || "Admin");
  const userEmail = escapeHtml(req.user?.email || "");
  const items = [
    { key: "panel", label: "🏠 Panel", href: "/dashboard" },
    { key: "patients", label: "👤 Pacientes", href: "/admin/user-new" },
    { key: "meds", label: "💊 Medicamentos", href: "/admin/meds-list" },
    { key: "alerts", label: "🔔 Alertas", href: "/admin/alerts" },
    { key: "dose", label: "🩺 Cambios de dosis", href: "/admin/dose-requests" },
    { key: "history", label: "📁 Historial médico", href: "/admin/medical-records" },
    { key: "imports", label: "⬆ Importaciones", href: "/admin/import" },
    { key: "billing", label: "💳 Facturación", href: "/admin/billing" },
    { key: "feedback", label: "⭐ Feedback", href: "/admin/feedback" },
    { key: "leads", label: "📩 Leads", href: "/admin/leads" },
    { key: "reports", label: "📊 Informes", href: "/admin/reports" },
    { key: "settings", label: "⚙ Ajustes", href: "/admin/settings" },
  ];
  return `
    <!doctype html>
    <html lang="es">
      <head>
        <meta charset="utf-8" />
        <meta name="viewport" content="width=device-width, initial-scale=1" />
        <title>${escapeHtml(title)}</title>
        <style>
          :root {
            color-scheme: light;
            --bg: #F6F8FC;
            --card: #FFFFFF;
            --ink: #0F172A;
            --muted: #475569;
            --border: #E2E8F0;
            --accent: #2563EB;
            --success: #16A34A;
            --warning: #F59E0B;
            --danger: #DC2626;
          }
          * { box-sizing: border-box; }
          body { margin:0; font-family: "Inter", Arial, sans-serif; background:var(--bg); color:var(--ink); }
          a { color:inherit; text-decoration:none; }
          .app { display:flex; min-height:100vh; }
          .sidebar { width:260px; background:#fff; border-right:1px solid var(--border); padding:20px 16px; position:sticky; top:0; height:100vh; }
          .sidebar h4 { margin:18px 0 8px; font-size:12px; text-transform:uppercase; letter-spacing:.08em; color:var(--muted); }
          .nav { display:flex; flex-direction:column; gap:6px; }
          .nav a { display:flex; align-items:center; gap:10px; padding:10px 12px; border-radius:12px; color:var(--ink); }
          .nav a.active { background:#EEF2FF; color:#1E3A8A; border-left:3px solid var(--accent); padding-left:9px; }
          .main { flex:1; display:flex; flex-direction:column; }
          .topbar { position:sticky; top:0; z-index:10; background:#fff; border-bottom:1px solid var(--border); height:64px; display:flex; align-items:center; justify-content:space-between; padding:0 24px; }
          .brand { font-weight:800; letter-spacing:.08em; font-size:14px; }
          .breadcrumb { font-size:14px; color:var(--muted); margin-left:8px; }
          .search { flex:1; max-width:420px; margin:0 24px; }
          .search input { width:100%; padding:8px 12px; border:1px solid var(--border); border-radius:12px; }
          .chip { display:inline-flex; align-items:center; gap:6px; padding:6px 12px; border-radius:999px; background:#E7F7ED; color:#166534; font-weight:600; font-size:12px; }
          .top-actions { display:flex; align-items:center; gap:12px; }
          .icon-btn { border:1px solid var(--border); background:#fff; border-radius:12px; padding:6px 10px; font-size:12px; }
          .menu { position:relative; }
          .menu summary { list-style:none; cursor:pointer; border:1px solid var(--border); border-radius:12px; padding:6px 10px; font-size:12px; }
          .menu summary::-webkit-details-marker { display:none; }
          .menu .menu-panel { position:absolute; right:0; top:38px; background:#fff; border:1px solid var(--border); border-radius:12px; padding:8px; min-width:160px; box-shadow:0 12px 24px -18px rgba(15,23,42,.4); }
          .menu .menu-panel a { display:block; padding:8px 10px; border-radius:8px; }
          .menu .menu-panel a:hover { background:#F1F5F9; }
          .content { padding:24px; }
          .card { background:var(--card); border:1px solid var(--border); border-radius:16px; padding:16px; box-shadow:0 8px 20px -18px rgba(15,23,42,.35); }
          .btn { display:inline-flex; align-items:center; justify-content:center; padding:10px 16px; border-radius:12px; font-weight:600; border:1px solid transparent; }
          .btn.primary { background:var(--accent); color:#fff; }
          .btn.outline { border-color:var(--border); background:#fff; color:var(--ink); }
          .muted { color:var(--muted); }
          .disabled { pointer-events:none; opacity:.5; }
          .actions { display:flex; gap:10px; flex-wrap:wrap; align-items:center; }
          .form-control { width:100%; border:1px solid var(--border); border-radius:12px; padding:8px 10px; margin-top:6px; }
          .table { width:100%; border-collapse:collapse; }
          .table th { text-align:left; padding:8px; color:var(--muted); font-size:12px; }
          .table td { padding:8px; border-top:1px solid var(--border); }
          @media (max-width: 1024px) { .sidebar { display:none; } }
          @media (max-width: 720px) { .topbar { padding:0 16px; } .search { display:none; } }
        </style>
      </head>
      <body>
        <div class="app">
          <aside class="sidebar">
            <div class="brand" style="display:flex; align-items:center; gap:8px;"><div style="width:28px; height:28px; background:linear-gradient(135deg,#34d399,#06b6d4); border-radius:8px; display:flex; align-items:center; justify-content:center; color:#fff; font-weight:bold; font-size:13px;">M</div>MediControl</div>
            <h4>Gestión</h4>
            <nav class="nav">
              ${items
                .slice(0, 5)
                .map(
                  (i) =>
                    `<a class="${active === i.key ? "active" : ""}" href="${i.href}">${i.label}</a>`
                )
                .join("")}
            </nav>
            <h4>Documentos</h4>
            <nav class="nav">
              ${items
                .slice(5, 7)
                .map(
                  (i) =>
                    `<a class="${active === i.key ? "active" : ""}" href="${i.href}">${i.label}</a>`
                )
                .join("")}
            </nav>
            <h4>Sistema</h4>
            <nav class="nav">
              ${items
                .slice(7)
                .map(
                  (i) =>
                    `<a class="${active === i.key ? "active" : ""}" href="${i.href}">${i.label}</a>`
                )
                .join("")}
            </nav>
          </aside>
          <div class="main">
            <header class="topbar">
              <div style="display:flex; align-items:center; gap:8px;">
                <div class="brand" style="display:flex; align-items:center; gap:8px;"><div style="width:28px; height:28px; background:linear-gradient(135deg,#34d399,#06b6d4); border-radius:8px; display:flex; align-items:center; justify-content:center; color:#fff; font-weight:bold; font-size:13px;">M</div>MediControl</div>
                <div class="breadcrumb">${escapeHtml(title)}</div>
              </div>
              <div class="search">
                <form method="GET" action="/admin/search" style="margin:0;">
                  <input name="q" placeholder="Buscar paciente, medicamento o alerta" />
                </form>
              </div>
              <div class="top-actions">
                <span class="chip">● Sincronizado</span>
                <button class="icon-btn">🔔</button>
                <details class="menu">
                  <summary>👤 ${userName}</summary>
                  <div class="menu-panel">
                    <div class="muted" style="padding:4px 8px; font-size:12px;">${userEmail}</div>
                    <a href="/admin/settings">Ajustes</a>
                    <a href="/admin/logout">Cerrar sesión</a>
                  </div>
                </details>
              </div>
            </header>
            <main class="content">
              ${content}
            </main>
          </div>
        </div>
      </body>
    </html>
  `;
}

function buildUserName(name, firstName, lastName) {
  if (name) return name.trim();
  const parts = [firstName, lastName].filter(Boolean);
  return parts.length ? parts.join(" ").trim() : "";
}

async function importMedsFromPdf(filePath, familyId, userId, useOcr = false, skipNameCheck = false) {
  const pdfParse = require("pdf-parse");
  const buffer = fs.readFileSync(filePath);
  const pdf = await pdfParse(buffer);
  let text = pdf.text;
  let ocrUsed = false;
  console.log(`[IMPORT PDF] pdf-parse text length: ${(text || "").length}`);
  // Auto-fallback to OCR if pdf-parse gets little/no text
  if (useOcr || !text || text.trim().length < 50) {
    try {
      text = await runOcrOnPdf(filePath, "deu+eng");
      ocrUsed = true;
      console.log(`[IMPORT PDF] OCR text length: ${(text || "").length}`);
    } catch (ocrErr) {
      console.error(`[IMPORT PDF] OCR failed:`, ocrErr.message);
      if (!text || text.trim().length < 10) {
        throw new Error("No se pudo extraer texto del PDF. OCR falló: " + ocrErr.message);
      }
    }
  }
  const rawText = (text || "").slice(0, 2000);
  if (!skipNameCheck) {
    const userResult = await pool.query(
      `SELECT id, name, first_name, last_name FROM users WHERE id = $1 AND family_id = $2`,
      [userId, familyId]
    );
    const user = userResult.rows[0];
    if (!user || !patientNameMatches(text, user)) {
      throw new Error("Nombre de paciente no coincide o no se encontró en la receta.");
    }
  }
  const lines = text
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter((line) => line && line.length > 3 && !line.startsWith("Medikament") && !line.startsWith("Seite") && !line.startsWith("Datum"));

  const extractQuantity = (line) => {
    const match = line.match(/(\d+)\s*(Stk|ml|Amp|Btl)\b/i);
    if (!match) return { qty: 0, unit: "unidades" };
    return { qty: Number(match[1]), unit: match[2] };
  };
  const extractDosage = (line) => {
    const match = line.match(/(\d+(?:\.\d+)?)\s*(mg|mcg|g|IE\/ml|IU\/ml)\b/i);
    if (!match) return "N/A";
    return `${match[1]} ${match[2]}`;
  };
  const extractExpiry = (line) => {
    const match = line.match(/(\d{2}\.\d{2}\.\d{4})/);
    if (!match) return null;
    const [day, month, year] = match[1].split(".");
    return `${year}-${month}-${day}`;
  };
  const extractName = (line) => {
    const cleaned = line
      .replace(/\d+\s*(Stk|ml|Amp|Btl)\b/gi, "")
      .replace(/\d+(?:\.\d+)?\s*(mg|mcg|g|IE\/ml|IU\/ml)\b/gi, "")
      .replace(/\d{2}\.\d{2}\.\d{4}/g, "")
      .replace(/\b(auf weiteres)\b/gi, "")
      .replace(/[-–]\s*$/, "")
      .trim();
    return cleaned.replace(/\s{2,}/g, " ");
  };
  const parseColumns = (line) => {
    const split = line.split(/auf\s+weiteres/i);
    if (split.length < 2) return { mo: "-", mi: "-", ab: "-", na: "-", extra: "" };
    const right = split[1].trim();
    const parts = right.split(/\s+/);
    return {
      mo: parts[0] || "-",
      mi: parts[1] || "-",
      ab: parts[2] || "-",
      na: parts[3] || "-",
      extra: parts.slice(4).join(" "),
    };
  };

  const batchResult = await pool.query(
    `INSERT INTO import_batches (family_id, user_id, source_file)
     VALUES ($1, $2, $3)
     RETURNING id`,
    [familyId, userId || null, filePath || null]
  );
  const batchId = batchResult.rows[0].id;

  let inserted = 0;
  let warnings = 0;
  const defaultStart = process.env.DEFAULT_SCHEDULE_START_DATE || null;
  for (const line of lines) {
    if (line.startsWith("--")) continue;
    const name = extractName(line);
    if (!name || name.length < 3) continue;
    const dosage = extractDosage(line);
    const { qty } = extractQuantity(line);
    const expiryDate = extractExpiry(line);
    const columns = parseColumns(line);

    const medicineResult = await upsertMedicineForUser({
      familyId,
      userId,
      name,
      dosage,
      qty,
      expiryDate,
      batchId,
    });
    const medicineId = medicineResult.id;
    const scheduleTimes = [
      { key: "mo", time: "08:00" },
      { key: "mi", time: "14:00" },
      { key: "ab", time: "20:00" },
      { key: "na", time: "22:00" },
    ];
    const dayValue = {
      mo: columns.mo,
      mi: columns.mi,
      ab: columns.ab,
      na: columns.na,
    };
    for (const slot of scheduleTimes) {
      const value = dayValue[slot.key];
      if (!value || value === "-" || value === "0") continue;
      await pool.query(
        `INSERT INTO schedules (medicine_id, user_id, dose_time, frequency, days_of_week, start_date)
         VALUES ($1, $2, $3, $4, $5, $6)`,
        [medicineId, userId, slot.time, value, "1234567", defaultStart]
      );
    }
    const suspicious = qty === 0 || dosage === "N/A" || !expiryDate;
    if (suspicious) {
      warnings += 1;
      await pool.query(
        `INSERT INTO alerts (family_id, type, level, message, med_name, med_dosage, alert_date)
         VALUES ($1, 'import_warning', 'warning', $2, $3, $4, $5)`,
        [
          familyId,
          `Revisar importación: ${name} (stock: ${qty || 0}, dosis: ${dosage}, caducidad: ${
            expiryDate || "N/A"
          })`,
          name,
          dosage || "N/A",
          new Date().toISOString().slice(0, 10),
        ]
      );
    }
    inserted += 1;
  }
  console.log(`[IMPORT PDF] Resultado: ${inserted} medicamentos, ${warnings} advertencias, ${lines.length} líneas procesadas`);
  return { inserted, warnings, batchId, rawText, ocrUsed, linesProcessed: lines.length };
}

function requireRole(roles) {
  return (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({ error: "no autenticado" });
    }
    if (!roles.includes(req.user.role)) {
      return res.status(403).json({ error: "sin permisos" });
    }
    return next();
  };
}

function resolveFamilyScope(req) {
  const familyId = getFamilyId(req);
  if (req.user?.role === "superuser") {
    return familyId;
  }
  return req.user?.family_id || familyId;
}

app.get("/health", async (_req, res) => {
  try {
    const r = await pool.query("SELECT NOW() AS time, current_database() AS db");
    res.json({ ok: true, db: r.rows[0].db, time: r.rows[0].time });
  } catch (error) {
    console.error("[HEALTH] DB error:", error.message);
    res.status(500).json({ ok: false, error: error.message, hint: "Database connection failed" });
  }
});

// Diagnóstico: muestra info del servidor sin consultar DB
app.get("/diag", (req, res) => {
  res.json({
    ok: true,
    node: process.version,
    uptime: Math.round(process.uptime()) + "s",
    memory: Math.round(process.memoryUsage().rss / 1024 / 1024) + "MB",
    env: {
      NODE_ENV: process.env.NODE_ENV || "dev",
      HAS_DATABASE_URL: !!process.env.DATABASE_URL,
      HAS_JWT_SECRET: !!process.env.JWT_SECRET,
      PORT: process.env.PORT || "4000",
    },
    cookies: req.cookies ? Object.keys(req.cookies) : [],
    hasUser: !!req.user,
  });
});

app.get("/", (_req, res) => {
  res.json({
    ok: true,
    message: "Backend de MediControl",
    endpoints: [
      "/health",
      "/auth/register",
      "/auth/login",
      "/auth/me",
      "/api/families",
      "/api/users",
      "/api/medicines",
      "/api/schedules",
      "/api/dose-logs",
    ],
  });
});

// =============================================================================
// AUTH
// =============================================================================
app.post("/auth/register", async (req, res) => {
  const {
    family_id,
    name,
    first_name,
    last_name,
    street,
    house_number,
    postal_code,
    city,
    email,
    password,
    role,
  } = req.body || {};
  let safeRole = ["admin", "superuser", "user"].includes(role) ? role : "user";
  if (safeRole === "superuser" && req.user?.role !== "superuser") {
    safeRole = "user";
  }

  const finalName = buildUserName(name, first_name, last_name);
  if (!family_id || !finalName || !email || !password) {
    return res
      .status(400)
      .json({ error: "family_id, nombre, email y password son requeridos" });
  }

  try {
    const family = await pool.query(`SELECT id FROM families WHERE id = $1`, [
      Number(family_id),
    ]);
    if (family.rows.length === 0) {
      return res.status(404).json({ error: "familia no encontrada" });
    }
    const hashed = await bcrypt.hash(password, 10);
    const result = await pool.query(
      `INSERT INTO users (family_id, name, first_name, last_name, street, house_number, postal_code, city, email, password_hash, role)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
       RETURNING id, family_id, name, first_name, last_name, email, role, created_at, must_change_password`,
      [
        Number(family_id),
        finalName,
        first_name || null,
        last_name || null,
        street || null,
        house_number || null,
        postal_code || null,
        city || null,
        email,
        hashed,
        safeRole,
      ]
    );

    const user = result.rows[0];
    const token = signToken(user);
    res.cookie(TOKEN_NAME, token, cookieOpts(req));

    res.status(201).json({ user, token });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post("/auth/login", async (req, res) => {
  const { family_id, email, password } = req.body || {};
  if (!family_id || !email || !password) {
    return res
      .status(400)
      .json({ error: "family_id, email y password son requeridos" });
  }

  try {
    const result = await pool.query(
      `SELECT id, family_id, name, first_name, last_name, email, role, password_hash, must_change_password
       FROM users
       WHERE family_id = $1 AND email = $2`,
      [Number(family_id), email]
    );
    if (result.rows.length === 0) {
      return res.status(401).json({ error: "credenciales inválidas" });
    }

    const user = result.rows[0];
    const ok = await bcrypt.compare(password, user.password_hash);
    if (!ok) {
      return res.status(401).json({ error: "credenciales inválidas" });
    }

    const token = signToken(user);
    res.cookie(TOKEN_NAME, token, cookieOpts(req));

    const { password_hash, ...safeUser } = user;
    res.json({ user: safeUser, token });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get("/auth/me", (req, res) => {
  if (!req.user) {
    return res.status(401).json({ error: "no autenticado" });
  }
  res.json({ user: req.user });
});

app.post("/auth/logout", (_req, res) => {
  res.clearCookie(TOKEN_NAME, {
    httpOnly: true,
    sameSite: "lax",
    secure: false,
  });
  res.json({ ok: true });
});

app.post("/auth/forgot", async (req, res) => {
  const { family_id, email } = req.body || {};
  if (!family_id || !email) {
    return res
      .status(400)
      .json({ error: "family_id y email son requeridos" });
  }

  try {
    const userResult = await pool.query(
      `SELECT id FROM users WHERE family_id = $1 AND email = $2`,
      [Number(family_id), email]
    );

    if (userResult.rows.length === 0) {
      return res.json({ ok: true });
    }

    const token = crypto.randomBytes(24).toString("hex");
    const expiresAt = new Date(Date.now() + 30 * 60 * 1000);

    await pool.query(
      `INSERT INTO password_resets (user_id, token, expires_at)
       VALUES ($1, $2, $3)`,
      [userResult.rows[0].id, token, expiresAt]
    );

    if (mailTransport) {
      const resetLink = `${req.protocol}://${req.get("host")}/reset?token=${token}`;
      await sendUserEmail(
        email,
        "Restablecer contraseña",
        `<p>Hemos recibido una solicitud para restablecer tu contraseña.</p>
         <p>Token: <strong>${token}</strong></p>
         <p>Enlace (opcional): ${resetLink}</p>
         <p>Este token vence en 30 minutos.</p>`
      );
    }

    res.json({ ok: true, reset_token: DEV_SHOW_RESET_TOKEN ? token : undefined });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post("/auth/reset", async (req, res) => {
  const { token, new_password } = req.body || {};
  if (!token || !new_password) {
    return res
      .status(400)
      .json({ error: "token y new_password son requeridos" });
  }

  try {
    const result = await pool.query(
      `SELECT id, user_id, expires_at, used_at
       FROM password_resets
       WHERE token = $1`,
      [token]
    );
    if (result.rows.length === 0) {
      return res.status(400).json({ error: "token inválido" });
    }
    const row = result.rows[0];
    if (row.used_at) {
      return res.status(400).json({ error: "token ya utilizado" });
    }
    if (new Date(row.expires_at) < new Date()) {
      return res.status(400).json({ error: "token expirado" });
    }

    const hash = await bcrypt.hash(new_password, 10);
    await pool.query(`UPDATE users SET password_hash = $1 WHERE id = $2`, [
      hash,
      row.user_id,
    ]);
    await pool.query(`UPDATE password_resets SET used_at = NOW() WHERE id = $1`, [
      row.id,
    ]);

    res.json({ ok: true });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post("/auth/change-password", requireAuth, async (req, res) => {
  const { current_password, new_password } = req.body || {};
  if (!current_password || !new_password) {
    return res
      .status(400)
      .json({ error: "current_password y new_password son requeridos" });
  }

  try {
    const result = await pool.query(
      `SELECT id, password_hash FROM users WHERE id = $1`,
      [req.user.sub]
    );
    if (result.rows.length === 0) {
      return res.status(404).json({ error: "usuario no encontrado" });
    }
    const ok = await bcrypt.compare(
      current_password,
      result.rows[0].password_hash
    );
    if (!ok) {
      return res.status(401).json({ error: "password actual incorrecto" });
    }
    const hash = await bcrypt.hash(new_password, 10);
    await pool.query(
      `UPDATE users SET password_hash = $1, must_change_password = false WHERE id = $2`,
      [hash, req.user.sub]
    );
    res.json({ ok: true });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

async function sendWelcomeEmail(email, tempPassword) {
  if (!mailTransport || !email) {
    return false;
  }
  await mailTransport.sendMail({
    from: process.env.SMTP_USER,
    to: email,
    subject: "Tu acceso inicial",
    html: `<p>Tu contraseña temporal es: <strong>${escapeHtml(
      tempPassword
    )}</strong></p><p>Ingresa y cámbiala desde la app.</p>`,
  });
  return true;
}

// =============================================================================
// HTML DASHBOARD (backend)
// =============================================================================
app.get("/admin/login", (_req, res) => {
  try {
    const errorMessage = _req.query?.error
      ? "Credenciales inválidas. Intenta nuevamente."
      : "";
    const html = `<!doctype html>
    <html lang="de">
    <head>
      <meta charset="utf-8" />
      <meta name="viewport" content="width=device-width, initial-scale=1" />
      <title>MediControl – Admin</title>
      <style>
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body {
          min-height: 100vh;
          background: linear-gradient(135deg, #0f172a 0%, #1e293b 50%, #0f172a 100%);
          display: flex; align-items: center; justify-content: center;
          font-family: "Inter", -apple-system, BlinkMacSystemFont, sans-serif;
          padding: 24px;
        }
        .login-card {
          width: 100%; max-width: 400px; text-align: center;
        }
        .logo {
          width: 64px; height: 64px; border-radius: 16px;
          background: linear-gradient(135deg, #34d399, #06b6d4);
          display: flex; align-items: center; justify-content: center;
          margin: 0 auto 16px; box-shadow: 0 8px 24px rgba(52,211,153,0.3);
        }
        .logo span { color: #fff; font-weight: 800; font-size: 28px; }
        h1 { color: #fff; font-size: 24px; font-weight: 700; }
        .subtitle { color: #94a3b8; font-size: 13px; margin-top: 4px; }
        .badge { display: inline-block; background: rgba(52,211,153,0.15); color: #34d399; font-size: 10px; font-weight: 700; padding: 3px 10px; border-radius: 20px; margin-top: 12px; border: 1px solid rgba(52,211,153,0.2); }
        .error { background: rgba(239,68,68,0.1); border: 1px solid rgba(239,68,68,0.2); color: #f87171; font-size: 13px; padding: 10px 14px; border-radius: 12px; margin-top: 20px; }
        form { margin-top: 28px; text-align: left; }
        label { display: block; color: #94a3b8; font-size: 11px; font-weight: 600; margin-bottom: 6px; margin-top: 16px; text-transform: uppercase; letter-spacing: 0.05em; }
        input[type="text"], input[type="email"], input[type="password"] {
          width: 100%; background: rgba(30,41,59,0.8); border: 1px solid rgba(100,116,139,0.3);
          border-radius: 12px; padding: 12px 14px; font-size: 14px; color: #fff;
          outline: none; transition: border-color 0.2s;
        }
        input:focus { border-color: #34d399; }
        input::placeholder { color: #475569; }
        button[type="submit"] {
          width: 100%; margin-top: 24px; padding: 14px;
          background: linear-gradient(135deg, #34d399, #06b6d4);
          color: #fff; font-weight: 700; font-size: 14px; border: none;
          border-radius: 12px; cursor: pointer; transition: opacity 0.2s;
          box-shadow: 0 4px 16px rgba(52,211,153,0.25);
        }
        button[type="submit"]:hover { opacity: 0.9; }
        .footer { margin-top: 24px; color: #475569; font-size: 10px; }
        .footer a { color: #64748b; text-decoration: none; }
        .footer a:hover { color: #94a3b8; }
      </style>
    </head>
    <body>
      <div class="login-card">
        <div class="logo"><span>M</span></div>
        <h1>MediControl</h1>
        <p class="subtitle">Admin Panel · Ihre Medikamente. Unter Kontrolle.</p>
        <span class="badge">🇨🇭 Swiss Healthcare SaaS</span>
        ${errorMessage ? `<div class="error">${errorMessage}</div>` : ""}
        <form method="POST" action="/admin/login">
          <label>Family ID</label>
          <input name="family_id" type="text" placeholder="1" required value="1" />
          <label>Email</label>
          <input name="email" type="email" placeholder="admin@medicontrol.app" required />
          <label>Password</label>
          <input name="password" type="password" placeholder="••••••" required />
          <button type="submit">Anmelden</button>
        </form>
        <p class="footer">© ${new Date().getFullYear()} MediControl · <a href="/">Zurück zur App</a></p>
      </div>
    </body>
    </html>`;
    res.send(html);
  } catch (error) {
    console.error("[ADMIN LOGIN GET] Error:", error.message, error.stack);
    res.status(500).send(`<html><body><h2>Error en login page</h2><pre>${error.message}\n${error.stack}</pre><a href="/diag">Ver diagnóstico</a></body></html>`);
  }
});

app.post("/admin/login", async (req, res) => {
  const { family_id, email, password } = req.body || {};
  if (!family_id || !email || !password) {
    return res.redirect("/admin/login?error=1");
  }

  try {
    console.log("[AUTH] Intentando login admin:", email, "family:", family_id);
    const result = await pool.query(
      `SELECT id, family_id, name, email, role, password_hash
       FROM users
       WHERE family_id = $1 AND email = $2`,
      [Number(family_id), email]
    );
    console.log("[AUTH] Query OK, rows:", result.rows.length);
    if (result.rows.length === 0) {
      return res.redirect("/admin/login?error=1");
    }

    const user = result.rows[0];
    const ok = await bcrypt.compare(password, user.password_hash);
    if (!ok) {
      return res.redirect("/admin/login?error=1");
    }

    const token = signToken(user);
    res.cookie(TOKEN_NAME, token, cookieOpts(req));
    console.log("[AUTH] Login exitoso:", email, "role:", user.role);
    res.redirect("/dashboard");
  } catch (error) {
    console.error("[AUTH] Error en login:", error.message);
    res.redirect("/admin/login?error=1");
  }
});

app.get("/admin/logout", (req, res) => {
  const isSecure = req.headers["x-forwarded-proto"] === "https" || req.secure;
  res.clearCookie(TOKEN_NAME, {
    httpOnly: true,
    sameSite: isSecure ? "none" : "lax",
    secure: isSecure,
  });
  res.redirect("/admin/login");
});

app.get("/dashboard", requireRoleHtml(["admin", "superuser"]), async (req, res) => {
  try {
  const familyId = req.user.family_id;
  console.log("[DASHBOARD] Cargando para family:", familyId, "user:", req.user.sub);
  const usersList = await pool.query(
    `SELECT id, name, email FROM users WHERE family_id = $1 ORDER BY name ASC`,
    [familyId]
  );
  const selectedUserId = Number(req.query?.user_id || req.user.sub);
  const safeUserId = Number.isFinite(selectedUserId)
    ? selectedUserId
    : usersList.rows[0]?.id;
  console.log("[DASHBOARD] safeUserId:", safeUserId);
  const [
    usersCount,
    medsCount,
    schedulesCount,
    lastUsers,
    lastMeds,
    alertsCount,
    alertsList,
    lowStockList,
  ] = await Promise.all([
      pool.query("SELECT COUNT(*) FROM users WHERE family_id = $1", [familyId]),
      pool.query("SELECT COUNT(*) FROM medicines WHERE family_id = $1 AND user_id = $2", [
        familyId,
        safeUserId,
      ]),
      pool.query(
        `SELECT COUNT(*) FROM schedules s
         JOIN medicines m ON m.id = s.medicine_id
         JOIN users u ON u.id = s.user_id
         WHERE m.family_id = $1 AND u.family_id = $1 AND s.user_id = $2`,
        [familyId, safeUserId]
      ),
      pool.query(
        `SELECT id, name, email, role, created_at
         FROM users
         WHERE family_id = $1
         ORDER BY created_at DESC
         LIMIT 5`,
        [familyId]
      ),
      pool.query(
        `SELECT id, name, dosage, current_stock, expiration_date, created_at
         FROM medicines
         WHERE family_id = $1 AND user_id = $2
         ORDER BY created_at DESC
         LIMIT 5`,
        [familyId, safeUserId]
      ),
      pool.query(
        `SELECT COUNT(*) FROM alerts
         WHERE family_id = $1 AND read_at IS NULL`,
        [familyId]
      ),
      pool.query(
        `SELECT type, level, message, created_at, med_name, med_dosage, dose_time, alert_date
         FROM alerts
         WHERE family_id = $1
         ORDER BY created_at DESC
         LIMIT 6`,
        [familyId]
      ),
      pool.query(
        `SELECT name, dosage, current_stock
         FROM medicines
         WHERE family_id = $1 AND user_id = $2 AND current_stock <= 10
         ORDER BY current_stock ASC
         LIMIT 6`,
        [familyId, safeUserId]
      ),
    ]);
  console.log("[DASHBOARD] Queries OK");

  const content = `
    <style>
      .context { display:flex; align-items:center; justify-content:space-between; gap:16px; flex-wrap:wrap; }
      .context .left { min-width:240px; }
      .context label { font-size:12px; color:var(--muted); text-transform:uppercase; letter-spacing:.08em; }
      .context select, .context input { margin-top:6px; padding:8px 10px; border:1px solid var(--border); border-radius:12px; width:100%; }
      .chip-row { display:flex; gap:8px; flex-wrap:wrap; }
      .chip-lite { padding:6px 10px; border-radius:999px; border:1px solid var(--border); font-size:12px; color:var(--muted); }
      .kpis { display:grid; grid-template-columns:repeat(12, 1fr); gap:16px; margin-top:16px; }
      .kpi { grid-column: span 3; }
      .kpi .title { font-size:11px; text-transform:uppercase; letter-spacing:.08em; color:var(--muted); }
      .kpi .value { font-size:24px; font-weight:700; margin:6px 0; }
      .kpi .meta { font-size:12px; color:var(--muted); }
      .kpi .action { margin-top:8px; font-size:12px; color:#1d4ed8; display:inline-block; }
      .panels { display:grid; grid-template-columns:repeat(12, 1fr); gap:16px; margin-top:16px; }
      .panel-wide { grid-column: span 8; }
      .panel-narrow { grid-column: span 4; }
      .panel-title { font-size:16px; font-weight:700; margin:0 0 8px; }
      .list { display:flex; flex-direction:column; gap:10px; }
      .list-item { padding:10px; border:1px solid var(--border); border-radius:12px; }
      .badge { font-size:11px; padding:3px 8px; border-radius:999px; display:inline-flex; align-items:center; gap:6px; }
      .badge.critical { background:#FEE2E2; color:#991B1B; }
      .badge.warn { background:#FEF3C7; color:#92400E; }
      .badge.info { background:#DBEAFE; color:#1E3A8A; }
      .empty { font-size:12px; color:var(--muted); }
      .meta { font-size:12px; color:var(--muted); }
      @media (max-width: 1024px) {
        .kpi { grid-column: span 6; }
        .panel-wide, .panel-narrow { grid-column: span 12; }
      }
      @media (max-width: 720px) {
        .kpi { grid-column: span 12; }
        .context { flex-direction:column; align-items:stretch; }
      }
    </style>
    <div class="card context">
      <div class="left">
        <label>Paciente activo</label>
        <form method="GET" action="/dashboard" id="patientForm">
          <select name="user_id" onchange="document.getElementById('patientForm').submit()">
            ${
              usersList.rows.length
                ? usersList.rows
                    .map(
                      (u) =>
                        `<option value="${u.id}" ${
                          u.id === safeUserId ? "selected" : ""
                        }>${escapeHtml(u.name)} · ${escapeHtml(u.email)}</option>`
                    )
                    .join("")
                : `<option value="">Sin usuarios</option>`
            }
          </select>
        </form>
      </div>
      <div class="chip-row">
        <span class="chip-lite">Alertas ${alertsCount.rows[0].count}</span>
        <span class="chip-lite">Inventario ${medsCount.rows[0].count}</span>
        <span class="chip-lite">Usuarios ${usersCount.rows[0].count}</span>
      </div>
      <div style="display:flex; gap:10px; align-items:center;">
        <a class="btn primary" href="/admin/user-edit/${safeUserId}">Ver ficha</a>
        <details class="menu">
          <summary class="btn outline">Acciones ▾</summary>
          <div class="menu-panel">
            <a href="/admin/user-new">Nuevo paciente</a>
            <a href="/admin/alerts">Crear alerta</a>
            <a href="/admin/import">Importar</a>
            <a href="/admin/medical-records">Ver historial</a>
          </div>
        </details>
      </div>
    </div>

    <div class="kpis">
      <div class="card kpi">
        <div class="title">Sesión activa</div>
        <div class="value">${escapeHtml(req.user.email || "admin")}</div>
        <div class="meta">${escapeHtml(req.user.role || "admin")}</div>
        <div class="action">Usuario actual</div>
      </div>
      <div class="card kpi">
        <div class="title">Alertas activas</div>
        <div class="value">${alertsCount.rows[0].count}</div>
        <div class="meta">Pendientes de revisión</div>
        <a class="action" href="/admin/alerts">Ver alertas</a>
      </div>
      <div class="card kpi">
        <div class="title">Inventario total</div>
        <div class="value">${medsCount.rows[0].count}</div>
        <div class="meta">Paciente activo</div>
        <a class="action" href="/admin/meds-list">Gestionar inventario</a>
      </div>
      <div class="card kpi">
        <div class="title">Usuarios activos</div>
        <div class="value">${usersCount.rows[0].count}</div>
        <div class="meta">Familia ${familyId}</div>
        <a class="action" href="/admin/reminders/run">Recordatorio semanal</a>
      </div>
    </div>

    <div class="panels">
      <div class="card panel-wide">
        <h2 class="panel-title">Alertas críticas</h2>
        <div class="list">
          ${
            alertsList.rows.length
              ? alertsList.rows
                  .map((row) => {
                    const level = row.level || "info";
                    const badgeClass =
                      level === "warning"
                        ? "warn"
                        : level === "critical"
                        ? "critical"
                        : "info";
                    const badgeLabel =
                      level === "warning"
                        ? "Aviso"
                        : level === "critical"
                        ? "Crítico"
                        : "Info";
                    const meta = [
                      row.med_name || "",
                      row.med_dosage || "",
                      row.dose_time || "",
                      row.alert_date ? formatDateOnlyDisplay(row.alert_date) : "",
                    ]
                      .filter(Boolean)
                      .join(" · ");
                    return `<div class="list-item">
                      <div style="display:flex; justify-content:space-between; align-items:center;">
                        <strong>${escapeHtml(row.message || "Alerta")}</strong>
                        <span class="badge ${badgeClass}">${badgeLabel}</span>
                      </div>
                      <div class="meta">${escapeHtml(meta || "Sin detalles")}</div>
                    </div>`;
                  })
                  .join("")
              : `<div class="empty">No hay alertas críticas en este momento.</div>`
          }
        </div>
      </div>
      <div class="card panel-narrow">
        <h2 class="panel-title">Inventario bajo stock</h2>
        <div class="list">
          ${
            lowStockList.rows.length
              ? lowStockList.rows
                  .map(
                    (row) => `<div class="list-item">
                      <strong>${escapeHtml(row.name)}</strong>
                      <div class="meta">${escapeHtml(row.dosage || "N/A")} · Stock ${row.current_stock}</div>
                    </div>`
                  )
                  .join("")
              : `<div class="empty">Sin medicamentos críticos para este paciente.</div>`
          }
        </div>
        <div style="margin-top:10px;">
          <a class="btn outline" href="/admin/meds-list">Ver inventario</a>
        </div>
      </div>
    </div>
  `;
  res.send(renderShell(req, "Panel de control", "panel", content));

  } catch (error) {
    console.error("[DASHBOARD] Error:", error.message);
    const content = `
      <div class="card" style="max-width:640px; margin:0 auto;">
        <h1>Error al cargar el dashboard</h1>
        <p style="color:#b91c1c; margin-top:12px;">${escapeHtml(error.message)}</p>
        <p style="color:var(--muted); margin-top:8px; font-size:13px;">Esto puede ocurrir si la base de datos está reconectándose. Intenta recargar la página.</p>
        <div style="margin-top:16px; display:flex; gap:10px;">
          <a class="btn primary" href="/dashboard">Reintentar</a>
          <a class="btn outline" href="/admin/logout">Cerrar sesión</a>
        </div>
      </div>
    `;
    res.send(renderShell(req, "Error", "panel", content));
  }
});

// =============================================================================
// ADMIN USERS HTML
// =============================================================================
app.get("/admin/user-new", requireRoleHtml(["admin", "superuser"]), (_req, res) => {
  const fieldClass = 'class="form-control"';
  const content = `
    <div class="card" style="max-width:640px; margin:0 auto;">
      <h1>Nuevo usuario</h1>
      <form method="POST" action="/admin/user-create">
        <label>Nombre</label>
        <input name="first_name" required ${fieldClass} />
        <label>Apellido</label>
        <input name="last_name" required ${fieldClass} />
        <label>Fecha de nacimiento</label>
        <input name="birth_date" type="date" ${fieldClass} />
        <label>Calle</label>
        <input name="street" ${fieldClass} />
        <label>Número</label>
        <input name="house_number" ${fieldClass} />
        <label>Código postal</label>
        <input name="postal_code" ${fieldClass} />
        <label>Ciudad</label>
        <input name="city" ${fieldClass} />
        <label>Email</label>
        <input name="email" type="email" required ${fieldClass} />
        <h2 style="margin-top:18px; font-size:14px;">Médico de cabecera</h2>
        <label>Nombre</label>
        <input name="doctor_first_name" ${fieldClass} />
        <label>Apellido</label>
        <input name="doctor_last_name" ${fieldClass} />
        <label>Calle</label>
        <input name="doctor_street" ${fieldClass} />
        <label>Número</label>
        <input name="doctor_house_number" ${fieldClass} />
        <label>Código postal</label>
        <input name="doctor_postal_code" ${fieldClass} />
        <label>Ciudad</label>
        <input name="doctor_city" ${fieldClass} />
        <label>Email</label>
        <input name="doctor_email" type="email" ${fieldClass} />
        <label>Teléfono</label>
        <input name="doctor_phone" ${fieldClass} />
        <label>Password temporal</label>
        <input name="password" type="password" value="${DEFAULT_TEMP_PASSWORD}" required ${fieldClass} />
        <label>Rol</label>
        <select name="role" ${fieldClass}>
          <option value="user">user</option>
          <option value="admin">admin</option>
          <option value="superuser">superuser</option>
        </select>
        <button class="btn primary" type="submit" style="width:100%; margin-top:18px;">Crear usuario</button>
      </form>
    </div>
  `;
  res.send(renderShell(_req, "Nuevo usuario", "patients", content));
});

app.post("/admin/user-create", requireRoleHtml(["admin", "superuser"]), async (req, res) => {
  const familyId = req.user.family_id;
  const {
    first_name,
    last_name,
    birth_date,
    street,
    house_number,
    postal_code,
    city,
    email,
    password,
    role,
    doctor_first_name,
    doctor_last_name,
    doctor_email,
    doctor_phone,
    doctor_street,
    doctor_house_number,
    doctor_postal_code,
    doctor_city,
  } = req.body || {};
  const safeRole = ["admin", "superuser", "user"].includes(role) ? role : "user";
  const finalName = buildUserName(null, first_name, last_name);
  if (!finalName || !email || !password) {
    return res.redirect("/admin/user-new");
  }
  try {
    const tempPassword = password || DEFAULT_TEMP_PASSWORD;
    const hashed = await bcrypt.hash(tempPassword, 10);
    const result = await pool.query(
      `INSERT INTO users (family_id, name, first_name, last_name, birth_date, street, house_number, postal_code, city, email, password_hash, role, must_change_password)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, true)
       RETURNING id`,
      [
        familyId,
        finalName,
        first_name || null,
        last_name || null,
        birth_date || null,
        street || null,
        house_number || null,
        postal_code || null,
        city || null,
        email,
        hashed,
        safeRole,
      ]
    );
    if (
      doctor_first_name ||
      doctor_last_name ||
      doctor_email ||
      doctor_phone ||
      doctor_street ||
      doctor_house_number ||
      doctor_postal_code ||
      doctor_city
    ) {
      await pool.query(
        `INSERT INTO doctors (family_id, user_id, first_name, last_name, email, phone, street, house_number, postal_code, city)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
         ON CONFLICT (family_id, user_id) DO UPDATE SET
           first_name = EXCLUDED.first_name,
           last_name = EXCLUDED.last_name,
           email = EXCLUDED.email,
           phone = EXCLUDED.phone,
           street = EXCLUDED.street,
           house_number = EXCLUDED.house_number,
           postal_code = EXCLUDED.postal_code,
           city = EXCLUDED.city`,
        [
          familyId,
          result.rows[0].id,
          doctor_first_name,
          doctor_last_name,
          doctor_email || null,
          doctor_phone || null,
          doctor_street || null,
          doctor_house_number || null,
          doctor_postal_code || null,
          doctor_city || null,
        ]
      );
    }
    try {
      await sendWelcomeEmail(email, tempPassword);
    } catch (emailError) {
      const content = `
        <div class="card">
          <h1>Usuario creado</h1>
          <p>El usuario fue creado, pero no se pudo enviar el email.</p>
          <p class="muted">${escapeHtml(emailError.message)}</p>
          <div style="margin-top:12px;">
            <a class="btn outline" href="/dashboard">Volver</a>
          </div>
        </div>
      `;
      return res.send(renderShell(req, "Usuario creado", "patients", content));
    }
    return res.redirect("/dashboard");
  } catch (error) {
    const isDuplicate = error?.code === "23505";
    if (isDuplicate) {
      try {
        const existing = await pool.query(
          `SELECT id FROM users WHERE family_id = $1 AND email = $2`,
          [familyId, email]
        );
        if (existing.rows[0]?.id) {
          return res.redirect(`/admin/user-edit/${existing.rows[0].id}?exists=1`);
        }
      } catch {
        // si falla la búsqueda, mostramos error estándar
      }
    }
    const message = isDuplicate
      ? "El email ya existe en esta familia."
      : "No se pudo crear el usuario.";
    const content = `
      <div class="card">
        <h1>Error al crear usuario</h1>
        <p>${message}</p>
        <p class="muted">${escapeHtml(error.message)}</p>
        <div style="margin-top:12px;">
          <a class="btn outline" href="/admin/user-new">Volver</a>
        </div>
      </div>
    `;
    return res.send(renderShell(req, "Error al crear usuario", "patients", content));
  }
});

app.get("/admin/user-edit/:id", requireRoleHtml(["admin", "superuser"]), async (req, res) => {
  const familyId = req.user.family_id;
  const id = Number(req.params.id);
  const [result, doctorResult] = await Promise.all([
    pool.query(
      `SELECT id, name, first_name, last_name, birth_date, street, house_number, postal_code, city, email, role,
              disclaimer_accepted_at, disclaimer_ip, disclaimer_lang
       FROM users WHERE id = $1 AND family_id = $2`,
      [id, familyId]
    ),
    pool.query(
      `SELECT * FROM doctors WHERE family_id = $1 AND user_id = $2`,
      [familyId, id]
    ),
  ]);
  if (result.rows.length === 0) {
    return res.redirect("/dashboard");
  }
  const user = result.rows[0];
  const doctor = doctorResult.rows[0] || {};
  const fieldClass = 'class="form-control"';
  const content = `
    <div class="card" style="max-width:640px; margin:0 auto;">
      <h1>Editar usuario</h1>
      ${user.disclaimer_accepted_at
        ? `<div style="background:#ECFDF5; border:1px solid #6EE7B7; border-radius:12px; padding:12px; margin-bottom:16px;">
            <p style="font-size:13px; color:#065F46; margin:0;">
              ✅ <strong>Aviso legal aceptado</strong> el ${new Date(user.disclaimer_accepted_at).toLocaleString("es-ES", { timeZone: "Europe/Zurich" })}
              · Idioma: ${escapeHtml(user.disclaimer_lang || "es")}
              · IP: ${escapeHtml(user.disclaimer_ip || "N/A")}
            </p>
          </div>`
        : `<div style="background:#FEF3C7; border:1px solid #FBBF24; border-radius:12px; padding:12px; margin-bottom:16px;">
            <p style="font-size:13px; color:#92400E; margin:0;">⚠️ <strong>Aviso legal NO aceptado</strong> - El usuario aún no ha aceptado los términos de uso.</p>
          </div>`
      }
      <form method="POST" action="/admin/user-save">
        <input type="hidden" name="id" value="${user.id}" />
        <label>Nombre</label>
        <input name="first_name" value="${escapeHtml(user.first_name || "")}" required ${fieldClass} />
        <label>Apellido</label>
        <input name="last_name" value="${escapeHtml(user.last_name || "")}" required ${fieldClass} />
        <label>Fecha de nacimiento</label>
        <input name="birth_date" type="date" value="${
          user.birth_date ? normalizeDateOnly(user.birth_date) : ""
        }" ${fieldClass} />
        <label>Calle</label>
        <input name="street" value="${escapeHtml(user.street || "")}" ${fieldClass} />
        <label>Número</label>
        <input name="house_number" value="${escapeHtml(user.house_number || "")}" ${fieldClass} />
        <label>Código postal</label>
        <input name="postal_code" value="${escapeHtml(user.postal_code || "")}" ${fieldClass} />
        <label>Ciudad</label>
        <input name="city" value="${escapeHtml(user.city || "")}" ${fieldClass} />
        <label>Email</label>
        <input name="email" type="email" value="${escapeHtml(user.email)}" required ${fieldClass} />
        <label>Rol</label>
        <select name="role" ${fieldClass}>
          <option value="user" ${user.role === "user" ? "selected" : ""}>user</option>
          <option value="admin" ${user.role === "admin" ? "selected" : ""}>admin</option>
          <option value="superuser" ${user.role === "superuser" ? "selected" : ""}>superuser</option>
        </select>
        <h2 style="margin-top:18px; font-size:14px;">Médico de cabecera</h2>
        <label>Nombre</label>
        <input name="doctor_first_name" value="${escapeHtml(doctor.first_name || "")}" ${fieldClass} />
        <label>Apellido</label>
        <input name="doctor_last_name" value="${escapeHtml(doctor.last_name || "")}" ${fieldClass} />
        <label>Email</label>
        <input name="doctor_email" type="email" value="${escapeHtml(doctor.email || "")}" ${fieldClass} />
        <label>Teléfono</label>
        <input name="doctor_phone" value="${escapeHtml(doctor.phone || "")}" ${fieldClass} />
        <label>Calle</label>
        <input name="doctor_street" value="${escapeHtml(doctor.street || "")}" ${fieldClass} />
        <label>Número de casa</label>
        <input name="doctor_house_number" value="${escapeHtml(doctor.house_number || "")}" ${fieldClass} />
        <label>Código postal</label>
        <input name="doctor_postal_code" value="${escapeHtml(doctor.postal_code || "")}" ${fieldClass} />
        <label>Ciudad</label>
        <input name="doctor_city" value="${escapeHtml(doctor.city || "")}" ${fieldClass} />
        <button class="btn primary" type="submit" style="width:100%; margin-top:18px;">Guardar cambios</button>
      </form>
    </div>
  `;
  res.send(renderShell(req, "Editar usuario", "patients", content));
});

app.post("/admin/user-save", requireRoleHtml(["admin", "superuser"]), async (req, res) => {
  const familyId = req.user.family_id;
  const {
    id,
    first_name,
    last_name,
    birth_date,
    street,
    house_number,
    postal_code,
    city,
    email,
    role,
    doctor_first_name,
    doctor_last_name,
    doctor_email,
    doctor_phone,
    doctor_street,
    doctor_house_number,
    doctor_postal_code,
    doctor_city,
  } = req.body || {};
  const safeRole = ["admin", "superuser", "user"].includes(role) ? role : "user";
  const finalName = buildUserName(null, first_name, last_name);
  await pool.query(
    `UPDATE users
     SET name = $1,
         first_name = $2,
         last_name = $3,
         birth_date = $4,
         street = $5,
         house_number = $6,
         postal_code = $7,
         city = $8,
         email = $9,
         role = $10
     WHERE id = $11 AND family_id = $12`,
    [
      finalName,
      first_name || null,
      last_name || null,
      birth_date || null,
      street || null,
      house_number || null,
      postal_code || null,
      city || null,
      email,
      safeRole,
      Number(id),
      familyId,
    ]
  );
  if (
    doctor_first_name ||
    doctor_last_name ||
    doctor_email ||
    doctor_phone ||
    doctor_street ||
    doctor_house_number ||
    doctor_postal_code ||
    doctor_city
  ) {
    await pool.query(
      `INSERT INTO doctors (family_id, user_id, first_name, last_name, email, phone, street, house_number, postal_code, city)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
       ON CONFLICT (family_id, user_id) DO UPDATE SET
         first_name = EXCLUDED.first_name,
         last_name = EXCLUDED.last_name,
         email = EXCLUDED.email,
         phone = EXCLUDED.phone,
         street = EXCLUDED.street,
         house_number = EXCLUDED.house_number,
         postal_code = EXCLUDED.postal_code,
         city = EXCLUDED.city`,
      [
        familyId,
        Number(id),
        doctor_first_name || null,
        doctor_last_name || null,
        doctor_email || null,
        doctor_phone || null,
        doctor_street || null,
        doctor_house_number || null,
        doctor_postal_code || null,
        doctor_city || null,
      ]
    );
  }
  res.redirect("/dashboard");
});

// =============================================================================
// ADMIN MEDS HTML (asignación por schedule)
// =============================================================================
app.get("/admin/meds/:id", requireRoleHtml(["admin", "superuser"]), async (req, res) => {
  const familyId = req.user.family_id;
  const userId = Number(req.params.id);
  const [userResult, medsResult, schedulesResult] = await Promise.all([
    pool.query(`SELECT id, name, email FROM users WHERE id = $1 AND family_id = $2`, [
      userId,
      familyId,
    ]),
    pool.query(
      `SELECT id, name, dosage FROM medicines WHERE family_id = $1 AND user_id = $2 ORDER BY name ASC`,
      [familyId, userId]
    ),
    pool.query(
      `SELECT s.id, s.dose_time, s.frequency, s.start_date, s.end_date, m.name AS medicine_name
       FROM schedules s
       JOIN medicines m ON m.id = s.medicine_id
       WHERE s.user_id = $1 AND m.family_id = $2
       ORDER BY s.id DESC`,
      [userId, familyId]
    ),
  ]);
  if (userResult.rows.length === 0) {
    return res.redirect("/dashboard");
  }
  const user = userResult.rows[0];
  const fieldStyle = 'class="form-control"';
  const content = `
    <div class="card">
      <h1>Medicinas de ${escapeHtml(user.name)}</h1>
      <p class="muted">${escapeHtml(user.email)}</p>
      <form method="POST" action="/admin/meds-add/${user.id}">
        <label>Medicina</label>
        <select name="medicine_id" required ${fieldStyle}>
          ${
            medsResult.rows.length
              ? medsResult.rows
                  .map(
                    (med) =>
                      `<option value="${med.id}">${escapeHtml(med.name)} · ${escapeHtml(
                        med.dosage
                      )}</option>`
                  )
                  .join("")
              : `<option value="">No hay medicinas</option>`
          }
        </select>
        <label>Hora</label>
        <input name="dose_time" type="time" value="08:00" required ${fieldStyle} />
        <label>Frecuencia</label>
        <input name="frequency" placeholder="Diario" required ${fieldStyle} />
        <label>Inicio (opcional)</label>
        <input name="start_date" type="date" ${fieldStyle} />
        <label>Fin (opcional)</label>
        <input name="end_date" type="date" ${fieldStyle} />
        <button class="btn primary" type="submit" style="width:100%; margin-top:18px;">Asignar medicina</button>
      </form>
    </div>
    <div class="card" style="margin-top:18px;">
      <h1>Programaciones activas</h1>
      <div style="margin-top:12px; overflow:auto;">
        <table class="table">
          <thead>
            <tr>
              <th>Medicina</th>
              <th>Hora</th>
              <th>Frecuencia</th>
              <th>Desde</th>
              <th>Hasta</th>
              <th>Acciones</th>
            </tr>
          </thead>
          <tbody>
            ${
              schedulesResult.rows.length
                ? schedulesResult.rows
                    .map(
                      (row) => `
            <tr>
              <td>${escapeHtml(row.medicine_name)}</td>
              <td>${escapeHtml(row.dose_time)}</td>
              <td>${escapeHtml(row.frequency)}</td>
              <td>${row.start_date ? escapeHtml(row.start_date) : "-"}</td>
              <td>${row.end_date ? escapeHtml(row.end_date) : "-"}</td>
              <td>
                <a href="/admin/meds-del/${row.id}/${user.id}">Eliminar</a>
              </td>
            </tr>`
                    )
                    .join("")
                : `<tr><td colspan="6" style="padding:12px; color:var(--muted);">Sin programaciones</td></tr>`
            }
          </tbody>
        </table>
      </div>
    </div>
  `;
  res.send(renderShell(req, "Medicinas del usuario", "meds", content));
});

app.post("/admin/meds-add/:id", requireRoleHtml(["admin", "superuser"]), async (req, res) => {
  const familyId = req.user.family_id;
  const userId = Number(req.params.id);
  const { medicine_id, dose_time, frequency, start_date, end_date } = req.body || {};
  const med = await pool.query(
    `SELECT id FROM medicines WHERE id = $1 AND family_id = $2 AND user_id = $3`,
    [Number(medicine_id), familyId, userId]
  );
  if (med.rows.length === 0) {
    return res.redirect(`/admin/meds/${userId}`);
  }
  await pool.query(
    `INSERT INTO schedules (medicine_id, user_id, dose_time, frequency, start_date, end_date)
     VALUES ($1, $2, $3, $4, $5, $6)`,
    [Number(medicine_id), userId, dose_time, frequency, start_date || null, end_date || null]
  );
  res.redirect(`/admin/meds/${userId}`);
});

app.get("/admin/meds-del/:mid/:uid", requireRoleHtml(["admin", "superuser"]), async (req, res) => {
  const familyId = req.user.family_id;
  const scheduleId = Number(req.params.mid);
  const userId = Number(req.params.uid);
  await pool.query(
    `DELETE FROM schedules s
     USING medicines m, users u
     WHERE s.id = $1 AND s.user_id = $2
       AND s.medicine_id = m.id AND u.id = s.user_id
       AND m.family_id = $3 AND u.family_id = $3`,
    [scheduleId, userId, familyId]
  );
  res.redirect(`/admin/meds/${userId}`);
});

// =============================================================================
// ADMIN MEDICINES CRUD (editable manual)
// =============================================================================
app.get("/admin/meds-list", requireRoleHtml(["admin", "superuser"]), async (req, res) => {
  const familyId = req.user.family_id;
  const query = (req.query?.q || "").trim();
  const userId = Number(req.query?.user_id || 0);
  const reviewOnly = req.query?.review === "1";
  const deletedCount = Number(req.query?.deleted || 0);
  const showDeleted = req.query?.reset === "1";
  const users = await pool.query(
    `SELECT id, name, email FROM users WHERE family_id = $1 ORDER BY name ASC`,
    [familyId]
  );
  const params = [familyId];
  let where = "WHERE family_id = $1";
  if (query) {
    params.push(`%${query}%`);
    where += " AND (name ILIKE $2 OR dosage ILIKE $2)";
  }
  if (userId) {
    params.push(userId);
    const idx = params.length;
    where += ` AND user_id = $${idx}`;
  }
  if (reviewOnly) {
    where += " AND (current_stock = 0 OR dosage = 'N/A' OR expiration_date IS NULL)";
  }
  const meds = await pool.query(
    `SELECT id, name, dosage, current_stock, expiration_date, end_date
     FROM medicines
     ${where}
     ORDER BY name ASC`,
    params
  );
  const content = `
    <div class="card">
      <h1>Medicamentos</h1>
      ${
        showDeleted
          ? `<p class="muted" style="margin:6px 0 10px;">Se borraron ${
              Number.isFinite(deletedCount) ? deletedCount : 0
            } medicamentos.</p>`
          : ""
      }
      <div class="actions" style="margin-top:12px;">
        <a class="btn primary" href="/admin/meds-new">➕ Nuevo medicamento</a>
        <a class="btn outline" href="/admin/meds-critical/pdf?user_id=${userId || ""}">📄 PDF críticos</a>
      </div>
      <form method="GET" action="/admin/meds-list" style="margin-top:16px; display:grid; gap:10px;">
        <input class="form-control" name="q" value="${escapeHtml(query)}" placeholder="Buscar por nombre o dosis" />
        <select class="form-control" name="user_id">
          <option value="">Todos los usuarios</option>
          ${
            users.rows
              .map(
                (u) =>
                  `<option value="${u.id}" ${u.id === userId ? "selected" : ""}>${escapeHtml(
                    u.name
                  )} · ${escapeHtml(u.email)}</option>`
              )
              .join("")
          }
        </select>
        <label style="font-size:12px; color:var(--muted);">
          <input type="checkbox" name="review" value="1" ${reviewOnly ? "checked" : ""} />
          Mostrar solo pendientes de revisión
        </label>
        <button class="btn outline" type="submit">🔎 Filtrar</button>
      </form>
      <div style="margin-top:12px; overflow:auto;">
        <table class="table">
          <thead>
            <tr>
              <th>Nombre</th>
              <th>Dosis</th>
              <th>Stock</th>
              <th>Caducidad</th>
              <th>Fin tratam.</th>
              <th>Acciones</th>
            </tr>
          </thead>
          <tbody>
            ${
              meds.rows.length
                ? meds.rows
                    .map(
                      (row) => `
            <tr>
              <td>${escapeHtml(row.name)}</td>
              <td>${escapeHtml(row.dosage)}</td>
              <td>${escapeHtml(row.current_stock)}</td>
              <td>${row.expiration_date ? escapeHtml(row.expiration_date) : "-"}</td>
              <td>${row.end_date ? escapeHtml(row.end_date) : "-"}</td>
              <td>
                <a href="/admin/meds-edit/${row.id}">Editar</a> ·
                <a href="/admin/meds-delete/${row.id}">Eliminar</a>
              </td>
            </tr>`
                    )
                    .join("")
                : `<tr><td colspan="5" style="padding:12px; color:var(--muted);">Sin medicamentos</td></tr>`
            }
          </tbody>
        </table>
      </div>
    </div>
  `;
  res.send(renderShell(req, "Medicamentos", "meds", content));
});

app.get("/admin/meds-new", requireRoleHtml(["admin", "superuser"]), async (_req, res) => {
  const users = await pool.query(
    `SELECT id, name, email FROM users WHERE family_id = $1 ORDER BY name ASC`,
    [_req.user.family_id]
  );
  const fieldClass = 'class="form-control"';
  const content = `
    <div class="card" style="max-width:520px; margin:0 auto;">
      <h1>Nuevo medicamento</h1>
      <form method="POST" action="/admin/meds-save">
        <label>Paciente</label>
        <select name="user_id" ${fieldClass}>
          ${
            users.rows.length
              ? users.rows
                  .map(
                    (u) =>
                      `<option value="${u.id}">${escapeHtml(u.name)} · ${escapeHtml(
                        u.email
                      )}</option>`
                  )
                  .join("")
              : `<option value="">Sin usuarios</option>`
          }
        </select>
        <label>Nombre</label>
        <input name="name" required ${fieldClass} />
        <label>Dosis</label>
        <input name="dosage" required ${fieldClass} />
        <label>Stock</label>
        <input name="current_stock" type="number" value="0" min="0" required ${fieldClass} />
        <label>Caducidad</label>
        <input name="expiration_date" type="date" ${fieldClass} />
        <label>Fecha límite de tratamiento</label>
        <input name="end_date" type="date" ${fieldClass} />
        <p style="font-size:11px; color:var(--muted); margin-top:2px;">
          Al llegar a esta fecha se envía mail al paciente y admin, y el medicamento deja de aparecer.
        </p>
        <button class="btn primary" type="submit" style="width:100%; margin-top:18px;">Guardar</button>
      </form>
    </div>
  `;
  res.send(renderShell(_req, "Nuevo medicamento", "meds", content));
});

app.get("/admin/meds-edit/:id", requireRoleHtml(["admin", "superuser"]), async (req, res) => {
  const familyId = req.user.family_id;
  const id = Number(req.params.id);
  const result = await pool.query(
    `SELECT id, name, dosage, current_stock, expiration_date, user_id, end_date
     FROM medicines
     WHERE id = $1 AND family_id = $2`,
    [id, familyId]
  );
  if (result.rows.length === 0) {
    return res.redirect("/admin/meds-list");
  }
  const med = result.rows[0];
  const fieldClass = 'class="form-control"';
  const content = `
    <div class="card" style="max-width:520px; margin:0 auto;">
      <h1>Editar medicamento</h1>
      <form method="POST" action="/admin/meds-save">
        <input type="hidden" name="id" value="${med.id}" />
        <label>ID de usuario (paciente)</label>
        <input name="user_id" value="${escapeHtml(med.user_id || "")}" required ${fieldClass} />
        <label>Nombre</label>
        <input name="name" value="${escapeHtml(med.name)}" required ${fieldClass} />
        <label>Dosis</label>
        <input name="dosage" value="${escapeHtml(med.dosage)}" required ${fieldClass} />
        <label>Stock</label>
        <input name="current_stock" type="number" min="0" value="${escapeHtml(med.current_stock)}" required ${fieldClass} />
        <label>Caducidad</label>
        <input name="expiration_date" type="date" value="${med.expiration_date || ""}" ${fieldClass} />
        <label>Fecha límite de tratamiento</label>
        <input name="end_date" type="date" value="${med.end_date || ""}" ${fieldClass} />
        <p style="font-size:11px; color:var(--muted); margin-top:2px;">
          Al llegar a esta fecha se envía mail al paciente y admin, y el medicamento deja de aparecer en la agenda.
        </p>
        <button class="btn primary" type="submit" style="width:100%; margin-top:18px;">Guardar cambios</button>
      </form>
    </div>
  `;
  res.send(renderShell(req, "Editar medicamento", "meds", content));
});

app.post("/admin/meds-save", requireRoleHtml(["admin", "superuser"]), async (req, res) => {
  const familyId = req.user.family_id;
  const { id, name, dosage, current_stock, expiration_date, user_id, end_date } = req.body || {};
  const userId = Number(user_id);
  if (!name || !dosage || !Number.isFinite(userId)) {
    return res.redirect("/admin/meds-list");
  }
  if (id) {
    // Si se cambia end_date, resetear la notificación
    await pool.query(
      `UPDATE medicines
       SET name = $1, dosage = $2, current_stock = $3, expiration_date = $4, user_id = $5,
           end_date = $6, end_date_notified = CASE WHEN end_date IS DISTINCT FROM $6 THEN FALSE ELSE end_date_notified END
       WHERE id = $7 AND family_id = $8`,
      [
        name,
        dosage,
        Number(current_stock || 0),
        expiration_date || null,
        userId,
        end_date || null,
        Number(id),
        familyId,
      ]
    );
    await logMedicineAudit(familyId, req.user.sub, Number(id), "update", "Edición manual");
  } else {
    const created = await pool.query(
      `INSERT INTO medicines (family_id, user_id, name, dosage, current_stock, expiration_date, end_date)
       VALUES ($1, $2, $3, $4, $5, $6, $7)
       RETURNING id`,
      [familyId, userId, name, dosage, Number(current_stock || 0), expiration_date || null, end_date || null]
    );
    await logMedicineAudit(
      familyId,
      req.user.sub,
      created.rows[0].id,
      "create",
      "Creación manual"
    );
  }
  res.redirect("/admin/meds-list");
});

app.get("/admin/meds-delete/:id", requireRoleHtml(["admin", "superuser"]), async (req, res) => {
  const familyId = req.user.family_id;
  const id = Number(req.params.id);
  await logMedicineAudit(familyId, req.user.sub, id, "delete", "Eliminación manual");
  await pool.query(`DELETE FROM medicines WHERE id = $1 AND family_id = $2`, [
    id,
    familyId,
  ]);
  res.redirect("/admin/meds-list");
});

// =============================================================================
// FAMILIES CRUD
// =============================================================================
app.post("/api/families", async (req, res) => {
  const { name } = req.body || {};
  if (!name) {
    return res.status(400).json({ error: "name es requerido" });
  }
  try {
    const result = await pool.query(
      `INSERT INTO families (name) VALUES ($1) RETURNING id, name, created_at`,
      [name]
    );
    res.status(201).json(result.rows[0]);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get("/api/families", requireRole(["superuser"]), async (_req, res) => {
  try {
    const result = await pool.query(
      `SELECT id, name, created_at FROM families ORDER BY id DESC`
    );
    res.json(result.rows);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get("/api/families/me", requireAuth, async (req, res) => {
  const familyId = req.user.family_id;
  try {
    const result = await pool.query(
      `SELECT id, name, created_at FROM families WHERE id = $1`,
      [familyId]
    );
    if (result.rows.length === 0) {
      return res.status(404).json({ error: "familia no encontrada" });
    }
    res.json(result.rows[0]);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.put("/api/families/:id", requireRole(["superuser"]), async (req, res) => {
  const id = Number(req.params.id);
  const { name } = req.body || {};
  if (!Number.isFinite(id) || !name) {
    return res.status(400).json({ error: "id y name son requeridos" });
  }
  try {
    const result = await pool.query(
      `UPDATE families SET name = $1 WHERE id = $2 RETURNING id, name, created_at`,
      [name, id]
    );
    if (result.rows.length === 0) {
      return res.status(404).json({ error: "familia no encontrada" });
    }
    res.json(result.rows[0]);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.delete("/api/families/:id", requireRole(["superuser"]), async (req, res) => {
  const id = Number(req.params.id);
  if (!Number.isFinite(id)) {
    return res.status(400).json({ error: "id inválido" });
  }
  try {
    const result = await pool.query(
      `DELETE FROM families WHERE id = $1 RETURNING id`,
      [id]
    );
    if (result.rows.length === 0) {
      return res.status(404).json({ error: "familia no encontrada" });
    }
    res.json({ ok: true });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// =============================================================================
// USERS CRUD
// =============================================================================
app.get("/api/users", requireRole(["admin", "superuser"]), async (req, res) => {
  const familyId = resolveFamilyScope(req);
  if (!familyId) {
    return res.status(400).json({ error: "family_id es requerido" });
  }
  try {
    const result = await pool.query(
      `SELECT id, family_id, name, first_name, last_name, street, house_number, postal_code, city, email, role, created_at
       FROM users
       WHERE family_id = $1
       ORDER BY id DESC`,
      [familyId]
    );
    res.json(result.rows);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post("/api/users", requireRole(["admin", "superuser"]), async (req, res) => {
  const familyId = resolveFamilyScope(req);
  const {
    name,
    first_name,
    last_name,
    street,
    house_number,
    postal_code,
    city,
    email,
    password,
    role,
  } = req.body || {};
  const safeRole = ["admin", "superuser", "user"].includes(role) ? role : "user";
  const finalName = buildUserName(name, first_name, last_name);
  if (!familyId || !finalName || !email || !password) {
    return res
      .status(400)
      .json({ error: "family_id, nombre, email y password son requeridos" });
  }
  try {
    const tempPassword = password || DEFAULT_TEMP_PASSWORD;
    const hashed = await bcrypt.hash(tempPassword, 10);
    const result = await pool.query(
      `INSERT INTO users (family_id, name, first_name, last_name, street, house_number, postal_code, city, email, password_hash, role)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
       RETURNING id, family_id, name, first_name, last_name, email, role, created_at, must_change_password`,
      [
        familyId,
        finalName,
        first_name || null,
        last_name || null,
        street || null,
        house_number || null,
        postal_code || null,
        city || null,
        email,
        hashed,
        safeRole,
      ]
    );
    await pool.query(
      `UPDATE users SET must_change_password = true WHERE id = $1`,
      [result.rows[0].id]
    );
    await sendWelcomeEmail(email, tempPassword);
    res.status(201).json(result.rows[0]);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.put("/api/users/:id", requireRole(["admin", "superuser"]), async (req, res) => {
  const familyId = resolveFamilyScope(req);
  const id = Number(req.params.id);
  const {
    name,
    first_name,
    last_name,
    street,
    house_number,
    postal_code,
    city,
    email,
    role,
  } = req.body || {};
  const safeRole = ["admin", "superuser", "user"].includes(role) ? role : null;
  const finalName = buildUserName(name, first_name, last_name);
  if (!familyId || !Number.isFinite(id) || !finalName || !email || !safeRole) {
    return res
      .status(400)
      .json({ error: "family_id, nombre, email y role son requeridos" });
  }
  try {
    const result = await pool.query(
      `UPDATE users
       SET name = $1,
           first_name = $2,
           last_name = $3,
           street = $4,
           house_number = $5,
           postal_code = $6,
           city = $7,
           email = $8,
           role = $9
       WHERE id = $10 AND family_id = $11
       RETURNING id, family_id, name, first_name, last_name, email, role, created_at`,
      [
        finalName,
        first_name || null,
        last_name || null,
        street || null,
        house_number || null,
        postal_code || null,
        city || null,
        email,
        safeRole,
        id,
        familyId,
      ]
    );
    if (result.rows.length === 0) {
      return res.status(404).json({ error: "usuario no encontrado" });
    }
    res.json(result.rows[0]);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.delete("/api/users/:id", requireRole(["admin", "superuser"]), async (req, res) => {
  const familyId = resolveFamilyScope(req);
  const id = Number(req.params.id);
  if (!familyId || !Number.isFinite(id)) {
    return res.status(400).json({ error: "family_id e id requeridos" });
  }
  try {
    const result = await pool.query(
      `DELETE FROM users WHERE id = $1 AND family_id = $2 RETURNING id`,
      [id, familyId]
    );
    if (result.rows.length === 0) {
      return res.status(404).json({ error: "usuario no encontrado" });
    }
    res.json({ ok: true });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// =============================================================================
// MEDICINES CRUD
// =============================================================================
app.get("/api/medicines", requireAuth, async (req, res) => {
  const familyId = getFamilyId(req);
  const userId = Number(req.query.user_id || req.query.userId || req.user?.sub);
  if (!familyId) {
    return res.status(400).json({ error: "family_id es requerido" });
  }
  if (!Number.isFinite(userId)) {
    return res.status(400).json({ error: "user_id es requerido" });
  }

  try {
    const result = await pool.query(
      `SELECT id, family_id, name, dosage, current_stock, expiration_date, created_at
       FROM medicines
       WHERE family_id = $1 AND user_id = $2
       ORDER BY name ASC`,
      [familyId, userId]
    );
    res.json(result.rows);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get("/api/medicines/:id", requireAuth, async (req, res) => {
  const familyId = getFamilyId(req);
  const userId = Number(req.query.user_id || req.query.userId || req.user?.sub);
  const id = Number(req.params.id);
  if (!familyId) {
    return res.status(400).json({ error: "family_id es requerido" });
  }
  if (!Number.isFinite(userId)) {
    return res.status(400).json({ error: "user_id es requerido" });
  }
  if (!Number.isFinite(id)) {
    return res.status(400).json({ error: "id inválido" });
  }

  try {
    const result = await pool.query(
      `SELECT id, family_id, name, dosage, current_stock, expiration_date, created_at
       FROM medicines
       WHERE id = $1 AND family_id = $2 AND user_id = $3`,
      [id, familyId, userId]
    );
    if (result.rows.length === 0) {
      return res.status(404).json({ error: "medicamento no encontrado" });
    }
    res.json(result.rows[0]);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post("/api/medicines", requireRole(["admin", "superuser"]), async (req, res) => {
  const familyId = getFamilyId(req);
  const { name, dosage, current_stock, expiration_date, user_id } = req.body || {};
  const userId = Number(user_id);

  if (!familyId || !name || !dosage || !Number.isFinite(userId)) {
    return res
      .status(400)
      .json({ error: "family_id, user_id, name y dosage son requeridos" });
  }

  try {
    const result = await pool.query(
      `INSERT INTO medicines (family_id, user_id, name, dosage, current_stock, expiration_date)
       VALUES ($1, $2, $3, $4, $5, $6)
       RETURNING id, family_id, user_id, name, dosage, current_stock, expiration_date, created_at`,
      [
        familyId,
        userId,
        name,
        dosage,
        Number(current_stock || 0),
        expiration_date || null,
      ]
    );
    res.status(201).json(result.rows[0]);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.put("/api/medicines/:id", requireRole(["admin", "superuser"]), async (req, res) => {
  const familyId = getFamilyId(req);
  const id = Number(req.params.id);
  const { name, dosage, current_stock, expiration_date, user_id } = req.body || {};
  const userId = Number(user_id);

  if (!familyId || !name || !dosage || !Number.isFinite(userId)) {
    return res
      .status(400)
      .json({ error: "family_id, user_id, name y dosage son requeridos" });
  }
  if (!Number.isFinite(id)) {
    return res.status(400).json({ error: "id inválido" });
  }

  try {
    const result = await pool.query(
      `UPDATE medicines
       SET name = $1,
           dosage = $2,
           current_stock = $3,
           expiration_date = $4,
           user_id = $5
       WHERE id = $6 AND family_id = $7
       RETURNING id, family_id, user_id, name, dosage, current_stock, expiration_date, created_at`,
      [
        name,
        dosage,
        Number(current_stock || 0),
        expiration_date || null,
        userId,
        id,
        familyId,
      ]
    );
    if (result.rows.length === 0) {
      return res.status(404).json({ error: "medicamento no encontrado" });
    }
    res.json(result.rows[0]);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.delete("/api/medicines/:id", requireRole(["admin", "superuser"]), async (req, res) => {
  const familyId = getFamilyId(req);
  const id = Number(req.params.id);
  const userId = Number(req.query.user_id || req.query.userId || req.body?.user_id);
  if (!familyId) {
    return res.status(400).json({ error: "family_id es requerido" });
  }
  if (!Number.isFinite(userId)) {
    return res.status(400).json({ error: "user_id es requerido" });
  }
  if (!Number.isFinite(id)) {
    return res.status(400).json({ error: "id inválido" });
  }

  try {
    const result = await pool.query(
      `DELETE FROM medicines
       WHERE id = $1 AND family_id = $2 AND user_id = $3
       RETURNING id`,
      [id, familyId, userId]
    );
    if (result.rows.length === 0) {
      return res.status(404).json({ error: "medicamento no encontrado" });
    }
    res.json({ ok: true });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// =============================================================================
// SCHEDULES CRUD
// =============================================================================
app.get("/api/schedules", requireAuth, async (req, res) => {
  const familyId = getFamilyId(req);
  if (!familyId) {
    return res.status(400).json({ error: "family_id es requerido" });
  }
  try {
    const result = await pool.query(
      `SELECT s.id, s.medicine_id, s.user_id, s.dose_time, s.frequency, s.start_date, s.end_date, s.created_at
       FROM schedules s
       JOIN medicines m ON m.id = s.medicine_id
       JOIN users u ON u.id = s.user_id
       WHERE m.family_id = $1 AND u.family_id = $1 AND m.user_id = s.user_id
       ORDER BY s.id DESC`,
      [familyId]
    );
    res.json(result.rows);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post("/api/schedules", requireRole(["admin", "superuser"]), async (req, res) => {
  const familyId = getFamilyId(req);
  const { medicine_id, user_id, dose_time, frequency, start_date, end_date } = req.body || {};
  if (!familyId || !medicine_id || !user_id || !dose_time || !frequency) {
    return res.status(400).json({
      error: "family_id, medicine_id, user_id, dose_time y frequency son requeridos",
    });
  }
  try {
    const med = await pool.query(
      `SELECT id FROM medicines WHERE id = $1 AND family_id = $2 AND user_id = $3`,
      [Number(medicine_id), familyId, Number(user_id)]
    );
    if (med.rows.length === 0) {
      return res.status(404).json({ error: "medicamento no encontrado" });
    }
    const user = await pool.query(
      `SELECT id FROM users WHERE id = $1 AND family_id = $2`,
      [Number(user_id), familyId]
    );
    if (user.rows.length === 0) {
      return res.status(404).json({ error: "usuario no encontrado" });
    }

    const result = await pool.query(
      `INSERT INTO schedules (medicine_id, user_id, dose_time, frequency, start_date, end_date)
       VALUES ($1, $2, $3, $4, $5, $6)
       RETURNING id, medicine_id, user_id, dose_time, frequency, start_date, end_date, created_at`,
      [Number(medicine_id), Number(user_id), dose_time, frequency, start_date || null, end_date || null]
    );
    res.status(201).json(result.rows[0]);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.put("/api/schedules/:id", requireRole(["admin", "superuser"]), async (req, res) => {
  const familyId = getFamilyId(req);
  const id = Number(req.params.id);
  const { medicine_id, user_id, dose_time, frequency, start_date, end_date } = req.body || {};
  if (!familyId || !Number.isFinite(id) || !medicine_id || !user_id || !dose_time || !frequency) {
    return res.status(400).json({
      error: "family_id, medicine_id, user_id, dose_time y frequency son requeridos",
    });
  }
  try {
    const schedule = await pool.query(
      `SELECT s.id
       FROM schedules s
       JOIN medicines m ON m.id = s.medicine_id
       JOIN users u ON u.id = s.user_id
       WHERE s.id = $1 AND m.family_id = $2 AND u.family_id = $2`,
      [id, familyId]
    );
    if (schedule.rows.length === 0) {
      return res.status(404).json({ error: "programación no encontrada" });
    }

    const result = await pool.query(
      `UPDATE schedules
       SET medicine_id = $1, user_id = $2, dose_time = $3, frequency = $4,
           start_date = $5, end_date = $6
       WHERE id = $7
       RETURNING id, medicine_id, user_id, dose_time, frequency, start_date, end_date, created_at`,
      [Number(medicine_id), Number(user_id), dose_time, frequency, start_date || null, end_date || null, id]
    );
    res.json(result.rows[0]);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.delete("/api/schedules/:id", requireRole(["admin", "superuser"]), async (req, res) => {
  const familyId = getFamilyId(req);
  const id = Number(req.params.id);
  if (!familyId || !Number.isFinite(id)) {
    return res.status(400).json({ error: "family_id e id requeridos" });
  }
  try {
    const result = await pool.query(
      `DELETE FROM schedules s
       USING medicines m, users u
       WHERE s.id = $1 AND s.medicine_id = m.id AND s.user_id = u.id
         AND m.family_id = $2 AND u.family_id = $2
       RETURNING s.id`,
      [id, familyId]
    );
    if (result.rows.length === 0) {
      return res.status(404).json({ error: "programación no encontrada" });
    }
    res.json({ ok: true });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// =============================================================================
// DOSE LOGS (registro de tomas)
// =============================================================================
app.get("/api/dose-logs", requireAuth, async (req, res) => {
  const scheduleId = Number(req.query.schedule_id || req.query.scheduleId);
  const familyId = getFamilyId(req);
  if (!Number.isFinite(scheduleId)) {
    return res.status(400).json({ error: "schedule_id es requerido" });
  }
  if (!familyId) {
    return res.status(400).json({ error: "family_id es requerido" });
  }

  try {
    const result = await pool.query(
      `SELECT id, schedule_id, taken_at, status
       FROM dose_logs dl
       JOIN schedules s ON s.id = dl.schedule_id
       JOIN medicines m ON m.id = s.medicine_id
       JOIN users u ON u.id = s.user_id
       WHERE dl.schedule_id = $1 AND m.family_id = $2 AND u.family_id = $2
       ORDER BY taken_at DESC`,
      [scheduleId, familyId]
    );
    res.json(result.rows);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post("/api/dose-logs", requireAuth, async (req, res) => {
  const { schedule_id, taken_at, status } = req.body || {};
  const familyId = getFamilyId(req);
  if (!schedule_id || !status) {
    return res
      .status(400)
      .json({ error: "schedule_id y status son requeridos" });
  }
  if (!familyId) {
    return res.status(400).json({ error: "family_id es requerido" });
  }

  try {
    const schedule = await pool.query(
      `SELECT s.id
       FROM schedules s
       JOIN medicines m ON m.id = s.medicine_id
       JOIN users u ON u.id = s.user_id
       WHERE s.id = $1 AND m.family_id = $2 AND u.family_id = $2`,
      [Number(schedule_id), familyId]
    );
    if (schedule.rows.length === 0) {
      return res.status(404).json({ error: "programación no encontrada" });
    }
    const result = await pool.query(
      `INSERT INTO dose_logs (schedule_id, taken_at, status)
       VALUES ($1, COALESCE($2, NOW()), $3)
       RETURNING id, schedule_id, taken_at, status`,
      [Number(schedule_id), taken_at || null, status]
    );
    res.status(201).json(result.rows[0]);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// =============================================================================
// MOBILE APP SUPPORT (meds by date + toggle)
// =============================================================================
app.get("/api/meds-by-date", requireAuth, async (req, res) => {
  const familyId = getFamilyId(req);
  const userId = Number(req.query.user_id || req.query.userId);
  const date = req.query.date;
  if (!familyId || !Number.isFinite(userId) || !date) {
    return res
      .status(400)
      .json({ error: "family_id, user_id y date son requeridos" });
  }

  try {
    await pool.query(
      `INSERT INTO schedules (medicine_id, user_id, dose_time, frequency, days_of_week)
       SELECT m.id, m.user_id, '08:00', '1', '1234567'
       FROM medicines m
       WHERE m.family_id = $1 AND m.user_id = $2
         AND COALESCE(m.stock_depleted, FALSE) = FALSE
         AND NOT EXISTS (
           SELECT 1 FROM schedules s
           WHERE s.medicine_id = m.id AND s.user_id = m.user_id
         )`,
      [familyId, userId]
    );
    const dayToken = (() => {
      const day = new Date(date).getDay();
      const map = [7, 1, 2, 3, 4, 5, 6];
      return String(map[day]);
    })();
    const result = await pool.query(
      `SELECT
       s.id AS schedule_id,
       s.dose_time,
       s.frequency,
       m.name AS medicine_name,
       m.dosage,
       m.current_stock,
       s.days_of_week,
       dcr.requested_dosage,
       dcr.effective_date,
        COALESCE(
          (
            SELECT dl.status
            FROM dose_logs dl
            WHERE dl.schedule_id = s.id
              AND dl.taken_at::date = $3::date
            ORDER BY dl.taken_at DESC
            LIMIT 1
          ),
          'missed'
        ) AS last_status
       FROM schedules s
       JOIN medicines m ON m.id = s.medicine_id
       JOIN users u ON u.id = s.user_id
       LEFT JOIN LATERAL (
         SELECT requested_dosage, effective_date
         FROM dose_change_requests
         WHERE schedule_id = s.id AND status = 'pending'
         ORDER BY created_at DESC
         LIMIT 1
       ) dcr ON true
       WHERE s.user_id = $1 AND m.family_id = $2 AND u.family_id = $2
         AND m.user_id = s.user_id
         AND POSITION($4 IN COALESCE(s.days_of_week, '1234567')) > 0
         AND (s.start_date IS NULL OR $3::date >= s.start_date)
         AND (s.end_date IS NULL OR $3::date <= s.end_date)
         AND (m.end_date IS NULL OR $3::date <= m.end_date)
         AND COALESCE(m.stock_depleted, FALSE) = FALSE
       ORDER BY s.dose_time ASC`,
      [userId, familyId, date, dayToken]
    );

    const data = result.rows.map((row) => ({
      id: row.schedule_id,
      nombre: row.medicine_name,
      dosis: row.dosage,
      frecuencia: row.frequency,
      hora: row.dose_time,
      stock: row.current_stock,
      estado: row.last_status === "taken" ? "tomado" : "pendiente",
      pending_dose: row.requested_dosage ? true : false,
      requested_dosage: row.requested_dosage || null,
      effective_date: row.effective_date || null,
    }));

    res.json(data);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post("/api/meds-toggle", requireAuth, async (req, res) => {
  const { schedule_id, status, family_id, date } = req.body || {};
  const familyId = Number(family_id || getFamilyId(req));
  const scheduleId = Number(schedule_id);
  const safeStatus = status === "tomado" ? "tomado" : "pendiente";
  const day = date || new Date().toISOString().slice(0, 10);
  const today = new Date().toISOString().slice(0, 10);

  if (!familyId || !Number.isFinite(scheduleId)) {
    return res.status(400).json({ error: "family_id y schedule_id son requeridos" });
  }
  if (day > today) {
    return res.status(400).json({ error: "no se puede confirmar tomas futuras" });
  }
  if (safeStatus !== "tomado") {
    return res.status(400).json({ error: "no se permite deshacer la toma" });
  }

  try {
    await pool.query("BEGIN");
    const schedule = await pool.query(
      `SELECT s.id, s.medicine_id, m.current_stock, m.user_id
       FROM schedules s
       JOIN medicines m ON m.id = s.medicine_id
       JOIN users u ON u.id = s.user_id
       WHERE s.id = $1 AND m.family_id = $2 AND u.family_id = $2 AND m.user_id = s.user_id`,
      [scheduleId, familyId]
    );
    if (schedule.rows.length === 0) {
      await pool.query("ROLLBACK");
      return res.status(404).json({ error: "programación no encontrada" });
    }

    const lastLog = await pool.query(
      `SELECT status
       FROM dose_logs
       WHERE schedule_id = $1 AND taken_at::date = $2::date
       ORDER BY taken_at DESC
       LIMIT 1`,
      [scheduleId, day]
    );
    const lastStatus = lastLog.rows[0]?.status || "missed";
    const desiredStatus = "taken";

    if (lastStatus === desiredStatus) {
      await pool.query("ROLLBACK");
      return res.json({ ok: true, status: safeStatus, stock: schedule.rows[0].current_stock });
    }

    const previousStock = schedule.rows[0].current_stock;
    if (lastStatus === "taken") {
      await pool.query("ROLLBACK");
      return res.json({ ok: true, status: "tomado", stock: previousStock });
    }
    const newStock = Math.max(0, previousStock - 1);

    await pool.query(
      `UPDATE medicines SET current_stock = $1 WHERE id = $2`,
      [newStock, schedule.rows[0].medicine_id]
    );

    await pool.query(
      `INSERT INTO dose_logs (schedule_id, taken_at, status)
       VALUES ($1, ($2)::date + CURRENT_TIME, $3)`,
      [scheduleId, day, desiredStatus]
    );

    await pool.query("COMMIT");
    if (previousStock > 10 && newStock <= 10) {
      const medRow = await pool.query(
        `SELECT name, dosage FROM medicines WHERE id = $1`,
        [schedule.rows[0].medicine_id]
      );
      const userRow = await pool.query(
        `SELECT id, name, email FROM users WHERE id = $1`,
        [req.user.sub]
      );
      const doctorRow = await pool.query(
        `SELECT email FROM doctors WHERE family_id = $1 AND user_id = $2`,
        [familyId, req.user.sub]
      );
      const medName = medRow.rows[0]?.name || "Medicamento";
      const patientName = userRow.rows[0]?.name || "Paciente";
      const emailSubject = "Stock bajo de medicamento";
      const emailBody = `<p>${escapeHtml(
        patientName
      )} tiene stock bajo de <strong>${escapeHtml(
        medName
      )}</strong> (${newStock} unidades).</p>`;
      await pool.query(
        `INSERT INTO alerts (family_id, user_id, type, level, message, med_name, med_dosage, alert_date)
         VALUES ($1, $2, 'low_stock', 'warning', $3, $4, $5, $6)`,
        [
          familyId,
          req.user.sub,
          `Stock bajo: ${medName} (${newStock})`,
          medName,
          medRow.rows[0]?.dosage || "N/A",
          new Date().toISOString().slice(0, 10),
        ]
      );
      await sendUserEmail(userRow.rows[0]?.email, emailSubject, emailBody);
      if (doctorRow.rows[0]?.email) {
        await sendUserEmail(doctorRow.rows[0]?.email, emailSubject, emailBody);
      }
      if (ADMIN_EMAIL) {
        await sendAdminAlertEmail(emailSubject, emailBody);
      }
    }
    res.json({ ok: true, status: safeStatus, stock: newStock });
  } catch (error) {
    await pool.query("ROLLBACK");
    res.status(500).json({ error: error.message });
  }
});

app.post("/api/dose-change-requests", requireAuth, async (req, res) => {
  const familyId = getFamilyId(req);
  const scheduleId = Number(req.body?.schedule_id);
  const requestedDosage = String(req.body?.new_dosage || "").trim();
  const effectiveDate = normalizeDateOnly(req.body?.effective_date);
  if (!familyId || !Number.isFinite(scheduleId) || !requestedDosage) {
    return res.status(400).json({ error: "family_id, schedule_id y new_dosage son requeridos" });
  }
  try {
    const sched = await pool.query(
      `SELECT s.id, s.user_id, m.id AS medicine_id, m.dosage
       FROM schedules s
       JOIN medicines m ON m.id = s.medicine_id
       WHERE s.id = $1 AND m.family_id = $2`,
      [scheduleId, familyId]
    );
    if (!sched.rows.length) {
      return res.status(404).json({ error: "programación no encontrada" });
    }
    const row = sched.rows[0];
    if (Number(row.user_id) !== Number(req.user.sub)) {
      return res.status(403).json({ error: "sin permiso" });
    }
    await pool.query(
      `INSERT INTO dose_change_requests
       (family_id, user_id, schedule_id, medicine_id, current_dosage, requested_dosage, effective_date)
       VALUES ($1, $2, $3, $4, $5, $6, $7)`,
      [
        familyId,
        row.user_id,
        scheduleId,
        row.medicine_id,
        row.dosage || null,
        requestedDosage,
        effectiveDate || null,
      ]
    );
    res.json({ ok: true });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// =============================================================================
// IMPORT API
// =============================================================================
app.post("/api/import-meds", requireRole(["admin", "superuser"]), async (req, res) => {
  const familyId = getFamilyId(req);
  const { file_path, user_id, use_ocr, skip_name_check } = req.body || {};
  const userId = Number(user_id);
  if (!familyId || !file_path || !Number.isFinite(userId)) {
    return res
      .status(400)
      .json({ error: "family_id, file_path y user_id son requeridos" });
  }
  try {
    const result = await importMedsFromPdf(
      file_path,
      familyId,
      userId,
      !!use_ocr,
      skip_name_check === "1"
    );
    res.json({ ok: true, ...result });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.delete("/api/meds-reset", requireRole(["admin", "superuser"]), async (req, res) => {
  const familyId = getFamilyId(req);
  const userId = Number(req.body?.user_id);
  const confirm = String(req.body?.confirm || "").trim();
  if (!familyId) {
    return res.status(400).json({ error: "family_id es requerido" });
  }
  if (confirm !== "RESET") {
    return res.status(400).json({ error: "confirm debe ser RESET" });
  }
  if (!Number.isFinite(userId)) {
    return res.status(400).json({ error: "user_id es requerido" });
  }
  const snapshotResult = await pool.query(
    `SELECT id, name, dosage, current_stock, expiration_date, import_batch_id
     FROM medicines
     WHERE family_id = $1 AND user_id = $2
     ORDER BY id`,
    [familyId, userId]
  );
  const snapshot = snapshotResult.rows || [];
  await pool.query(
    `DELETE FROM dose_logs
     WHERE schedule_id IN (SELECT id FROM schedules WHERE user_id = $1)`,
    [userId]
  );
  await pool.query(`DELETE FROM schedules WHERE user_id = $1`, [userId]);
  await pool.query(`DELETE FROM medicines WHERE family_id = $1 AND user_id = $2`, [
    familyId,
    userId,
  ]);
  await pool.query(
    `INSERT INTO deletion_logs (family_id, user_id, deleted_count, snapshot)
     VALUES ($1, $2, $3, $4)`,
    [familyId, userId, snapshot.length, JSON.stringify(snapshot)]
  );
  await pool.query(`DELETE FROM alerts WHERE family_id = $1 AND user_id = $2`, [
    familyId,
    userId,
  ]);
  res.json({ ok: true });
});

// =============================================================================
// ALERTS API
// =============================================================================
app.get("/api/alerts", requireAuth, async (req, res) => {
  const familyId = getFamilyId(req);
  if (!familyId) {
    return res.status(400).json({ error: "family_id es requerido" });
  }
  try {
    const result = await pool.query(
      `SELECT id, type, level, message, created_at, med_name, med_dosage, dose_time, alert_date, schedule_id
       FROM alerts
       WHERE family_id = $1
         AND (user_id = $2 OR user_id IS NULL)
         AND read_at IS NULL
       ORDER BY created_at DESC`,
      [familyId, req.user.sub]
    );
    res.json(result.rows);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post("/api/alerts/read", requireAuth, async (req, res) => {
  const { alert_id } = req.body || {};
  const familyId = getFamilyId(req);
  if (!alert_id || !familyId) {
    return res.status(400).json({ error: "alert_id y family_id requeridos" });
  }
  await pool.query(
    `UPDATE alerts SET read_at = NOW()
     WHERE id = $1 AND family_id = $2 AND (user_id = $3 OR user_id IS NULL)`,
    [Number(alert_id), familyId, req.user.sub]
  );
  res.json({ ok: true });
});

// =============================================================================
// DOCTOR (info del médico de cabecera)
// =============================================================================
app.get("/api/doctor", requireAuth, async (req, res) => {
  const familyId = getFamilyId(req);
  const userId = Number(req.query.user_id || req.query.userId || req.user?.sub);
  if (!familyId || !Number.isFinite(userId)) {
    return res.status(400).json({ error: "family_id y user_id son requeridos" });
  }
  const result = await pool.query(
    `SELECT first_name, last_name, email, phone, street, house_number, postal_code, city
     FROM doctors
     WHERE family_id = $1 AND user_id = $2`,
    [familyId, userId]
  );
  if (result.rows.length === 0) {
    return res.status(404).json({ error: "médico no encontrado" });
  }
  res.json(result.rows[0]);
});

// =============================================================================
// PDF CRÍTICOS
// =============================================================================
app.get("/admin/meds-critical/pdf", requireRoleHtml(["admin", "superuser"]), async (req, res) => {
  const familyId = req.user.family_id;
  const userId = Number(req.query.user_id || req.query.userId || req.user.sub);
  if (!Number.isFinite(userId)) {
    return res.redirect("/dashboard");
  }
  const patient = await pool.query(
    `SELECT name FROM users WHERE id = $1 AND family_id = $2`,
    [userId, familyId]
  );
  const meds = await pool.query(
    `SELECT name, dosage, current_stock
     FROM medicines
     WHERE family_id = $1 AND user_id = $2 AND current_stock <= 10
     ORDER BY current_stock ASC, name ASC`,
    [familyId, userId]
  );

  res.setHeader("Content-Type", "application/pdf");
  res.setHeader(
    "Content-Disposition",
    `attachment; filename="medicamentos_criticos_${userId}.pdf"`
  );

  const doc = new PDFDocument({ margin: 40 });
  doc.pipe(res);
  doc.fontSize(18).text("Medicamentos críticos", { align: "left" });
  doc.moveDown(0.5);
  doc.fontSize(12).text(`Paciente: ${patient.rows[0]?.name || "Paciente"}`);
  doc.text(`Fecha: ${formatDateOnlyDisplay(new Date())}`);
  doc.moveDown();
  if (!meds.rows.length) {
    doc.text("Sin medicamentos críticos (stock > 10).");
  } else {
    meds.rows.forEach((med) => {
      doc
        .fontSize(12)
        .text(`${med.name} · ${med.dosage || "N/A"} · Stock ${med.current_stock}`);
    });
  }
  doc.end();
});

// =============================================================================
// PUSH NOTIFICATIONS
// =============================================================================
app.get("/api/push/vapid", (_req, res) => {
  res.json({ publicKey: pushKeys.publicKey });
});

app.post("/api/push/subscribe", requireAuth, async (req, res) => {
  const familyId = getFamilyId(req);
  const sub = req.body || {};
  if (!familyId || !sub.endpoint || !sub.keys?.p256dh || !sub.keys?.auth) {
    return res.status(400).json({ error: "subscription inválida" });
  }
  await pool.query(
    `INSERT INTO push_subscriptions (user_id, family_id, endpoint, p256dh, auth)
     VALUES ($1, $2, $3, $4, $5)
     ON CONFLICT (user_id, endpoint) DO NOTHING`,
    [req.user.sub, familyId, sub.endpoint, sub.keys.p256dh, sub.keys.auth]
  );
  res.json({ ok: true });
});

app.post("/api/push/test", requireAuth, async (req, res) => {
  const familyId = getFamilyId(req);
  await sendPushToFamily(familyId, {
    title: "Recordatorio",
    body: "Tienes tomas pendientes.",
  });
  res.json({ ok: true });
});

// =============================================================================
// BILLING / STRIPE ENDPOINTS
// =============================================================================

// Estado de suscripción de la familia
app.get("/api/billing/status", requireAuth, async (req, res) => {
  const familyId = Number(getFamilyId(req));
  if (!familyId) return res.status(400).json({ error: "family_id requerido" });
  try {
    const result = await pool.query(
      `SELECT subscription_status, subscription_start, subscription_end, trial_ends_at, stripe_customer_id, max_medicines
       FROM families WHERE id = $1`,
      [familyId]
    );
    if (!result.rows.length) return res.status(404).json({ error: "Familia no encontrada" });
    const fam = result.rows[0];
    const now = new Date();
    const trialActive = fam.subscription_status === "trial" && fam.trial_ends_at && new Date(fam.trial_ends_at) > now;
    const subActive = fam.subscription_status === "active";
    const daysLeft = trialActive ? Math.ceil((new Date(fam.trial_ends_at) - now) / (1000 * 60 * 60 * 24)) : 0;
    // Contar medicamentos actuales
    const medsCount = await pool.query(
      `SELECT COUNT(*) FROM medicines WHERE family_id = $1`, [familyId]
    );
    const currentMeds = Number(medsCount.rows[0]?.count || 0);
    const maxMeds = fam.subscription_status === "trial" ? (fam.max_medicines || 5) : null;

    res.json({
      status: fam.subscription_status,
      active: subActive || trialActive,
      trial: trialActive,
      trial_expired: fam.subscription_status === "trial" && !trialActive,
      days_left: trialActive ? daysLeft : 0,
      trial_ends_at: fam.trial_ends_at,
      subscription_start: fam.subscription_start,
      subscription_end: fam.subscription_end,
      has_customer: !!fam.stripe_customer_id,
      stripe_configured: !!stripe,
      max_medicines: maxMeds,
      current_medicines: currentMeds,
    });
  } catch (err) {
    console.error("[BILLING STATUS]", err.message);
    res.status(500).json({ error: "Error al consultar estado" });
  }
});

// Crear sesión de Stripe Checkout
app.post("/api/billing/create-checkout", requireAuth, async (req, res) => {
  if (!stripe) {
    return res.status(400).json({ error: "Stripe no configurado. Contacte al administrador." });
  }
  const plan = req.body?.plan || "monthly";
  const priceId = plan === "yearly" ? STRIPE_PRICE_ID_YEARLY : STRIPE_PRICE_ID;
  if (!priceId) {
    return res.status(400).json({ error: `Precio de Stripe no configurado para plan ${plan}. Contacte al administrador.` });
  }
  const familyId = Number(getFamilyId(req));
  if (!familyId) return res.status(400).json({ error: "family_id requerido" });

  try {
    const fam = await pool.query(`SELECT stripe_customer_id, name FROM families WHERE id = $1`, [familyId]);
    if (!fam.rows.length) return res.status(404).json({ error: "Familia no encontrada" });

    let customerId = fam.rows[0].stripe_customer_id;
    if (!customerId) {
      const customer = await stripe.customers.create({
        metadata: { family_id: String(familyId) },
        name: fam.rows[0].name || `Familia ${familyId}`,
        email: req.user.email || undefined,
      });
      customerId = customer.id;
      await pool.query(`UPDATE families SET stripe_customer_id = $1 WHERE id = $2`, [customerId, familyId]);
    }

    const session = await stripe.checkout.sessions.create({
      customer: customerId,
      payment_method_types: ["card"],
      mode: "subscription",
      line_items: [{ price: priceId, quantity: 1 }],
      success_url: `${FRONTEND_URL}/billing?success=1`,
      cancel_url: `${FRONTEND_URL}/billing?cancelled=1`,
      metadata: { family_id: String(familyId), plan },
      subscription_data: { metadata: { family_id: String(familyId) } },
    });

    console.log(`[STRIPE] Checkout ${plan} creado para familia ${familyId}: ${session.id}`);
    res.json({ url: session.url, session_id: session.id });
  } catch (err) {
    console.error("[STRIPE CHECKOUT]", err.message);
    res.status(500).json({ error: `Error al crear sesión: ${err.message}` });
  }
});

// Portal de clientes (para gestionar/cancelar suscripción)
app.post("/api/billing/portal", requireAuth, async (req, res) => {
  if (!stripe) return res.status(400).json({ error: "Stripe no configurado" });
  const familyId = Number(getFamilyId(req));
  if (!familyId) return res.status(400).json({ error: "family_id requerido" });

  try {
    const fam = await pool.query(`SELECT stripe_customer_id FROM families WHERE id = $1`, [familyId]);
    if (!fam.rows[0]?.stripe_customer_id) {
      return res.status(400).json({ error: "No hay suscripción activa" });
    }
    const session = await stripe.billingPortal.sessions.create({
      customer: fam.rows[0].stripe_customer_id,
      return_url: `${FRONTEND_URL}/billing`,
    });
    res.json({ url: session.url });
  } catch (err) {
    console.error("[STRIPE PORTAL]", err.message);
    res.status(500).json({ error: "Error al crear portal" });
  }
});

// Admin: sincronizar suscripción con Stripe
app.post("/admin/billing/sync/:familyId", requireRoleHtml(["admin", "superuser"]), async (req, res) => {
  const familyId = Number(req.params.familyId);
  if (!stripe) return res.redirect("/admin/billing?msg=Stripe+no+configurado");
  try {
    const fam = await pool.query(`SELECT stripe_customer_id FROM families WHERE id = $1`, [familyId]);
    if (!fam.rows[0]?.stripe_customer_id) return res.redirect("/admin/billing?msg=Sin+customer+Stripe");

    const subs = await stripe.subscriptions.list({ customer: fam.rows[0].stripe_customer_id, limit: 1 });
    if (subs.data.length > 0) {
      const sub = subs.data[0];
      const status = (sub.status === "active" || sub.status === "trialing") ? "active" : sub.status === "past_due" ? "past_due" : "cancelled";
      const endDate = sub.current_period_end ? new Date(sub.current_period_end * 1000) : null;
      const startDate = sub.current_period_start ? new Date(sub.current_period_start * 1000) : null;
      await pool.query(
        `UPDATE families SET subscription_status = $1, subscription_start = $2, subscription_end = $3, stripe_subscription_id = $4 WHERE id = $5`,
        [status, startDate, endDate, sub.id, familyId]
      );
      console.log(`[ADMIN SYNC] Familia ${familyId} sincronizada: ${status} hasta ${endDate}`);
      return res.redirect(`/admin/billing?msg=Familia+${familyId}+sincronizada:+${status}`);
    } else {
      return res.redirect(`/admin/billing?msg=Familia+${familyId}:+sin+suscripción+en+Stripe`);
    }
  } catch (err) {
    console.error("[ADMIN SYNC]", err.message);
    return res.redirect(`/admin/billing?msg=Error:+${encodeURIComponent(err.message)}`);
  }
});

// Admin: ver billing de todas las familias
app.get("/admin/billing", requireRoleHtml(["admin", "superuser"]), async (req, res) => {
  try {
    const families = await pool.query(
      `SELECT f.id, f.name, f.subscription_status, f.trial_ends_at, f.subscription_start, f.subscription_end,
              f.stripe_customer_id, f.stripe_subscription_id, f.max_medicines, f.trial_email_sent,
              COUNT(u.id) AS user_count,
              (SELECT COUNT(*) FROM medicines m WHERE m.family_id = f.id) AS med_count
       FROM families f LEFT JOIN users u ON u.family_id = f.id
       GROUP BY f.id ORDER BY f.id`
    );

    const statusBadge = (s) => {
      if (s === "active") return `<span class="badge info">Activa</span>`;
      if (s === "trial") return `<span class="badge warn">Prueba</span>`;
      if (s === "past_due") return `<span class="badge critical">Pago pendiente</span>`;
      return `<span class="badge critical">Cancelada</span>`;
    };

    const fmtDate = (d) => d ? new Date(d).toLocaleDateString("de-CH", { day: "2-digit", month: "2-digit", year: "numeric" }) : "-";

    const totalActive = families.rows.filter(f => f.subscription_status === "active").length;
    const totalTrial = families.rows.filter(f => f.subscription_status === "trial").length;
    const totalUsers = families.rows.reduce((s, f) => s + Number(f.user_count), 0);

    const msg = req.query.msg || "";
    const content = `
      <div class="card">
        <h1>Facturación / Suscripciones</h1>
        <p class="muted" style="margin-bottom:16px;">Estado de pago de todas las familias registradas.</p>
        ${msg ? `<div style="background:#eff6ff; border:1px solid #93c5fd; border-radius:8px; padding:10px 14px; margin-bottom:12px; font-size:13px; color:#1e40af;">${escapeHtml(msg)}</div>` : ""}
        ${stripe ? `<p style="font-size:12px; color:#059669; margin-bottom:12px;">● Stripe conectado (${STRIPE_SECRET_KEY.startsWith("sk_test") ? "MODO TEST" : "PRODUCCIÓN"}) · Webhook ${STRIPE_WEBHOOK_SECRET ? "✓" : "✗ NO configurado"}</p>` : `<p style="font-size:12px; color:#dc2626; margin-bottom:12px;">● Stripe NO configurado</p>`}
        <div style="display:flex; gap:12px; margin-bottom:16px; flex-wrap:wrap;">
          <div style="background:#ecfdf5; border:1px solid #6ee7b7; border-radius:8px; padding:12px 16px; text-align:center; min-width:120px;">
            <div style="font-size:24px; font-weight:bold; color:#059669;">${totalActive}</div>
            <div style="font-size:11px; color:#065f46;">Suscripciones activas</div>
          </div>
          <div style="background:#eff6ff; border:1px solid #93c5fd; border-radius:8px; padding:12px 16px; text-align:center; min-width:120px;">
            <div style="font-size:24px; font-weight:bold; color:#2563eb;">${totalTrial}</div>
            <div style="font-size:11px; color:#1e40af;">En prueba</div>
          </div>
          <div style="background:#f8fafc; border:1px solid #cbd5e1; border-radius:8px; padding:12px 16px; text-align:center; min-width:120px;">
            <div style="font-size:24px; font-weight:bold; color:#334155;">${families.rows.length}</div>
            <div style="font-size:11px; color:#475569;">Familias</div>
          </div>
          <div style="background:#f8fafc; border:1px solid #cbd5e1; border-radius:8px; padding:12px 16px; text-align:center; min-width:120px;">
            <div style="font-size:24px; font-weight:bold; color:#334155;">${totalUsers}</div>
            <div style="font-size:11px; color:#475569;">Usuarios totales</div>
          </div>
        </div>
        <div style="overflow:auto;">
          <table class="table">
            <thead>
              <tr>
                <th>ID</th>
                <th>Familia</th>
                <th>Estado</th>
                <th>Trial expira</th>
                <th>Suscripción</th>
                <th>Fin/Renovación</th>
                <th>Usuarios</th>
                <th>Medis</th>
                <th>Stripe</th>
                <th>Acción</th>
              </tr>
            </thead>
            <tbody>
              ${families.rows.map(f => {
                const trialExpired = f.subscription_status === "trial" && f.trial_ends_at && new Date(f.trial_ends_at) < new Date();
                return `
                <tr style="${trialExpired ? "background:#fef2f2;" : ""}">
                  <td>${f.id}</td>
                  <td>${escapeHtml(f.name || "Sin nombre")}</td>
                  <td>${statusBadge(f.subscription_status)}${trialExpired ? ' <span style="font-size:10px; color:#dc2626;">EXPIRADA</span>' : ""}</td>
                  <td>${fmtDate(f.trial_ends_at)}${f.trial_email_sent ? ' <span style="font-size:10px; color:#059669;">✉ enviado</span>' : ""}</td>
                  <td>${fmtDate(f.subscription_start)}</td>
                  <td>${fmtDate(f.subscription_end)}</td>
                  <td>${f.user_count}</td>
                  <td>${f.med_count}${f.max_medicines ? `/${f.max_medicines}` : ""}</td>
                  <td style="font-size:10px; word-break:break-all;">${f.stripe_customer_id ? `<a href="https://dashboard.stripe.com/test/customers/${f.stripe_customer_id}" target="_blank" style="color:#2563eb;">${escapeHtml(f.stripe_customer_id.slice(0, 18))}…</a>` : "-"}</td>
                  <td>${f.stripe_customer_id ? `<form method="POST" action="/admin/billing/sync/${f.id}" style="margin:0;"><button type="submit" style="font-size:11px; background:#2563eb; color:white; border:none; padding:4px 10px; border-radius:6px; cursor:pointer;">🔄 Sync</button></form>` : "-"}</td>
                </tr>`;
              }).join("")}
            </tbody>
          </table>
        </div>
      </div>
    `;
    res.send(renderShell(req, "Facturación", "billing", content));
  } catch (err) {
    console.error("[ADMIN BILLING]", err.message);
    res.status(500).send("Error al cargar facturación");
  }
});

// =============================================================================
// LEADS (Landing page signups) - PUBLIC endpoint, no auth required
// =============================================================================
app.post("/api/leads", async (req, res) => {
  const { name, email, phone, lang, message, source } = req.body || {};
  if (!email || !email.includes("@")) return res.status(400).json({ error: "Email inválido" });

  try {
    await pool.query(
      `INSERT INTO leads (name, email, phone, lang, source, message, ip, user_agent)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
       ON CONFLICT (email) DO UPDATE SET name = COALESCE(EXCLUDED.name, leads.name), phone = COALESCE(EXCLUDED.phone, leads.phone), updated_at = NOW()`,
      [name || null, email.trim().toLowerCase(), phone || null, lang || "de-CH", source || "landing", message || null,
       req.headers["x-forwarded-for"] || req.ip || null, req.headers["user-agent"] || null]
    );

    // Send welcome email
    if (mailTransport) {
      const welcomeHtml = `
        <div style="font-family:Arial,sans-serif; max-width:600px; margin:0 auto; padding:20px;">
          <div style="background:linear-gradient(135deg,#0f172a 0%,#1e3a5f 100%); border-radius:16px; padding:32px; text-align:center; margin-bottom:24px;">
            <h1 style="color:#34d399; font-size:28px; margin:0;">MediControl</h1>
            <p style="color:#94a3b8; font-size:14px; margin-top:8px;">Ihre Medikamente. Unter Kontrolle.</p>
          </div>
          <h2 style="color:#0f172a;">Vielen Dank für Ihr Interesse! / ¡Gracias por tu interés!</h2>
          <p style="color:#475569; font-size:14px;">Wir haben Ihre Anfrage erhalten. Sie werden benachrichtigt, sobald die App verfügbar ist.</p>
          <p style="color:#475569; font-size:14px;">Hemos recibido su solicitud. Le notificaremos cuando la app esté disponible.</p>
          <div style="background:#f8fafc; border-radius:12px; padding:20px; margin:20px 0; text-align:center;">
            <p style="font-size:16px; font-weight:bold; color:#0f172a;">Kostenlose 7-Tage-Testversion / Prueba gratuita de 7 días</p>
            <a href="${FRONTEND_URL}" style="display:inline-block; background:#007AFF; color:white; text-decoration:none; padding:12px 32px; border-radius:12px; font-weight:bold; margin-top:12px;">Jetzt testen / Probar ahora</a>
          </div>
          <p style="color:#94a3b8; font-size:11px; text-align:center;">SaaS-Service nach Schweizer Recht. © ${new Date().getFullYear()} MediControl</p>
        </div>`;
      try {
        await mailTransport.sendMail({
          from: process.env.SMTP_USER, to: email.trim(),
          subject: "Willkommen bei MediControl / Bienvenido a MediControl",
          html: welcomeHtml,
        });
      } catch (e) { console.error("[LEADS] Email error:", e.message); }
    }

    // Notify admin
    if (mailTransport && ADMIN_EMAIL) {
      try {
        await sendAdminAlertEmail(`Nuevo lead: ${name || email}`,
          `<p><strong>Nombre:</strong> ${escapeHtml(name || "-")}</p>
           <p><strong>Email:</strong> ${escapeHtml(email)}</p>
           <p><strong>Teléfono:</strong> ${escapeHtml(phone || "-")}</p>
           <p><strong>Idioma:</strong> ${lang || "de-CH"}</p>
           <p><strong>Mensaje:</strong> ${escapeHtml(message || "-")}</p>
           <p><strong>Fuente:</strong> ${source || "landing"}</p>`);
      } catch {}
    }

    console.log(`[LEAD] Nuevo: ${email} (${name || "?"}) via ${source || "landing"}`);
    res.json({ ok: true });
  } catch (err) {
    console.error("[LEADS]", err.message);
    res.status(500).json({ error: "Error al registrar" });
  }
});

// Admin: ver leads
app.get("/admin/leads", requireRoleHtml(["admin", "superuser"]), async (req, res) => {
  try {
    const leads = await pool.query(`SELECT * FROM leads ORDER BY created_at DESC LIMIT 500`);
    const total = leads.rows.length;
    const today = leads.rows.filter(l => new Date(l.created_at).toDateString() === new Date().toDateString()).length;
    const week = leads.rows.filter(l => new Date(l.created_at) > new Date(Date.now() - 7*24*60*60*1000)).length;

    const content = `
      <div class="card">
        <h1>📩 Leads / Interesados</h1>
        <p class="muted" style="margin-bottom:16px;">Registros desde la landing page y otras fuentes.</p>
        <div style="display:flex; gap:12px; margin-bottom:16px; flex-wrap:wrap;">
          <div style="background:#ecfdf5; border:1px solid #6ee7b7; border-radius:8px; padding:12px 16px; text-align:center; min-width:100px;">
            <div style="font-size:24px; font-weight:bold; color:#059669;">${total}</div>
            <div style="font-size:11px; color:#065f46;">Total</div>
          </div>
          <div style="background:#eff6ff; border:1px solid #93c5fd; border-radius:8px; padding:12px 16px; text-align:center; min-width:100px;">
            <div style="font-size:24px; font-weight:bold; color:#2563eb;">${week}</div>
            <div style="font-size:11px; color:#1e40af;">Esta semana</div>
          </div>
          <div style="background:#fffbeb; border:1px solid #fbbf24; border-radius:8px; padding:12px 16px; text-align:center; min-width:100px;">
            <div style="font-size:24px; font-weight:bold; color:#92400e;">${today}</div>
            <div style="font-size:11px; color:#92400e;">Hoy</div>
          </div>
        </div>
        ${leads.rows.length === 0 ? `<p style="color:#94a3b8; text-align:center; padding:32px;">Aún no hay leads.</p>` : `
        <div style="overflow:auto;">
          <table class="table">
            <thead>
              <tr><th>Fecha</th><th>Nombre</th><th>Email</th><th>Teléfono</th><th>Idioma</th><th>Fuente</th><th>Mensaje</th></tr>
            </thead>
            <tbody>
              ${leads.rows.map(l => `
                <tr>
                  <td style="white-space:nowrap; font-size:11px;">${new Date(l.created_at).toLocaleString("de-CH", { timeZone: "Europe/Zurich", day: "2-digit", month: "2-digit", year: "2-digit", hour: "2-digit", minute: "2-digit" })}</td>
                  <td style="font-weight:bold;">${escapeHtml(l.name || "-")}</td>
                  <td style="font-size:12px;"><a href="mailto:${escapeHtml(l.email)}" style="color:#2563eb;">${escapeHtml(l.email)}</a></td>
                  <td style="font-size:12px;">${escapeHtml(l.phone || "-")}</td>
                  <td>${l.lang || "-"}</td>
                  <td style="font-size:11px;">${escapeHtml(l.source || "-")}</td>
                  <td style="max-width:200px; font-size:11px; word-break:break-word;">${l.message ? escapeHtml(l.message) : "-"}</td>
                </tr>
              `).join("")}
            </tbody>
          </table>
        </div>`}
      </div>
    `;
    res.send(renderShell(req, "Leads", "leads", content));
  } catch (err) {
    console.error("[ADMIN LEADS]", err.message);
    res.status(500).send("Error al cargar leads");
  }
});

// =============================================================================
// ADMIN FEEDBACK PAGE
// =============================================================================
app.get("/admin/feedback", requireRoleHtml(["admin", "superuser"]), async (req, res) => {
  try {
    const feedbacks = await pool.query(
      `SELECT f.*, u.name AS current_name FROM feedback f LEFT JOIN users u ON u.id = f.user_id ORDER BY f.created_at DESC LIMIT 100`
    );
    const avgRating = feedbacks.rows.length > 0
      ? (feedbacks.rows.reduce((s, f) => s + f.rating, 0) / feedbacks.rows.length).toFixed(1) : "0";
    const starsHtml = (r) => "⭐".repeat(r) + "☆".repeat(5 - r);

    const content = `
      <div class="card">
        <h1>⭐ Feedback de usuarios</h1>
        <p class="muted" style="margin-bottom:16px;">${feedbacks.rows.length} valoraciones recibidas.</p>
        <div style="display:flex; gap:12px; margin-bottom:16px; flex-wrap:wrap;">
          <div style="background:#fffbeb; border:1px solid #fbbf24; border-radius:8px; padding:12px 16px; text-align:center; min-width:120px;">
            <div style="font-size:28px; font-weight:bold; color:#92400e;">${avgRating}</div>
            <div style="font-size:11px; color:#92400e;">Promedio</div>
          </div>
          <div style="background:#f8fafc; border:1px solid #cbd5e1; border-radius:8px; padding:12px 16px; text-align:center; min-width:120px;">
            <div style="font-size:24px; font-weight:bold; color:#334155;">${feedbacks.rows.length}</div>
            <div style="font-size:11px; color:#475569;">Total valoraciones</div>
          </div>
          ${[5,4,3,2,1].map(r => {
            const count = feedbacks.rows.filter(f => f.rating === r).length;
            return `<div style="background:#f8fafc; border:1px solid #e2e8f0; border-radius:8px; padding:8px 12px; text-align:center; min-width:80px;">
              <div style="font-size:16px; font-weight:bold;">${count}</div>
              <div style="font-size:10px; color:#64748b;">${"⭐".repeat(r)}</div>
            </div>`;
          }).join("")}
        </div>
        ${feedbacks.rows.length === 0 ? `<p style="color:#94a3b8; text-align:center; padding:32px;">Aún no hay valoraciones.</p>` : `
        <div style="overflow:auto;">
          <table class="table">
            <thead>
              <tr>
                <th>Fecha</th>
                <th>Usuario</th>
                <th>Email</th>
                <th>Familia</th>
                <th>Valoración</th>
                <th>Comentario</th>
                <th>Idioma</th>
              </tr>
            </thead>
            <tbody>
              ${feedbacks.rows.map(f => `
                <tr>
                  <td style="white-space:nowrap;">${new Date(f.created_at).toLocaleString("de-CH", { timeZone: "Europe/Zurich", day: "2-digit", month: "2-digit", year: "numeric", hour: "2-digit", minute: "2-digit" })}</td>
                  <td>${escapeHtml(f.user_name || f.current_name || "?")}</td>
                  <td style="font-size:11px;">${escapeHtml(f.user_email || "-")}</td>
                  <td>${f.family_id || "-"}</td>
                  <td style="white-space:nowrap;">${starsHtml(f.rating)} <strong>${f.rating}/5</strong></td>
                  <td style="max-width:300px; word-break:break-word; font-size:12px; font-style:italic;">${f.comment ? escapeHtml(f.comment) : '<span style="color:#94a3b8;">—</span>'}</td>
                  <td>${f.lang || "es"}</td>
                </tr>
              `).join("")}
            </tbody>
          </table>
        </div>`}
      </div>
    `;
    res.send(renderShell(req, "Feedback", "feedback", content));
  } catch (err) {
    console.error("[ADMIN FEEDBACK]", err.message);
    res.status(500).send("Error al cargar feedback");
  }
});

// =============================================================================
// ADMIN REPORTS PAGE
// =============================================================================
app.get("/admin/reports", requireRoleHtml(["admin", "superuser"]), async (req, res) => {
  try {
    const users = await pool.query(`
      SELECT u.id, u.name, u.email, u.role, u.birth_date, u.created_at, u.last_login, u.lang, u.disclaimer_accepted_at,
             f.name AS family_name, f.subscription_status,
             (SELECT COUNT(*) FROM medicines m WHERE m.user_id = u.id OR (m.family_id = u.family_id AND m.user_id IS NULL)) AS med_count,
             (SELECT COUNT(*) FROM schedules s JOIN medicines m2 ON s.medicine_id = m2.id WHERE s.user_id = u.id) AS schedule_count,
             (SELECT MAX(dc.checked_at) FROM daily_checkouts dc WHERE dc.user_id = u.id) AS last_checkout,
             (SELECT COUNT(*) FROM daily_checkouts dc2 WHERE dc2.user_id = u.id AND dc2.checked_at > NOW() - INTERVAL '7 days') AS checkouts_7d
      FROM users u
      LEFT JOIN families f ON f.id = u.family_id
      ORDER BY u.last_login DESC NULLS LAST, u.created_at DESC
    `);

    const totalUsers = users.rows.length;
    const activeUsers = users.rows.filter(u => u.last_login && new Date(u.last_login) > new Date(Date.now() - 7*24*60*60*1000)).length;
    const disclaimerAccepted = users.rows.filter(u => u.disclaimer_accepted_at).length;
    const fmtDate = (d) => d ? new Date(d).toLocaleDateString("de-CH", { day: "2-digit", month: "2-digit", year: "numeric" }) : "-";
    const fmtDateTime = (d) => d ? new Date(d).toLocaleString("de-CH", { timeZone: "Europe/Zurich", day: "2-digit", month: "2-digit", year: "2-digit", hour: "2-digit", minute: "2-digit" }) : "-";

    const content = `
      <div class="card">
        <h1>📊 Informes de usuarios</h1>
        <p class="muted" style="margin-bottom:16px;">Información detallada de actividad y estado de cada usuario.</p>
        <div style="display:flex; gap:12px; margin-bottom:16px; flex-wrap:wrap;">
          <div style="background:#ecfdf5; border:1px solid #6ee7b7; border-radius:8px; padding:12px 16px; text-align:center; min-width:120px;">
            <div style="font-size:24px; font-weight:bold; color:#059669;">${activeUsers}</div>
            <div style="font-size:11px; color:#065f46;">Activos (7d)</div>
          </div>
          <div style="background:#f8fafc; border:1px solid #cbd5e1; border-radius:8px; padding:12px 16px; text-align:center; min-width:120px;">
            <div style="font-size:24px; font-weight:bold; color:#334155;">${totalUsers}</div>
            <div style="font-size:11px; color:#475569;">Usuarios totales</div>
          </div>
          <div style="background:#eff6ff; border:1px solid #93c5fd; border-radius:8px; padding:12px 16px; text-align:center; min-width:120px;">
            <div style="font-size:24px; font-weight:bold; color:#2563eb;">${disclaimerAccepted}</div>
            <div style="font-size:11px; color:#1e40af;">Disclaimer aceptado</div>
          </div>
        </div>
        <div style="overflow:auto;">
          <table class="table">
            <thead>
              <tr>
                <th>ID</th>
                <th>Nombre</th>
                <th>Email</th>
                <th>Rol</th>
                <th>Familia</th>
                <th>Suscripción</th>
                <th>Medis</th>
                <th>Horarios</th>
                <th>Registrado</th>
                <th>Último login</th>
                <th>Tomas 7d</th>
                <th>Última toma</th>
                <th>Idioma</th>
                <th>Disclaimer</th>
              </tr>
            </thead>
            <tbody>
              ${users.rows.map(u => {
                const isActive = u.last_login && new Date(u.last_login) > new Date(Date.now() - 7*24*60*60*1000);
                const subBadge = u.subscription_status === "active" ? '<span class="badge info">Activa</span>'
                  : u.subscription_status === "trial" ? '<span class="badge warn">Trial</span>'
                  : '<span class="badge critical">Inactiva</span>';
                return `
                <tr style="${isActive ? "" : "opacity:0.7;"}">
                  <td>${u.id}</td>
                  <td><a href="/admin/user-edit/${u.id}" style="color:#2563eb; font-weight:bold;">${escapeHtml(u.name || "?")}</a></td>
                  <td style="font-size:11px;">${escapeHtml(u.email || "-")}</td>
                  <td style="font-size:11px;">${u.role}</td>
                  <td style="font-size:11px;">${escapeHtml(u.family_name || "-")}</td>
                  <td>${subBadge}</td>
                  <td>${u.med_count}</td>
                  <td>${u.schedule_count}</td>
                  <td style="font-size:11px;">${fmtDate(u.created_at)}</td>
                  <td style="font-size:11px; ${isActive ? "color:#059669; font-weight:bold;" : ""}">${fmtDateTime(u.last_login)}</td>
                  <td style="text-align:center; ${Number(u.checkouts_7d) > 0 ? "color:#059669; font-weight:bold;" : "color:#94a3b8;"}">${u.checkouts_7d}</td>
                  <td style="font-size:11px;">${fmtDateTime(u.last_checkout)}</td>
                  <td>${u.lang || "es"}</td>
                  <td>${u.disclaimer_accepted_at ? `<span style="color:#059669;">✓ ${fmtDate(u.disclaimer_accepted_at)}</span>` : '<span style="color:#dc2626;">✗</span>'}</td>
                </tr>`;
              }).join("")}
            </tbody>
          </table>
        </div>
      </div>
    `;
    res.send(renderShell(req, "Informes", "reports", content));
  } catch (err) {
    console.error("[ADMIN REPORTS]", err.message);
    res.status(500).send("Error al cargar informes");
  }
});

// =============================================================================
// USER FEEDBACK (Bewertung)
// =============================================================================
app.post("/api/feedback", requireAuth, async (req, res) => {
  const { user_id, family_id, rating, comment, lang: userLang } = req.body || {};
  const userId = Number(user_id || req.user.sub);
  const familyId = Number(family_id || getFamilyId(req));
  const stars = Math.min(5, Math.max(1, Number(rating) || 0));

  try {
    const userResult = await pool.query(
      `SELECT name, email FROM users WHERE id = $1 AND family_id = $2`,
      [userId, familyId]
    );
    const u = userResult.rows[0];
    if (!u) return res.status(404).json({ error: "Usuario no encontrado" });

    const starsDisplay = "⭐".repeat(stars) + "☆".repeat(5 - stars);
    const ts = new Date().toLocaleString("es-ES", { timeZone: "Europe/Zurich" });

    const feedbackHtml = `
      <div style="font-family:Arial,sans-serif; max-width:600px; margin:0 auto; padding:20px;">
        <h2 style="color:#0f172a;">Nueva valoración de usuario</h2>
        <div style="background:#fffbeb; border:1px solid #fbbf24; border-radius:12px; padding:16px; margin:16px 0; text-align:center;">
          <p style="font-size:32px; margin:0;">${starsDisplay}</p>
          <p style="font-size:18px; font-weight:bold; color:#92400e; margin-top:8px;">${stars} / 5</p>
        </div>
        ${comment ? `
        <div style="background:#f8fafc; border:1px solid #e2e8f0; border-radius:12px; padding:16px; margin:16px 0;">
          <p style="font-size:13px; color:#334155; font-style:italic;">"${comment.replace(/</g, "&lt;").replace(/>/g, "&gt;")}"</p>
        </div>` : ""}
        <table style="width:100%; font-size:13px; color:#475569; border-collapse:collapse;">
          <tr><td style="padding:4px 0; font-weight:bold;">Usuario:</td><td>${u.name || "N/A"}</td></tr>
          <tr><td style="padding:4px 0; font-weight:bold;">Email:</td><td>${u.email}</td></tr>
          <tr><td style="padding:4px 0; font-weight:bold;">Familia ID:</td><td>${familyId}</td></tr>
          <tr><td style="padding:4px 0; font-weight:bold;">Idioma:</td><td>${userLang || "es"}</td></tr>
          <tr><td style="padding:4px 0; font-weight:bold;">Fecha:</td><td>${ts}</td></tr>
          <tr><td style="padding:4px 0; font-weight:bold;">User-Agent:</td><td style="word-break:break-all; font-size:11px;">${req.headers["user-agent"] || "N/A"}</td></tr>
        </table>
      </div>
    `;

    // Save to database
    try {
      await pool.query(
        `INSERT INTO feedback (user_id, family_id, user_name, user_email, rating, comment, lang, user_agent)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
        [userId, familyId, u.name || null, u.email, stars, comment || null, userLang || "es", req.headers["user-agent"] || null]
      );
    } catch (e) { console.error("[FEEDBACK] Error guardando en DB:", e.message); }

    // Send to admin
    if (mailTransport && ADMIN_EMAIL) {
      try {
        await sendAdminAlertEmail(`Feedback ${starsDisplay} – ${u.name || u.email}`, feedbackHtml);
      } catch (e) { console.error("[FEEDBACK] Error email admin:", e.message); }
    }

    // Send confirmation to user
    const userConfirmHtml = `
      <div style="font-family:Arial,sans-serif; max-width:600px; margin:0 auto; padding:20px;">
        <h2 style="color:#0f172a;">Gracias por tu valoración</h2>
        <p style="font-size:14px; color:#475569;">Hemos recibido tu feedback:</p>
        <div style="background:#fffbeb; border:1px solid #fbbf24; border-radius:12px; padding:16px; margin:16px 0; text-align:center;">
          <p style="font-size:32px; margin:0;">${starsDisplay}</p>
        </div>
        ${comment ? `<p style="font-size:13px; color:#334155; font-style:italic; background:#f8fafc; padding:12px; border-radius:8px;">"${comment.replace(/</g, "&lt;").replace(/>/g, "&gt;")}"</p>` : ""}
        <p style="font-size:12px; color:#94a3b8; margin-top:16px;">Tu opinión nos ayuda a mejorar. ¡Gracias!</p>
      </div>
    `;
    if (mailTransport && u.email) {
      try {
        await sendUserEmail(u.email, "Gracias por tu valoración – MediControl", userConfirmHtml);
      } catch (e) { console.error("[FEEDBACK] Error email user:", e.message); }
    }

    console.log(`[FEEDBACK] ${stars}/5 de user ${userId} (${u.email}): ${comment || "(sin comentario)"}`);
    res.json({ ok: true });
  } catch (err) {
    console.error("[FEEDBACK] Error:", err.message);
    res.status(500).json({ error: "Error al enviar feedback" });
  }
});

// =============================================================================
// DISCLAIMER ACCEPTANCE (legal)
// =============================================================================
app.post("/api/disclaimer-accepted", requireAuth, async (req, res) => {
  const { user_id, family_id, accepted_at, lang: userLang } = req.body || {};
  const userId = Number(user_id || req.user.sub);
  const familyId = Number(family_id || getFamilyId(req));
  const ts = accepted_at || new Date().toISOString();

  try {
    // Save acceptance in DB
    await pool.query(
      `UPDATE users SET disclaimer_accepted_at = $1, disclaimer_ip = $2, disclaimer_lang = $3 WHERE id = $4 AND family_id = $5`,
      [ts, req.ip || req.headers["x-forwarded-for"] || "unknown", userLang || "es", userId, familyId]
    );

    // Get user info
    const userResult = await pool.query(
      `SELECT name, email FROM users WHERE id = $1 AND family_id = $2`,
      [userId, familyId]
    );
    const u = userResult.rows[0];
    if (!u) return res.status(404).json({ error: "Usuario no encontrado" });

    const disclaimerHtml = `
      <div style="font-family:Arial,sans-serif; max-width:600px; margin:0 auto; padding:20px;">
        <h2 style="color:#0f172a;">Confirmación de aceptación del aviso legal</h2>
        <div style="background:#f8fafc; border:1px solid #e2e8f0; border-radius:12px; padding:16px; margin:16px 0;">
          <p style="font-size:14px; color:#334155; line-height:1.6;">
            Esta aplicación es una herramienta de apoyo para la gestión y el recordatorio de la medicación
            prescrita por su médico de cabecera. En ningún caso sustituye, modifica ni reemplaza el diagnóstico,
            la prescripción ni las indicaciones de su profesional sanitario. El usuario se compromete a seguir
            siempre las instrucciones de su médico tratante. El uso de esta aplicación no establece una relación
            médico-paciente. Ante cualquier duda sobre su medicación, consulte a su médico o farmacéutico.
          </p>
        </div>
        <table style="width:100%; font-size:14px; color:#475569; border-collapse:collapse;">
          <tr><td style="padding:6px 0; font-weight:bold;">Usuario:</td><td>${u.name || "N/A"}</td></tr>
          <tr><td style="padding:6px 0; font-weight:bold;">Email:</td><td>${u.email}</td></tr>
          <tr><td style="padding:6px 0; font-weight:bold;">Fecha de aceptación:</td><td>${new Date(ts).toLocaleString("es-ES", { timeZone: "Europe/Zurich" })}</td></tr>
          <tr><td style="padding:6px 0; font-weight:bold;">IP:</td><td>${req.ip || "N/A"}</td></tr>
          <tr><td style="padding:6px 0; font-weight:bold;">User-Agent:</td><td style="word-break:break-all;">${req.headers["user-agent"] || "N/A"}</td></tr>
        </table>
        <p style="font-size:11px; color:#94a3b8; margin-top:16px;">
          Este correo se genera automáticamente como registro legal de la aceptación de los términos de uso.
          Conserve este mensaje como comprobante.
        </p>
      </div>
    `;

    const subject = `Aceptación del aviso legal – ${u.name || u.email}`;

    // Send to user
    if (mailTransport && u.email) {
      try { await sendUserEmail(u.email, subject, disclaimerHtml); } catch (e) { console.error("[DISCLAIMER] Error email usuario:", e.message); }
    }
    // Send to admin
    if (mailTransport && ADMIN_EMAIL) {
      try { await sendAdminAlertEmail(subject, disclaimerHtml); } catch (e) { console.error("[DISCLAIMER] Error email admin:", e.message); }
    }

    console.log(`[DISCLAIMER] Aceptado por user ${userId} (${u.email}) a las ${ts}`);
    res.json({ ok: true, message: "Aceptación registrada" });
  } catch (err) {
    console.error("[DISCLAIMER] Error:", err.message);
    res.status(500).json({ error: "Error al registrar aceptación" });
  }
});

// =============================================================================
// ADMIN GLOBAL SEARCH
// =============================================================================
app.get("/admin/search", requireRoleHtml(["admin", "superuser"]), async (req, res) => {
  const familyId = req.user.family_id;
  const q = (req.query?.q || "").trim();
  if (!q) return res.redirect("/dashboard");

  try {
    const like = `%${q}%`;
    const [users, meds, alertsResult] = await Promise.all([
      pool.query(
        `SELECT id, name, email, role FROM users WHERE family_id = $1 AND (name ILIKE $2 OR email ILIKE $2 OR first_name ILIKE $2 OR last_name ILIKE $2) ORDER BY name LIMIT 20`,
        [familyId, like]
      ),
      pool.query(
        `SELECT m.id, m.name, m.dosage, m.current_stock, u.name AS user_name
         FROM medicines m JOIN users u ON u.id = m.user_id
         WHERE m.family_id = $1 AND (m.name ILIKE $2 OR m.dosage ILIKE $2) ORDER BY m.name LIMIT 20`,
        [familyId, like]
      ),
      pool.query(
        `SELECT id, type, message, med_name, created_at FROM alerts
         WHERE family_id = $1 AND (message ILIKE $2 OR med_name ILIKE $2) ORDER BY created_at DESC LIMIT 20`,
        [familyId, like]
      ),
    ]);

    const escQ = escapeHtml(q);
    const content = `
      <div class="card">
        <h1>Resultados para "${escQ}"</h1>

        <h2 style="margin-top:18px; font-size:16px;">👤 Pacientes (${users.rows.length})</h2>
        ${users.rows.length ? `
          <div class="list">
            ${users.rows.map(u => `
              <div class="list-item" style="display:flex; justify-content:space-between; align-items:center;">
                <div>
                  <strong>${escapeHtml(u.name)}</strong>
                  <div class="meta">${escapeHtml(u.email)} · ${u.role}</div>
                </div>
                <div style="display:flex; gap:8px;">
                  <a class="btn outline" href="/admin/user-edit/${u.id}">Editar</a>
                  <a class="btn outline" href="/admin/meds/${u.id}">Medicamentos</a>
                </div>
              </div>
            `).join("")}
          </div>
        ` : `<p class="empty">Sin resultados</p>`}

        <h2 style="margin-top:18px; font-size:16px;">💊 Medicamentos (${meds.rows.length})</h2>
        ${meds.rows.length ? `
          <div class="list">
            ${meds.rows.map(m => `
              <div class="list-item" style="display:flex; justify-content:space-between; align-items:center;">
                <div>
                  <strong>${escapeHtml(m.name)}</strong> · ${escapeHtml(m.dosage || "")}
                  <div class="meta">Stock: ${m.current_stock} · Paciente: ${escapeHtml(m.user_name || "")}</div>
                </div>
                <a class="btn outline" href="/admin/meds-edit/${m.id}">Editar</a>
              </div>
            `).join("")}
          </div>
        ` : `<p class="empty">Sin resultados</p>`}

        <h2 style="margin-top:18px; font-size:16px;">🔔 Alertas (${alertsResult.rows.length})</h2>
        ${alertsResult.rows.length ? `
          <div class="list">
            ${alertsResult.rows.map(a => `
              <div class="list-item">
                <strong>${escapeHtml(a.med_name || a.type)}</strong>
                <div class="meta">${escapeHtml(a.message || "")} · ${a.created_at ? new Date(a.created_at).toLocaleDateString("es-ES") : ""}</div>
              </div>
            `).join("")}
          </div>
        ` : `<p class="empty">Sin resultados</p>`}
      </div>
    `;
    res.send(renderShell(req, `Búsqueda: ${escQ}`, "home", content));
  } catch (err) {
    console.error("[SEARCH] Error:", err.message);
    res.redirect("/dashboard");
  }
});

// =============================================================================
// DAILY CHECKOUT (envío de mail cuando el plan del día se completa)
// =============================================================================
app.post("/api/daily-checkout", requireAuth, async (req, res) => {
  const { user_id, date, family_id } = req.body || {};
  const familyId = Number(family_id || getFamilyId(req));
  const userId = Number(user_id || req.user.sub);
  const day = date || new Date().toISOString().slice(0, 10);

  if (!familyId || !userId) {
    return res.status(400).json({ error: "family_id y user_id son requeridos" });
  }

  try {
    const dayToken = String((() => {
      const d = new Date(day).getDay();
      const map = [7, 1, 2, 3, 4, 5, 6];
      return map[d];
    })());

    const schedules = await pool.query(
      `SELECT s.id
       FROM schedules s
       JOIN medicines m ON m.id = s.medicine_id
       JOIN users u ON u.id = s.user_id
       WHERE s.user_id = $1 AND m.family_id = $2 AND u.family_id = $2
         AND POSITION($3 IN COALESCE(s.days_of_week, '1234567')) > 0
         AND (s.start_date IS NULL OR $4::date >= s.start_date)
         AND (s.end_date IS NULL OR $4::date <= s.end_date)`,
      [userId, familyId, dayToken, day]
    );

    if (schedules.rows.length === 0) {
      return res.json({ ok: true, message: "Sin programaciones para hoy" });
    }

    const taken = await pool.query(
      `SELECT COUNT(*) FROM dose_logs
       WHERE schedule_id = ANY($1) AND taken_at::date = $2::date AND status = 'taken'`,
      [schedules.rows.map((s) => s.id), day]
    );

    const total = schedules.rows.length;
    const takenCount = Number(taken.rows[0].count || 0);
    if (takenCount < total) {
      await sendPushToUser(userId, {
        title: "Tomas pendientes",
        body: `Te faltan ${total - takenCount} toma(s) hoy.`,
      });
      return res.json({ ok: false, message: "Plan incompleto" });
    }

    const existing = await pool.query(
      `SELECT id FROM daily_checkouts WHERE user_id = $1 AND day = $2::date`,
      [userId, day]
    );
    if (existing.rows.length > 0) {
      return res.json({ ok: true, message: "Checkout ya enviado" });
    }

    await pool.query(
      `INSERT INTO daily_checkouts (user_id, family_id, day)
       VALUES ($1, $2, $3::date)`,
      [userId, familyId, day]
    );

    const userResult = await pool.query(
      `SELECT email, name FROM users WHERE id = $1`,
      [userId]
    );

    const userEmail = userResult.rows[0]?.email;
    const userName = userResult.rows[0]?.name;
    const subject = "Plan diario completado";
    const html = `<p>${escapeHtml(
      userName || "Paciente"
    )} completó el plan del día ${day}.</p>`;

    if (mailTransport && userEmail) {
      await mailTransport.sendMail({
        from: process.env.SMTP_USER,
        to: userEmail,
        subject,
        html,
      });
    }
    if (ADMIN_EMAIL) {
      await sendAdminAlertEmail(subject, html);
    }

    res.json({ ok: true, message: "Checkout enviado" });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ---------------------------------------------------------------------------
// SISTEMA DE ALERTAS v2
// - Stock bajo/cero: se genera máximo 1 vez al día por medicamento
// - Dosis pendientes: se re-evalúan cada 4 horas (no se duplican)
// - Alertas de días pasados: se borran automáticamente
// ---------------------------------------------------------------------------

async function generateStockAlerts(familyId) {
  const today = new Date().toISOString().slice(0, 10);
  const lowStock = await pool.query(
    `SELECT id, name, dosage, current_stock, user_id, stock_depleted
     FROM medicines
     WHERE family_id = $1 AND current_stock <= $2`,
    [familyId, LOW_STOCK_THRESHOLD]
  );
  let created = 0;
  for (const med of lowStock.rows) {
    // Si stock = 0 y ya está marcado como depleted, NO generar más alertas
    // Solo se reactivará cuando el paciente escanee/importe nueva caja
    if (med.current_stock === 0 && med.stock_depleted) {
      continue; // Ya se envió la alerta, no repetir
    }

    // Si stock = 0 y NO estaba marcado, marcar como depleted y crear UNA alerta
    if (med.current_stock === 0 && !med.stock_depleted) {
      await pool.query(`UPDATE medicines SET stock_depleted = TRUE WHERE id = $1`, [med.id]);
    }

    // Solo crear si no existe ya una alerta de stock para este medicamento (cualquier día)
    const exists = await pool.query(
      `SELECT 1 FROM alerts
       WHERE family_id = $1 AND type = 'low_stock' AND med_name = $2
         AND (user_id = $3 OR ($3::int IS NULL AND user_id IS NULL))
       LIMIT 1`,
      [familyId, med.name, med.user_id]
    );
    if (exists.rows.length === 0) {
      await pool.query(
        `INSERT INTO alerts (family_id, user_id, type, level, message, med_name, med_dosage, alert_date)
         VALUES ($1, $2, 'low_stock', $3, $4, $5, $6, $7)`,
        [
          familyId,
          med.user_id,
          med.current_stock === 0 ? "critical" : "warning",
          med.current_stock === 0
            ? `Sin stock: ${med.name}`
            : `Stock bajo: ${med.name} (${med.current_stock})`,
          med.name,
          med.dosage || "N/A",
          today,
        ]
      );
      created += 1;
    }
  }
  return created;
}

async function generateDoseAlerts(familyId) {
  const today = new Date().toISOString().slice(0, 10);
  const dayToken = String((() => {
    const d = new Date(today).getDay();
    const map = [7, 1, 2, 3, 4, 5, 6];
    return map[d];
  })());
  const dueSchedules = await pool.query(
    `SELECT s.id, s.user_id, s.dose_time, u.name AS user_name, m.name AS med_name, m.dosage
     FROM schedules s
     JOIN users u ON u.id = s.user_id
     JOIN medicines m ON m.id = s.medicine_id
     WHERE u.family_id = $1 AND m.family_id = $1
       AND m.user_id = s.user_id
       AND POSITION($2 IN COALESCE(s.days_of_week, '1234567')) > 0
       AND (s.start_date IS NULL OR $3::date >= s.start_date)
       AND (s.end_date IS NULL OR $3::date <= s.end_date)`,
    [familyId, dayToken, today]
  );
  let created = 0;
  for (const row of dueSchedules.rows) {
    // Verificar si ya fue tomado
    const taken = await pool.query(
      `SELECT 1 FROM dose_logs
       WHERE schedule_id = $1 AND taken_at::date = $2::date AND status = 'taken'`,
      [row.id, today]
    );
    if (taken.rows.length > 0) continue;
    // No duplicar alerta si ya existe para este schedule + hoy
    const alertExists = await pool.query(
      `SELECT 1 FROM alerts
       WHERE family_id = $1 AND type = 'dose_due' AND schedule_id = $2
         AND alert_date = $3::date AND read_at IS NULL`,
      [familyId, row.id, today]
    );
    if (alertExists.rows.length > 0) continue;
    await pool.query(
      `INSERT INTO alerts (family_id, user_id, type, level, message, med_name, med_dosage, dose_time, alert_date, schedule_id)
       VALUES ($1, $2, 'dose_due', 'info', $3, $4, $5, $6, $7, $8)`,
      [
        familyId,
        row.user_id,
        `Toma pendiente: ${row.med_name} a las ${row.dose_time}`,
        row.med_name,
        row.dosage || "N/A",
        row.dose_time,
        today,
        row.id,
      ]
    );
    await sendPushToUser(row.user_id, {
      title: "Recordatorio de medicación",
      body: `Toma pendiente: ${row.med_name} a las ${row.dose_time}`,
    });
    created += 1;
  }
  return created;
}

// Wrapper compatible con las rutas admin que llaman a generateAlertsForFamily
async function generateAlertsForFamily(familyId) {
  const s = await generateStockAlerts(familyId);
  const d = await generateDoseAlerts(familyId);
  return s + d;
}

async function cleanupOldAlerts() {
  const today = new Date().toISOString().slice(0, 10);
  // 1) Borrar alertas de DOSIS de días pasados (read o no)
  await pool.query(
    `DELETE FROM alerts WHERE type = 'dose_due' AND alert_date IS NOT NULL AND alert_date < $1::date`,
    [today]
  );
  // 2) Borrar alertas dose_due ya confirmadas (tomadas hoy)
  await pool.query(
    `DELETE FROM alerts a
     WHERE a.type = 'dose_due'
       AND EXISTS (
         SELECT 1 FROM dose_logs dl
         WHERE dl.schedule_id = a.schedule_id
           AND dl.taken_at::date = a.alert_date
           AND dl.status = 'taken'
       )`
  );
  // 3) Borrar alertas de stock si el medicamento ya tiene stock suficiente (fue reabastecido)
  await pool.query(
    `DELETE FROM alerts a
     WHERE a.type IN ('low_stock', 'stock_low')
       AND a.med_name IS NOT NULL
       AND EXISTS (
         SELECT 1 FROM medicines m
         WHERE m.family_id = a.family_id
           AND m.user_id = a.user_id
           AND m.name = a.med_name
           AND m.current_stock > $1
           AND COALESCE(m.stock_depleted, FALSE) = FALSE
       )`,
    [LOW_STOCK_THRESHOLD]
  );
  // 4) Borrar alertas de stock sin medicamento asociado
  await pool.query(
    `DELETE FROM alerts
     WHERE type IN ('low_stock', 'stock_low') AND (med_name IS NULL OR med_name = '')`
  );
  // 5) Migrar tipo viejo stock_low → low_stock para consistencia
  await pool.query(
    `UPDATE alerts SET type = 'low_stock' WHERE type = 'stock_low'`
  );
}

// Verificar medicamentos que alcanzaron su fecha límite (end_date)
// Envía mail al paciente y al admin, marca como notificado
async function checkMedicineEndDates() {
  const today = new Date().toISOString().slice(0, 10);
  const expired = await pool.query(
    `SELECT m.id, m.name, m.dosage, m.end_date, m.family_id, m.user_id,
            u.name AS user_name, u.email AS user_email
     FROM medicines m
     LEFT JOIN users u ON u.id = m.user_id
     WHERE m.end_date IS NOT NULL
       AND m.end_date <= $1::date
       AND m.end_date_notified = FALSE`,
    [today]
  );
  for (const med of expired.rows) {
    // Enviar mail al paciente
    if (med.user_email && mailTransport) {
      try {
        await mailTransport.sendMail({
          from: process.env.SMTP_USER,
          to: med.user_email,
          subject: `Tratamiento finalizado: ${med.name}`,
          html: `<p>Hola ${med.user_name || ""},</p>
                 <p>El tratamiento con <strong>${med.name} (${med.dosage || ""})</strong> ha llegado a su fecha límite (${med.end_date}).</p>
                 <p>Consulta con tu médico si necesitas continuar.</p>`,
        });
      } catch (err) {
        console.error("Error enviando mail end_date al paciente:", err.message);
      }
    }
    // Enviar mail al admin
    if (ADMIN_EMAIL && mailTransport) {
      try {
        await mailTransport.sendMail({
          from: process.env.SMTP_USER,
          to: ADMIN_EMAIL,
          subject: `Tratamiento finalizado: ${med.name} (${med.user_name || "paciente"})`,
          html: `<p>El medicamento <strong>${med.name} (${med.dosage || ""})</strong> del paciente <strong>${med.user_name || ""}</strong> ha alcanzado su fecha límite (${med.end_date}).</p>`,
        });
      } catch (err) {
        console.error("Error enviando mail end_date al admin:", err.message);
      }
    }
    // Marcar como notificado
    await pool.query(
      `UPDATE medicines SET end_date_notified = TRUE WHERE id = $1`,
      [med.id]
    );
    console.log(`[end_date] Medicamento ${med.name} (id=${med.id}) alcanzó límite ${med.end_date}`);
  }
}

// --- Timers separados para stock (1x/día) y dosis (cada 4h) ---
let lastStockRunDate = "";

async function runAlertsJob() {
  try {
    // Siempre limpiar alertas viejas
    await cleanupOldAlerts();

    const today = new Date().toISOString().slice(0, 10);
    const families = await pool.query(`SELECT id FROM families`);

    for (const row of families.rows) {
      // Stock: solo 1 vez al día
      if (lastStockRunDate !== today) {
        await generateStockAlerts(row.id);
      }
      // Dosis: cada ejecución (cada 4 horas)
      await generateDoseAlerts(row.id);
    }

    // Verificar fechas límite de medicamentos (1x al día)
    if (lastStockRunDate !== today) {
      await checkMedicineEndDates();
      lastStockRunDate = today;
      console.log(`[alertas] Stock + end_date generados para ${today}`);
    }
  } catch (error) {
    console.error("ERROR: job alertas:", error.message);
  }
}

app.get("/admin/alerts/run", requireRoleHtml(["admin", "superuser"]), async (req, res) => {
  const familyId = req.user.family_id;
  const userId = Number(req.query?.user_id);
  const where = Number.isFinite(userId) ? "family_id = $1 AND user_id = $2" : "family_id = $1";
  const args = Number.isFinite(userId) ? [familyId, userId] : [familyId];
  const medicines = await pool.query(
    `SELECT id, name, dosage, current_stock, user_id
     FROM medicines
     WHERE ${where} AND current_stock <= $${args.length + 1}
     ORDER BY current_stock ASC`,
    [...args, LOW_STOCK_THRESHOLD]
  );
  for (const med of medicines.rows) {
    const message = `Stock bajo: ${med.name} (${med.dosage || "N/A"}) · ${med.current_stock}`;
    await pool.query(
      `INSERT INTO alerts (family_id, user_id, type, level, message)
       VALUES ($1, $2, 'low_stock', 'warning', $3)`,
      [familyId, med.user_id || null, message]
    );
  }
  if (medicines.rows.length) {
    const pdfBuffer = await buildCriticalMedsPdf(medicines.rows, {
      title: "Medicamentos críticos (stock bajo)",
    });
    await sendAdminAlertEmail(
      "Alertas de stock bajo",
      `<p>Se generaron ${medicines.rows.length} alertas de stock bajo.</p>
       <p>Adjunto: PDF con medicamentos críticos.</p>`,
      [
        {
          filename: "medicamentos_criticos.pdf",
          content: pdfBuffer,
        },
      ]
    );
  }
  return res.redirect("/admin/alerts");
});

app.post("/admin/alerts/run", requireRoleHtml(["admin", "superuser"]), async (req, res) => {
  const familyId = req.user.family_id;
  const created = await generateAlertsForFamily(familyId);
  await sendAdminAlertEmail(
    "Alertas de medicación",
    `<p>Se generaron ${created} alertas para la familia ${familyId}.</p>`
  );
  res.redirect("/admin/alerts");
});

app.get("/admin/alerts/test-email", requireRoleHtml(["admin", "superuser"]), async (_req, res) => {
  if (!mailTransport || !ADMIN_EMAIL) {
    const content = `
      <div class="card">
        <h1>SMTP no configurado</h1>
        <p>Faltan SMTP_HOST/SMTP_USER/SMTP_PASS o ADMIN_EMAIL.</p>
        <div style="margin-top:12px;">
          <a class="btn outline" href="/admin/alerts">Volver</a>
        </div>
      </div>
    `;
    return res.send(renderShell(_req, "SMTP no configurado", "alerts", content));
  }
  try {
    const familyId = _req.user.family_id;
    const meds = await pool.query(
      `SELECT name, dosage, current_stock
       FROM medicines
       WHERE family_id = $1 AND current_stock <= $2
       ORDER BY current_stock ASC`,
      [familyId, LOW_STOCK_THRESHOLD]
    );
    const attachments = meds.rows.length
      ? [
          {
            filename: "medicamentos_criticos.pdf",
            content: await buildCriticalMedsPdf(meds.rows, {
              title: "Medicamentos críticos (prueba)",
            }),
          },
        ]
      : undefined;
    await sendAdminAlertEmail(
      "Prueba de correo",
      `<p>Este es un correo de prueba del sistema de alertas.</p>
       <p>Adjunto: PDF si hay medicamentos críticos.</p>`,
      attachments
    );
    const content = `
      <div class="card">
        <h1>Correo enviado</h1>
        <p>Se envió un email de prueba a ${ADMIN_EMAIL}.</p>
        <div style="margin-top:12px;">
          <a class="btn outline" href="/admin/alerts">Volver</a>
        </div>
      </div>
    `;
    return res.send(renderShell(_req, "Correo enviado", "alerts", content));
  } catch (error) {
    const content = `
      <div class="card">
        <h1>Error al enviar</h1>
        <p class="muted">${escapeHtml(error.message)}</p>
        <div style="margin-top:12px;">
          <a class="btn outline" href="/admin/alerts">Volver</a>
        </div>
      </div>
    `;
    return res.send(renderShell(_req, "Error al enviar", "alerts", content));
  }
});

app.get("/admin/alerts", requireRoleHtml(["admin", "superuser"]), async (req, res) => {
  const familyId = req.user.family_id;
  const users = await pool.query(
    `SELECT id, name, email FROM users WHERE family_id = $1 ORDER BY name ASC`,
    [familyId]
  );
  const alerts = await pool.query(
    `SELECT id, type, level, message, created_at, read_at
     FROM alerts
     WHERE family_id = $1
     ORDER BY created_at DESC
     LIMIT 50`,
    [familyId]
  );
  const content = `
    <div class="card">
      <h1>Alertas</h1>
      <div class="actions" style="margin-top:12px;">
        <a class="btn primary" href="/admin/alerts/run">⚠ Generar alertas</a>
        <a class="btn outline" href="/admin/alerts/test-email">✉ Probar email</a>
      </div>
      <form method="POST" action="/admin/alerts/clear" class="actions" style="margin-top:12px;">
        <select name="user_id" class="form-control" style="max-width:320px;">
          <option value="">Todas las alertas</option>
          ${
            users.rows.length
              ? users.rows
                  .map(
                    (u) =>
                      `<option value="${u.id}">${escapeHtml(u.name)} · ${escapeHtml(
                        u.email
                      )}</option>`
                  )
                  .join("")
              : `<option value="">Sin usuarios</option>`
          }
        </select>
        <button class="btn outline" type="submit">🧹 Borrar alertas</button>
      </form>
      <div style="margin-top:12px; overflow:auto;">
        <table class="table">
          <thead>
            <tr>
              <th>Tipo</th>
              <th>Mensaje</th>
              <th>Estado</th>
              <th>Fecha</th>
            </tr>
          </thead>
          <tbody>
            ${
              alerts.rows.length
                ? alerts.rows
                    .map(
                      (row) => `
            <tr>
              <td>${escapeHtml(row.type)}</td>
              <td>${escapeHtml(row.message)}</td>
              <td>
                  <span style="padding:4px 8px; border-radius:999px; font-size:12px; background:${
                    row.level === "warning" ? "#FEF3C7" : "#DBEAFE"
                  }; color:${row.level === "warning" ? "#92400E" : "#1E3A8A"};">
                    ${row.read_at ? "Leída" : "Nueva"}
                  </span>
                </td>
              <td>${formatDateTime(row.created_at)}</td>
              </tr>`
                    )
                    .join("")
                : `<tr><td colspan="4" style="padding:12px; color:var(--muted);">Sin alertas</td></tr>`
            }
          </tbody>
        </table>
      </div>
    </div>
  `;
  res.send(renderShell(req, "Alertas", "alerts", content));
});

app.get("/admin/dose-requests", requireRoleHtml(["admin", "superuser"]), async (req, res) => {
  const familyId = req.user.family_id;
  const requests = await pool.query(
    `SELECT r.id, r.requested_dosage, r.effective_date, r.created_at,
            u.name AS user_name, u.email AS user_email,
            m.name AS med_name, m.dosage AS current_dosage,
            s.dose_time
     FROM dose_change_requests r
     JOIN users u ON u.id = r.user_id
     JOIN medicines m ON m.id = r.medicine_id
     JOIN schedules s ON s.id = r.schedule_id
     WHERE r.family_id = $1 AND r.status = 'pending'
     ORDER BY r.created_at DESC`,
    [familyId]
  );
  const content = `
    <div class="card">
      <h1>Solicitudes de cambio de dosis</h1>
      <div style="margin-top:12px; overflow:auto;">
        <table class="table">
          <thead>
            <tr>
              <th>Paciente</th>
              <th>Medicamento</th>
              <th>Dosis actual</th>
              <th>Nueva dosis</th>
              <th>Fecha efectiva</th>
              <th>Hora</th>
              <th>Acciones</th>
            </tr>
          </thead>
          <tbody>
            ${
              requests.rows.length
                ? requests.rows
                    .map(
                      (row) => `
            <tr>
              <td>${escapeHtml(row.user_name)} · ${escapeHtml(row.user_email || "")}</td>
              <td>${escapeHtml(row.med_name)}</td>
              <td>${escapeHtml(row.current_dosage || "N/A")}</td>
              <td>${escapeHtml(row.requested_dosage)}</td>
              <td>${row.effective_date ? formatDateOnlyDisplay(row.effective_date) : "-"}</td>
              <td>${escapeHtml(row.dose_time || "-")}</td>
              <td>
                <form method="POST" action="/admin/dose-requests/${row.id}/approve" style="display:inline;">
                  <button class="btn primary" type="submit">Aprobar</button>
                </form>
                <form method="POST" action="/admin/dose-requests/${row.id}/reject" style="display:inline; margin-left:6px;">
                  <button class="btn outline" type="submit">Rechazar</button>
                </form>
              </td>
            </tr>`
                    )
                    .join("")
                : `<tr><td colspan="7" style="padding:12px; color:var(--muted);">Sin solicitudes pendientes</td></tr>`
            }
          </tbody>
        </table>
      </div>
    </div>
  `;
  res.send(renderShell(req, "Cambios de dosis", "dose", content));
});

app.get("/admin/medical-records", requireRoleHtml(["admin", "superuser"]), async (req, res) => {
  const familyId = req.user.family_id;
  const userId = Number(req.query?.user_id || 0);
  const users = await pool.query(
    `SELECT id, name, email FROM users WHERE family_id = $1 ORDER BY name ASC`,
    [familyId]
  );
  const params = [familyId];
  let where = "WHERE family_id = $1";
  if (userId) {
    params.push(userId);
    where += ` AND user_id = $${params.length}`;
  }
  const records = await pool.query(
    `SELECT id, user_id, title, record_date, created_at
     FROM medical_records
     ${where}
     ORDER BY created_at DESC
     LIMIT 100`,
    params
  );
  const content = `
    <div class="card">
      <h1>Subir PDF médico</h1>
      <form method="POST" action="/admin/medical-records" enctype="multipart/form-data" class="actions">
        <select name="user_id" class="form-control" style="max-width:260px;">
          ${
            users.rows.length
              ? users.rows
                  .map(
                    (u) =>
                      `<option value="${u.id}">${escapeHtml(u.name)} · ${escapeHtml(
                        u.email
                      )}</option>`
                  )
                  .join("")
              : `<option value="">Sin usuarios</option>`
          }
        </select>
        <input class="form-control" name="title" placeholder="Título (ej. Análisis de sangre)" required style="max-width:260px;" />
        <input class="form-control" name="record_date" placeholder="Fecha (YYYY-MM-DD)" style="max-width:200px;" />
        <input name="file" type="file" accept="application/pdf" required />
        <button class="btn primary" type="submit">⬆ Guardar</button>
      </form>
      <p class="muted" style="font-size:12px; margin-top:6px;">Solo PDF. Se guardará en el historial del paciente.</p>
    </div>
    <div class="card">
      <h1>Historial médico</h1>
      <form method="GET" action="/admin/medical-records" class="actions">
        <select name="user_id" class="form-control" style="max-width:260px;">
          <option value="">Todos los usuarios</option>
          ${
            users.rows.length
              ? users.rows
                  .map(
                    (u) =>
                      `<option value="${u.id}" ${u.id === userId ? "selected" : ""}>${escapeHtml(
                        u.name
                      )} · ${escapeHtml(u.email)}</option>`
                  )
                  .join("")
              : `<option value="">Sin usuarios</option>`
          }
        </select>
        <button class="btn outline" type="submit">🔎 Filtrar</button>
      </form>
      <div style="margin-top:12px; overflow:auto;">
        <table class="table">
          <thead>
            <tr>
              <th>ID</th>
              <th>Paciente</th>
              <th>Título</th>
              <th>Fecha</th>
              <th>Creado</th>
              <th>Acciones</th>
            </tr>
          </thead>
          <tbody>
            ${
              records.rows.length
                ? records.rows
                    .map(
                      (row) => `
            <tr>
              <td>${row.id}</td>
              <td>${row.user_id}</td>
              <td>${escapeHtml(row.title)}</td>
              <td>${row.record_date ? formatDateOnlyDisplay(row.record_date) : "-"}</td>
              <td>${formatDateTime(row.created_at)}</td>
              <td><a class="btn outline" href="/admin/medical-records/${row.id}/download">Descargar</a></td>
            </tr>`
                    )
                    .join("")
                : `<tr><td colspan="6" style="padding:12px; color:var(--muted);">Sin registros</td></tr>`
            }
          </tbody>
        </table>
      </div>
    </div>
  `;
  res.send(renderShell(req, "Historial médico", "history", content));
});

app.post(
  "/admin/medical-records",
  requireRoleHtml(["admin", "superuser"]),
  upload.single("file"),
  async (req, res) => {
    const familyId = req.user.family_id;
    const userId = Number(req.body?.user_id);
    const title = String(req.body?.title || "").trim();
    const recordDate = normalizeDateOnly(req.body?.record_date);
    if (!Number.isFinite(userId) || !title || !req.file?.path) {
      return res.redirect("/admin/medical-records");
    }
    const fileName = `${Date.now()}_${safeFilename(req.file.originalname)}`;
    const targetPath = path.join(medicalRecordsDir, fileName);
    try {
      fs.renameSync(req.file.path, targetPath);
    } catch {
      fs.copyFileSync(req.file.path, targetPath);
      fs.unlinkSync(req.file.path);
    }
    await pool.query(
      `INSERT INTO medical_records (family_id, user_id, title, record_date, file_path)
       VALUES ($1, $2, $3, $4, $5)`,
      [familyId, userId, title, recordDate || null, targetPath]
    );
    res.redirect("/admin/medical-records");
  }
);

app.get("/admin/medical-records/:id/download", requireRoleHtml(["admin", "superuser"]), async (req, res) => {
  const familyId = req.user.family_id;
  const recordId = Number(req.params.id);
  if (!Number.isFinite(recordId)) {
    return res.redirect("/admin/medical-records");
  }
  const record = await pool.query(
    `SELECT title, file_path
     FROM medical_records
     WHERE id = $1 AND family_id = $2`,
    [recordId, familyId]
  );
  if (!record.rows.length) {
    return res.redirect("/admin/medical-records");
  }
  const filePath = record.rows[0].file_path;
  res.download(filePath, safeFilename(`${record.rows[0].title}.pdf`));
});

app.post("/admin/dose-requests/:id/approve", requireRoleHtml(["admin", "superuser"]), async (req, res) => {
  const familyId = req.user.family_id;
  const requestId = Number(req.params.id);
  if (!Number.isFinite(requestId)) {
    return res.redirect("/admin/dose-requests");
  }
  const request = await pool.query(
    `SELECT id, medicine_id, requested_dosage
     FROM dose_change_requests
     WHERE id = $1 AND family_id = $2 AND status = 'pending'`,
    [requestId, familyId]
  );
  if (!request.rows.length) {
    return res.redirect("/admin/dose-requests");
  }
  const row = request.rows[0];
  await pool.query(`UPDATE medicines SET dosage = $1 WHERE id = $2`, [
    row.requested_dosage,
    row.medicine_id,
  ]);
  await pool.query(`UPDATE dose_change_requests SET status = 'approved' WHERE id = $1`, [
    requestId,
  ]);
  res.redirect("/admin/dose-requests");
});

app.post("/admin/dose-requests/:id/reject", requireRoleHtml(["admin", "superuser"]), async (req, res) => {
  const familyId = req.user.family_id;
  const requestId = Number(req.params.id);
  if (!Number.isFinite(requestId)) {
    return res.redirect("/admin/dose-requests");
  }
  await pool.query(
    `UPDATE dose_change_requests SET status = 'rejected'
     WHERE id = $1 AND family_id = $2 AND status = 'pending'`,
    [requestId, familyId]
  );
  res.redirect("/admin/dose-requests");
});

app.get("/admin/settings", requireRoleHtml(["admin", "superuser"]), (req, res) => {
  const emergency = req.query?.emergency === "1";
  const settingsMsg = req.query?.msg || "";
  const content = `
    ${settingsMsg === "snapshot_ok" ? '<div class="card" style="background:#dcfce7; border-color:#22c55e; margin-bottom:12px;"><p style="margin:0; font-size:14px;">✅ Snapshot creado correctamente.</p></div>' : ""}
    ${settingsMsg === "restored" ? '<div class="card" style="background:#dcfce7; border-color:#22c55e; margin-bottom:12px;"><p style="margin:0; font-size:14px;">✅ Base de datos restaurada correctamente desde backup.</p></div>' : ""}
    <style>
      .link-grid { display:grid; grid-template-columns:repeat(auto-fill, minmax(280px, 1fr)); gap:12px; margin-top:16px; }
      .link-card { display:flex; align-items:center; gap:12px; padding:14px 16px; border:1px solid var(--border); border-radius:14px; transition:all .15s; background:#fff; }
      .link-card:hover { border-color:var(--accent); box-shadow:0 4px 12px -6px rgba(37,99,235,.2); transform:translateY(-1px); }
      .link-icon { width:40px; height:40px; border-radius:10px; display:flex; align-items:center; justify-content:center; font-size:18px; flex-shrink:0; }
      .link-meta { flex:1; min-width:0; }
      .link-meta h3 { margin:0; font-size:14px; font-weight:600; }
      .link-meta p { margin:2px 0 0; font-size:11px; color:var(--muted); }
      .section-title { font-size:13px; font-weight:700; text-transform:uppercase; letter-spacing:.08em; color:var(--muted); margin:24px 0 8px; }
    </style>

    <!-- Links de Soporte y Plataformas -->
    <div class="card">
      <h1>🔗 Soporte y plataformas</h1>
      <p class="muted" style="font-size:13px; margin-top:6px;">Acceso rápido a todos los servicios del proyecto MediControl.</p>

      <div class="section-title">🚀 Despliegue y hosting</div>
      <div class="link-grid">
        <a class="link-card" href="https://vercel.com/medicamentos-webs-projects" target="_blank">
          <div class="link-icon" style="background:#000; color:#fff;">▲</div>
          <div class="link-meta">
            <h3>Vercel Dashboard</h3>
            <p>Frontend · Deployments · Logs · Analytics</p>
          </div>
        </a>
        <a class="link-card" href="https://medicamentos-frontend.vercel.app" target="_blank">
          <div class="link-icon" style="background:#10b981; color:#fff;">🌐</div>
          <div class="link-meta">
            <h3>App en producción</h3>
            <p>medicamentos-frontend.vercel.app</p>
          </div>
        </a>
        <a class="link-card" href="https://medicamentos-frontend.vercel.app/landing" target="_blank">
          <div class="link-icon" style="background:#6366f1; color:#fff;">📄</div>
          <div class="link-meta">
            <h3>Landing Page</h3>
            <p>Página de presentación multiidioma</p>
          </div>
        </a>
      </div>

      <div class="section-title">💻 Código fuente</div>
      <div class="link-grid">
        <a class="link-card" href="https://github.com/Medicamentos-web/medicamentos-frontend" target="_blank">
          <div class="link-icon" style="background:#24292e; color:#fff;">🐙</div>
          <div class="link-meta">
            <h3>GitHub — Frontend</h3>
            <p>Repositorio Next.js · Commits · PRs · Issues</p>
          </div>
        </a>
      </div>

      <div class="section-title">🛠️ Backend y base de datos</div>
      <div class="link-grid">
        <a class="link-card" href="/dashboard">
          <div class="link-icon" style="background:#2563eb; color:#fff;">🏠</div>
          <div class="link-meta">
            <h3>Panel Admin</h3>
            <p>Dashboard de administración del backend</p>
          </div>
        </a>
        <a class="link-card" href="/admin/import">
          <div class="link-icon" style="background:#f59e0b; color:#fff;">⬆</div>
          <div class="link-meta">
            <h3>Importar medicamentos</h3>
            <p>PDF · Imagen · OCR · Escaneo</p>
          </div>
        </a>
        <a class="link-card" href="/admin/import-scan">
          <div class="link-icon" style="background:#06b6d4; color:#fff;">📷</div>
          <div class="link-meta">
            <h3>Escanear imagen</h3>
            <p>OCR desde foto de etiqueta</p>
          </div>
        </a>
        <a class="link-card" href="/admin/meds-list">
          <div class="link-icon" style="background:#8b5cf6; color:#fff;">💊</div>
          <div class="link-meta">
            <h3>Lista de medicamentos</h3>
            <p>Ver y gestionar inventario</p>
          </div>
        </a>
        <a class="link-card" href="/admin/billing">
          <div class="link-icon" style="background:#ec4899; color:#fff;">💳</div>
          <div class="link-meta">
            <h3>Facturación</h3>
            <p>Planes · Suscripciones · Trial</p>
          </div>
        </a>
        <a class="link-card" href="/admin/reports">
          <div class="link-icon" style="background:#14b8a6; color:#fff;">📊</div>
          <div class="link-meta">
            <h3>Informes</h3>
            <p>Estadísticas de uso y adherencia</p>
          </div>
        </a>
        <a class="link-card" href="/admin/feedback">
          <div class="link-icon" style="background:#eab308; color:#fff;">⭐</div>
          <div class="link-meta">
            <h3>Feedback</h3>
            <p>Valoraciones de los usuarios</p>
          </div>
        </a>
        <a class="link-card" href="/admin/leads">
          <div class="link-icon" style="background:#f97316; color:#fff;">📩</div>
          <div class="link-meta">
            <h3>Leads</h3>
            <p>Registros desde landing page</p>
          </div>
        </a>
        <a class="link-card" href="/health" target="_blank">
          <div class="link-icon" style="background:#22c55e; color:#fff;">💚</div>
          <div class="link-meta">
            <h3>Health Check</h3>
            <p>Estado del backend y base de datos</p>
          </div>
        </a>
      </div>

      <div class="section-title">📱 App móvil</div>
      <div class="link-grid">
        <a class="link-card" href="https://medicamentos-frontend.vercel.app/promo" target="_blank">
          <div class="link-icon" style="background:#7c3aed; color:#fff;">🎬</div>
          <div class="link-meta">
            <h3>Video Promo</h3>
            <p>Página de grabación de pantalla</p>
          </div>
        </a>
        <a class="link-card" href="https://medicamentos-frontend.vercel.app/billing" target="_blank">
          <div class="link-icon" style="background:#dc2626; color:#fff;">💰</div>
          <div class="link-meta">
            <h3>Planes y precios</h3>
            <p>Vista del usuario de suscripciones</p>
          </div>
        </a>
      </div>
    </div>

    <!-- Backup / Snapshot / Restore -->
    <div class="card" style="margin-top:16px;">
      <h1>💾 Backup y restauración</h1>
      <p class="muted" style="font-size:13px; margin-top:6px;">Exporta un backup completo de la base de datos o restaura desde un archivo JSON.</p>

      <div style="display:flex; gap:10px; flex-wrap:wrap; margin-top:16px;">
        <a class="btn primary" href="/admin/backup/full" style="gap:6px;">⬇ Backup completo (JSON)</a>
        <a class="btn outline" href="/admin/backup/medicines" style="gap:6px;">💊 Solo medicamentos</a>
        <a class="btn outline" href="/admin/backup/schedules" style="gap:6px;">🕐 Solo horarios</a>
        <a class="btn outline" href="/admin/backup/users" style="gap:6px;">👤 Solo usuarios</a>
      </div>

      <div style="margin-top:20px; padding-top:16px; border-top:1px solid var(--border);">
        <h2 style="font-size:16px; margin:0 0 8px;">📸 Crear snapshot</h2>
        <p class="muted" style="font-size:12px;">Guarda el estado actual de la base de datos internamente. Puedes restaurar desde aquí si algo sale mal.</p>
        <form method="POST" action="/admin/backup/snapshot" style="margin-top:10px;">
          <input name="description" placeholder="Descripción (ej: Antes de importar nuevo PDF)" class="form-control" style="max-width:400px;" />
          <button class="btn primary" type="submit" style="margin-top:8px;">📸 Crear snapshot ahora</button>
        </form>
      </div>

      <div style="margin-top:20px; padding-top:16px; border-top:1px solid var(--border);">
        <h2 style="font-size:16px; margin:0 0 8px;">♻️ Restaurar desde archivo</h2>
        <p class="muted" style="font-size:12px;">Sube un archivo JSON de backup para restaurar la base de datos. ⚠️ Esto reemplazará los datos actuales.</p>
        <form method="POST" action="/admin/backup/restore" enctype="multipart/form-data" style="margin-top:10px;">
          <input name="file" type="file" accept=".json" class="form-control" style="max-width:400px;" />
          <label style="display:flex; align-items:center; gap:8px; margin-top:8px; font-size:12px;">
            <input type="checkbox" name="confirm" value="1" />
            Confirmo que quiero reemplazar los datos actuales
          </label>
          <button class="btn primary" type="submit" style="margin-top:8px; background:var(--danger);">♻️ Restaurar backup</button>
        </form>
      </div>

      <div style="margin-top:20px; padding-top:16px; border-top:1px solid var(--border);">
        <h2 style="font-size:16px; margin:0 0 8px;">📋 Snapshots guardados</h2>
        <a class="btn outline" href="/admin/backup/snapshots">Ver snapshots guardados</a>
      </div>
    </div>

    <!-- Ajustes avanzados -->
    <div class="card" style="margin-top:16px;">
      <h1>⚙ Ajustes avanzados</h1>
      <p class="muted" style="font-size:13px; margin-top:6px;">Opciones avanzadas desactivadas por defecto.</p>
      <form method="GET" action="/admin/settings">
        <label style="display:flex; align-items:center; gap:10px; margin-top:12px; font-size:13px;">
          <input type="checkbox" name="emergency" value="1" ${emergency ? "checked" : ""} />
          Habilitar modo emergencia (ver logs de borrado)
        </label>
        <button class="btn outline" type="submit" style="margin-top:10px;">✅ Aplicar</button>
      </form>
      <p class="muted" style="font-size:13px; margin-top:6px;">Por seguridad, los logs de borrado se muestran solo en emergencias.</p>
      <div style="margin-top:16px; display:flex; gap:10px; flex-wrap:wrap;">
        <a class="btn ${emergency ? "primary" : "outline"} ${emergency ? "" : "disabled"}" href="/admin/logs">📜 Mirar logs</a>
      </div>
    </div>
  `;
  res.send(renderShell(req, "Ajustes", "settings", content));
});

// =============================================================================
// BACKUP / SNAPSHOT / RESTORE
// =============================================================================

const BACKUP_TABLES = [
  "families", "users", "medicines", "schedules", "dose_logs", "alerts",
  "import_batches", "deletion_logs", "medical_records", "dose_change_requests",
  "feedback", "leads", "doctors", "family_doctors", "push_subscriptions",
  "medicine_audits", "weekly_reminders", "daily_checkouts", "password_resets",
];

async function exportTables(familyId, tableNames) {
  const data = { _meta: { version: 1, exported_at: new Date().toISOString(), family_id: familyId } };
  for (const table of tableNames) {
    try {
      const hasFamilyId = (await pool.query(
        `SELECT column_name FROM information_schema.columns WHERE table_name = $1 AND column_name = 'family_id'`, [table]
      )).rows.length > 0;
      const result = hasFamilyId
        ? await pool.query(`SELECT * FROM ${table} WHERE family_id = $1 ORDER BY id`, [familyId])
        : await pool.query(`SELECT * FROM ${table} ORDER BY id`);
      data[table] = result.rows;
    } catch (err) {
      data[table] = { error: err.message };
    }
  }
  return data;
}

// Full backup (JSON download)
app.get("/admin/backup/full", requireRoleHtml(["admin", "superuser"]), async (req, res) => {
  try {
    const familyId = req.user.family_id;
    const data = await exportTables(familyId, BACKUP_TABLES);
    const filename = `medicontrol_backup_${familyId}_${new Date().toISOString().slice(0, 10)}.json`;
    res.setHeader("Content-Disposition", `attachment; filename="${filename}"`);
    res.setHeader("Content-Type", "application/json");
    res.send(JSON.stringify(data, null, 2));
  } catch (err) {
    res.status(500).send(renderShell(req, "Error", "settings", `<div class="card"><h1>Error</h1><p>${escapeHtml(err.message)}</p><a class="btn outline" href="/admin/settings">Volver</a></div>`));
  }
});

// Partial backups
app.get("/admin/backup/medicines", requireRoleHtml(["admin", "superuser"]), async (req, res) => {
  try {
    const familyId = req.user.family_id;
    const data = await exportTables(familyId, ["medicines", "schedules", "dose_logs"]);
    const filename = `medicontrol_medicines_${familyId}_${new Date().toISOString().slice(0, 10)}.json`;
    res.setHeader("Content-Disposition", `attachment; filename="${filename}"`);
    res.setHeader("Content-Type", "application/json");
    res.send(JSON.stringify(data, null, 2));
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get("/admin/backup/schedules", requireRoleHtml(["admin", "superuser"]), async (req, res) => {
  try {
    const familyId = req.user.family_id;
    const data = await exportTables(familyId, ["schedules", "dose_logs"]);
    const filename = `medicontrol_schedules_${familyId}_${new Date().toISOString().slice(0, 10)}.json`;
    res.setHeader("Content-Disposition", `attachment; filename="${filename}"`);
    res.setHeader("Content-Type", "application/json");
    res.send(JSON.stringify(data, null, 2));
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get("/admin/backup/users", requireRoleHtml(["admin", "superuser"]), async (req, res) => {
  try {
    const familyId = req.user.family_id;
    const data = await exportTables(familyId, ["users", "doctors", "family_doctors"]);
    const filename = `medicontrol_users_${familyId}_${new Date().toISOString().slice(0, 10)}.json`;
    res.setHeader("Content-Disposition", `attachment; filename="${filename}"`);
    res.setHeader("Content-Type", "application/json");
    res.send(JSON.stringify(data, null, 2));
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Snapshot: save current state internally
app.post("/admin/backup/snapshot", requireRoleHtml(["admin", "superuser"]), async (req, res) => {
  try {
    const familyId = req.user.family_id;
    const description = (req.body?.description || "").trim() || "Snapshot manual";
    const data = await exportTables(familyId, BACKUP_TABLES);
    await pool.query(`CREATE TABLE IF NOT EXISTS db_snapshots (
      id SERIAL PRIMARY KEY, family_id INTEGER NOT NULL, description TEXT,
      snapshot JSONB NOT NULL, created_by INTEGER, created_at TIMESTAMPTZ DEFAULT NOW()
    )`);
    await pool.query(
      `INSERT INTO db_snapshots (family_id, description, snapshot, created_by) VALUES ($1, $2, $3, $4)`,
      [familyId, description, JSON.stringify(data), req.user.sub]
    );
    res.redirect("/admin/settings?msg=snapshot_ok");
  } catch (err) {
    res.status(500).send(renderShell(req, "Error", "settings", `<div class="card"><h1>Error al crear snapshot</h1><p>${escapeHtml(err.message)}</p><a class="btn outline" href="/admin/settings">Volver</a></div>`));
  }
});

// List snapshots
app.get("/admin/backup/snapshots", requireRoleHtml(["admin", "superuser"]), async (req, res) => {
  try {
    const familyId = req.user.family_id;
    await pool.query(`CREATE TABLE IF NOT EXISTS db_snapshots (
      id SERIAL PRIMARY KEY, family_id INTEGER NOT NULL, description TEXT,
      snapshot JSONB NOT NULL, created_by INTEGER, created_at TIMESTAMPTZ DEFAULT NOW()
    )`);
    const snapshots = await pool.query(
      `SELECT s.id, s.description, s.created_at, u.name AS created_by_name
       FROM db_snapshots s LEFT JOIN users u ON u.id = s.created_by
       WHERE s.family_id = $1 ORDER BY s.created_at DESC LIMIT 50`,
      [familyId]
    );
    const content = `
      <div class="card">
        <h1>📋 Snapshots guardados</h1>
        <p class="muted" style="font-size:13px;">Restaura cualquier snapshot para volver a un estado anterior.</p>
        ${snapshots.rows.length === 0 ? '<p class="empty" style="margin-top:16px;">No hay snapshots guardados.</p>' : `
        <div style="margin-top:16px; overflow:auto;">
          <table class="table">
            <thead><tr><th>ID</th><th>Descripción</th><th>Creado por</th><th>Fecha</th><th>Acciones</th></tr></thead>
            <tbody>
            ${snapshots.rows.map(s => `<tr>
              <td>${s.id}</td>
              <td>${escapeHtml(s.description || "-")}</td>
              <td>${escapeHtml(s.created_by_name || "-")}</td>
              <td>${new Date(s.created_at).toLocaleString("de-CH")}</td>
              <td style="display:flex; gap:6px;">
                <a class="btn outline" href="/admin/backup/snapshot-download/${s.id}" style="font-size:11px;">⬇ Descargar</a>
                <form method="POST" action="/admin/backup/snapshot-restore/${s.id}" onsubmit="return confirm('¿Restaurar este snapshot? Se reemplazarán los datos actuales.')">
                  <button class="btn outline" type="submit" style="font-size:11px; color:var(--danger);">♻️ Restaurar</button>
                </form>
              </td>
            </tr>`).join("")}
            </tbody>
          </table>
        </div>`}
        <div style="margin-top:16px;"><a class="btn outline" href="/admin/settings">← Volver a ajustes</a></div>
      </div>`;
    res.send(renderShell(req, "Snapshots", "settings", content));
  } catch (err) {
    res.status(500).send(renderShell(req, "Error", "settings", `<div class="card"><h1>Error</h1><p>${escapeHtml(err.message)}</p></div>`));
  }
});

// Download a snapshot
app.get("/admin/backup/snapshot-download/:id", requireRoleHtml(["admin", "superuser"]), async (req, res) => {
  try {
    const familyId = req.user.family_id;
    const snap = await pool.query(`SELECT snapshot, description FROM db_snapshots WHERE id = $1 AND family_id = $2`, [req.params.id, familyId]);
    if (!snap.rows.length) return res.status(404).send("Snapshot no encontrado");
    const filename = `medicontrol_snapshot_${req.params.id}_${new Date().toISOString().slice(0, 10)}.json`;
    res.setHeader("Content-Disposition", `attachment; filename="${filename}"`);
    res.setHeader("Content-Type", "application/json");
    res.send(JSON.stringify(snap.rows[0].snapshot, null, 2));
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Restore from snapshot
app.post("/admin/backup/snapshot-restore/:id", requireRoleHtml(["admin", "superuser"]), async (req, res) => {
  const client = await pool.connect();
  try {
    const familyId = req.user.family_id;
    const snap = await client.query(`SELECT snapshot FROM db_snapshots WHERE id = $1 AND family_id = $2`, [req.params.id, familyId]);
    if (!snap.rows.length) return res.status(404).send("Snapshot no encontrado");
    const data = typeof snap.rows[0].snapshot === "string" ? JSON.parse(snap.rows[0].snapshot) : snap.rows[0].snapshot;
    await restoreFromBackup(client, familyId, data);
    res.redirect("/admin/backup/snapshots?msg=restored");
  } catch (err) {
    res.status(500).send(renderShell(req, "Error", "settings", `<div class="card"><h1>Error al restaurar</h1><p>${escapeHtml(err.message)}</p><a class="btn outline" href="/admin/backup/snapshots">Volver</a></div>`));
  } finally {
    client.release();
  }
});

// Restore from uploaded JSON file
app.post("/admin/backup/restore", requireRoleHtml(["admin", "superuser"]), upload.single("file"), async (req, res) => {
  const client = await pool.connect();
  try {
    if (req.body?.confirm !== "1") throw new Error("Debes confirmar la restauración.");
    if (!req.file) throw new Error("No se recibió archivo.");
    const raw = fs.readFileSync(req.file.path, "utf-8");
    const data = JSON.parse(raw);
    const familyId = req.user.family_id;
    await restoreFromBackup(client, familyId, data);
    try { fs.unlinkSync(req.file.path); } catch {}
    res.redirect("/admin/settings?msg=restored");
  } catch (err) {
    res.status(500).send(renderShell(req, "Error", "settings", `<div class="card"><h1>Error al restaurar</h1><p>${escapeHtml(err.message)}</p><a class="btn outline" href="/admin/settings">Volver</a></div>`));
  } finally {
    client.release();
  }
});

async function restoreFromBackup(client, familyId, data) {
  await client.query("BEGIN");
  try {
    // Delete in dependency order
    await client.query(`DELETE FROM dose_logs WHERE schedule_id IN (SELECT s.id FROM schedules s JOIN medicines m ON m.id = s.medicine_id WHERE m.family_id = $1)`, [familyId]);
    await client.query(`DELETE FROM schedules WHERE medicine_id IN (SELECT id FROM medicines WHERE family_id = $1)`, [familyId]);
    await client.query(`DELETE FROM alerts WHERE family_id = $1`, [familyId]);
    await client.query(`DELETE FROM dose_change_requests WHERE family_id = $1`, [familyId]);
    await client.query(`DELETE FROM medicine_audits WHERE family_id = $1`, [familyId]);
    await client.query(`DELETE FROM medicines WHERE family_id = $1`, [familyId]);

    // Restore medicines
    const idMap = {};
    if (data.medicines && Array.isArray(data.medicines)) {
      for (const m of data.medicines) {
        const r = await client.query(
          `INSERT INTO medicines (family_id, user_id, name, dosage, current_stock, expiration_date, stock_depleted)
           VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING id`,
          [familyId, m.user_id || null, m.name, m.dosage || "N/A", m.current_stock || 0, m.expiration_date || null, m.stock_depleted || false]
        );
        idMap[m.id] = r.rows[0].id;
      }
    }

    // Restore schedules
    const schedMap = {};
    if (data.schedules && Array.isArray(data.schedules)) {
      for (const s of data.schedules) {
        const newMedId = idMap[s.medicine_id] || s.medicine_id;
        const r = await client.query(
          `INSERT INTO schedules (medicine_id, user_id, dose_time, frequency, days_of_week, start_date, end_date)
           VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING id`,
          [newMedId, s.user_id, s.dose_time, s.frequency || "1", s.days_of_week || "1234567", s.start_date || null, s.end_date || null]
        );
        schedMap[s.id] = r.rows[0].id;
      }
    }

    // Restore dose_logs
    if (data.dose_logs && Array.isArray(data.dose_logs)) {
      for (const d of data.dose_logs) {
        const newSchedId = schedMap[d.schedule_id] || d.schedule_id;
        await client.query(
          `INSERT INTO dose_logs (schedule_id, taken_at, status) VALUES ($1, $2, $3)`,
          [newSchedId, d.taken_at, d.status]
        );
      }
    }

    // Restore alerts
    if (data.alerts && Array.isArray(data.alerts)) {
      for (const a of data.alerts) {
        await client.query(
          `INSERT INTO alerts (family_id, user_id, type, level, message, med_name, med_dosage, dose_time, alert_date, schedule_id, read_at)
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`,
          [familyId, a.user_id || null, a.type, a.level || "info", a.message || "", a.med_name || null, a.med_dosage || null, a.dose_time || null, a.alert_date || null, a.schedule_id || null, a.read_at || null]
        );
      }
    }

    await client.query("COMMIT");
  } catch (err) {
    await client.query("ROLLBACK");
    throw err;
  }
}

app.get("/admin/logs", requireRoleHtml(["admin", "superuser"]), async (req, res) => {
  const familyId = req.user.family_id;
  const userId = Number(req.query?.user_id || 0);
  const from = String(req.query?.from || "").trim();
  const to = String(req.query?.to || "").trim();
  const users = await pool.query(
    `SELECT id, name, email FROM users WHERE family_id = $1 ORDER BY name ASC`,
    [familyId]
  );
  const params = [familyId];
  let where = "WHERE l.family_id = $1";
  if (userId) {
    params.push(userId);
    where += ` AND l.user_id = $${params.length}`;
  }
  if (from) {
    params.push(from);
    where += ` AND l.deleted_at >= $${params.length}::timestamptz`;
  }
  if (to) {
    params.push(to);
    where += ` AND l.deleted_at <= $${params.length}::timestamptz`;
  }
  const logs = await pool.query(
    `SELECT l.id, l.user_id, l.deleted_count, l.deleted_at, u.name AS user_name, u.email AS user_email
     FROM deletion_logs l
     LEFT JOIN users u ON u.id = l.user_id
     ${where}
     ORDER BY l.deleted_at DESC
     LIMIT 100`,
    params
  );
  const content = `
    <div class="card">
      <h1>Logs de borrado</h1>
      <form method="GET" action="/admin/logs" class="actions" style="margin-top:12px;">
        <select name="user_id" class="form-control" style="max-width:260px;">
          <option value="">Todos los usuarios</option>
          ${
            users.rows
              .map(
                (u) =>
                  `<option value="${u.id}" ${u.id === userId ? "selected" : ""}>${escapeHtml(
                    u.name
                  )} · ${escapeHtml(u.email)}</option>`
              )
              .join("")
          }
        </select>
        <input class="form-control" name="from" placeholder="Desde (YYYY-MM-DD)" value="${escapeHtml(from)}" style="max-width:200px;" />
        <input class="form-control" name="to" placeholder="Hasta (YYYY-MM-DD)" value="${escapeHtml(to)}" style="max-width:200px;" />
        <button class="btn outline" type="submit">Buscar</button>
      </form>
      <p class="muted" style="margin-top:10px; font-size:12px;">
        Restaurar reemplaza la medicación actual del paciente por el snapshot.
      </p>
      <div style="margin-top:12px; overflow:auto;">
        <table class="table">
          <thead>
            <tr>
              <th>ID</th>
              <th>Paciente</th>
              <th>Borrados</th>
              <th>Fecha</th>
              <th>Acciones</th>
            </tr>
          </thead>
          <tbody>
            ${
              logs.rows.length
                ? logs.rows
                    .map(
                      (row) => `
            <tr>
              <td>${row.id}</td>
              <td>${
                row.user_name
                  ? `${escapeHtml(row.user_name)} · ${escapeHtml(row.user_email || "")}`
                  : "-"
              }</td>
              <td>${row.deleted_count}</td>
              <td>${formatDateTime(row.deleted_at)}</td>
              <td>
                ${
                  row.user_id
                    ? `<form method="POST" action="/admin/logs/restore" style="margin:0;">
                         <input type="hidden" name="log_id" value="${row.id}" />
                         <button class="btn outline" type="submit">Reimportar</button>
                       </form>`
                    : ""
                }
              </td>
            </tr>`
                    )
                    .join("")
                : `<tr><td colspan="5" style="padding:12px; color:var(--muted);">Sin logs</td></tr>`
            }
          </tbody>
        </table>
      </div>
    </div>
  `;
  res.send(renderShell(req, "Logs de borrado", "settings", content));
});

app.post("/admin/logs/restore", requireRoleHtml(["admin", "superuser"]), async (req, res) => {
  const familyId = req.user.family_id;
  const logId = Number(req.body?.log_id);
  if (!Number.isFinite(logId)) {
    return res.redirect("/admin/logs");
  }
  const logResult = await pool.query(
    `SELECT id, user_id, snapshot
     FROM deletion_logs
     WHERE id = $1 AND family_id = $2`,
    [logId, familyId]
  );
  if (!logResult.rows.length || !logResult.rows[0].user_id) {
    return res.redirect("/admin/logs");
  }
  const userId = Number(logResult.rows[0].user_id);
  const snapshot = Array.isArray(logResult.rows[0].snapshot)
    ? logResult.rows[0].snapshot
    : [];
  await pool.query(
    `DELETE FROM dose_logs
     WHERE schedule_id IN (SELECT id FROM schedules WHERE user_id = $1)`,
    [userId]
  );
  await pool.query(`DELETE FROM schedules WHERE user_id = $1`, [userId]);
  await pool.query(`DELETE FROM medicines WHERE family_id = $1 AND user_id = $2`, [
    familyId,
    userId,
  ]);
  for (const med of snapshot) {
    await pool.query(
      `INSERT INTO medicines (family_id, user_id, name, dosage, current_stock, expiration_date, import_batch_id)
       VALUES ($1, $2, $3, $4, $5, $6, $7)`,
      [
        familyId,
        userId,
        med.name || "Medicamento",
        med.dosage || "N/A",
        Number(med.current_stock || 0),
        med.expiration_date || null,
        med.import_batch_id || null,
      ]
    );
  }
  return res.redirect(`/admin/meds-list?reset=1&deleted=0&user_id=${userId}`);
});

app.post("/admin/alerts/clear", requireRoleHtml(["admin", "superuser"]), async (req, res) => {
  const familyId = req.user.family_id;
  const rawUserId = String(req.body?.user_id || "").trim();
  const userId = Number(rawUserId);
  if (rawUserId && Number.isFinite(userId) && userId > 0) {
    await pool.query(`DELETE FROM alerts WHERE family_id = $1 AND user_id = $2`, [
      familyId,
      userId,
    ]);
  } else {
    await pool.query(`DELETE FROM alerts WHERE family_id = $1`, [familyId]);
  }
  res.redirect("/admin/alerts");
});

app.get("/admin/reminders/run", requireRoleHtml(["admin", "superuser"]), async (req, res) => {
  const familyId = req.user.family_id;
  const now = new Date();
  const weekStart = new Date(now);
  weekStart.setDate(now.getDate() - ((now.getDay() + 6) % 7));
  weekStart.setHours(0, 0, 0, 0);
  const isoWeek = weekStart.toISOString().slice(0, 10);

  const existing = await pool.query(
    `SELECT id FROM weekly_reminders WHERE family_id = $1 AND week_start = $2::date`,
    [familyId, isoWeek]
  );
  if (existing.rows.length === 0) {
    await pool.query(
      `INSERT INTO weekly_reminders (family_id, week_start) VALUES ($1, $2::date)`,
      [familyId, isoWeek]
    );
    await pool.query(
      `INSERT INTO alerts (family_id, type, level, message, alert_date)
       VALUES ($1, 'weekly_review', 'info', $2, $3)`,
      [familyId, "Revisión semanal de stock y caducidades recomendada.", isoWeek]
    );
    await sendAdminAlertEmail(
      "Recordatorio semanal",
      "<p>Revisión semanal de stock y caducidades recomendada.</p>"
    );
  }
  res.redirect("/admin/alerts");
});

app.get("/admin/import", requireRoleHtml(["admin", "superuser"]), async (req, res) => {
  const users = await pool.query(
    `SELECT id, name, email FROM users WHERE family_id = $1 ORDER BY name ASC`,
    [req.user.family_id]
  );
  const resetDeleted = Number(req.query?.deleted || 0);
  const showReset = req.query?.reset === "1";
  const content = `
    <style>
      header { padding:20px; background:linear-gradient(120deg,#0f172a 0%, #1d4ed8 60%, #14b8a6 100%); color:#fff; border-radius:16px; }
      header .wrap { display:flex; align-items:center; justify-content:space-between; }
      header h1 { margin:0; font-size:20px; }
      header p { margin:6px 0 0; font-size:12px; opacity:.8; }
      .wrap { max-width:900px; }
      .card { background:#fff; border-radius:22px; padding:24px; box-shadow:0 24px 48px -30px rgba(15,23,42,.4); margin-top:18px; border:1px solid var(--border); }
      label { display:block; font-size:13px; color:#64748b; margin-top:12px; }
      input { width:100%; border:1px solid #e2e8f0; border-radius:14px; padding:12px 14px; margin-top:6px; }
      button { width:100%; margin-top:18px; background:#2563eb; color:#fff; border:0; border-radius:14px; padding:12px 14px; font-weight:600; }
      .note { font-size:12px; color:#64748b; margin-top:8px; }
      .danger { background:#ef4444; }
      .row { display:grid; grid-template-columns:1fr 1fr; gap:16px; }
    </style>
    <div class="wrap">
      <header>
        <div class="wrap">
          <div>
            <h1>Importación de medicamentos</h1>
            <p>Sube la receta y genera tomas automáticamente.</p>
          </div>
          <div>Familia #${req.user.family_id}</div>
        </div>
      </header>
      ${
        showReset
          ? `<div class="card">
               <h1>Reset completado</h1>
               <p>Se borraron ${Number.isFinite(resetDeleted) ? resetDeleted : 0} medicamentos.</p>
             </div>`
          : ""
      }
      <div class="card">
        <h1>Importar desde PDF</h1>
        <form method="POST" action="/admin/import" enctype="multipart/form-data">
          <label>Archivo PDF (desde tu PC)</label>
          <input name="file" type="file" accept=".pdf" />
          <label>Ruta del archivo (dentro del contenedor)</label>
          <input name="file_path" value="" />
          <div class="row">
            <div>
              <label>Paciente</label>
              <select name="user_id" style="width:100%; border:1px solid #e2e8f0; border-radius:14px; padding:12px 14px; margin-top:6px;">
                ${
                  users.rows.length
                    ? users.rows
                        .map(
                          (u) =>
                            `<option value="${u.id}" ${
                              u.id === req.user.sub ? "selected" : ""
                            }>${escapeHtml(u.name)} · ${escapeHtml(u.email)}</option>`
                        )
                        .join("")
                    : `<option value="">Sin usuarios</option>`
                }
              </select>
            </div>
            <div>
              <label>Modo OCR (recomendado para PDFs escaneados)</label>
              <input name="use_ocr" type="checkbox" value="1" checked />
            </div>
            <div>
              <label>Omitir verificación de nombre</label>
              <input name="skip_name_check" type="checkbox" value="1" />
            </div>
          </div>
          <button type="submit">⬆ Importar</button>
        </form>
        <p class="note">Los horarios se asignan a 08:00 / 14:00 / 20:00 / 22:00 según columnas Mo/Mi/Ab/Na.</p>
        <p class="note">Si subes archivo, la ruta interna no es necesaria.</p>
        <p class="note"><a href="/admin/import-scan">📷 Escanear desde foto (imagen)</a></p>
      </div>
      <div class="card">
        <h1>Reset de medicación</h1>
        <p class="note">Borra TODOS los medicamentos del paciente seleccionado. Esta acción es irreversible.</p>
        <form method="POST" action="/admin/meds-reset">
          <label>Paciente</label>
          <select name="user_id" style="width:100%; border:1px solid #e2e8f0; border-radius:14px; padding:12px 14px; margin-top:6px;">
            ${
              users.rows.length
                ? users.rows
                    .map(
                      (u) =>
                        `<option value="${u.id}" ${
                          u.id === req.user.sub ? "selected" : ""
                        }>${escapeHtml(u.name)} · ${escapeHtml(u.email)}</option>`
                    )
                    .join("")
                : `<option value="">Sin usuarios</option>`
            }
          </select>
          <label>Escribe RESET para confirmar</label>
          <input name="confirm" placeholder="RESET" required />
          <button class="danger" type="submit">🧹 Borrar medicamentos</button>
        </form>
      </div>
      <div class="card">
        <h1>Reset global (toda la familia)</h1>
        <p class="note">Borra TODOS los medicamentos, schedules, tomas y alertas de la familia. Esta acción es irreversible.</p>
        <form method="POST" action="/admin/meds-reset-all">
          <label>Escribe RESET-TODO para confirmar</label>
          <input name="confirm" placeholder="RESET-TODO" required />
          <button class="danger" type="submit">🧹 Borrar todo</button>
        </form>
      </div>
    </div>
  `;
  res.send(renderShell(req, "Importar medicamentos", "imports", content));
});

app.get("/admin/import-scan", requireRoleHtml(["admin", "superuser"]), async (req, res) => {
  const users = await pool.query(
    `SELECT id, name, email FROM users WHERE family_id = $1 ORDER BY name ASC`,
    [req.user.family_id]
  );
  const content = `
    <style>
      header { padding:20px; background:linear-gradient(120deg,#0f172a 0%, #1d4ed8 60%, #14b8a6 100%); color:#fff; border-radius:16px; }
      header .wrap { display:flex; align-items:center; justify-content:space-between; }
      header h1 { margin:0; font-size:20px; }
      header p { margin:6px 0 0; font-size:12px; opacity:.8; }
      .wrap { max-width:900px; }
      .card { background:#fff; border-radius:22px; padding:24px; box-shadow:0 24px 48px -30px rgba(15,23,42,.4); margin-top:18px; border:1px solid var(--border); }
      label { display:block; font-size:13px; color:#64748b; margin-top:12px; }
      input, select { width:100%; border:1px solid #e2e8f0; border-radius:14px; padding:12px 14px; margin-top:6px; }
      button { width:100%; margin-top:18px; background:#2563eb; color:#fff; border:0; border-radius:14px; padding:12px 14px; font-weight:600; }
      .note { font-size:12px; color:#64748b; margin-top:8px; }
      .row { display:grid; grid-template-columns:1fr 1fr; gap:16px; }
    </style>
    <div class="wrap">
      <header>
        <div class="wrap">
          <div>
            <h1>Escanear desde imagen</h1>
            <p>Sube una foto o escaneo del medicamento.</p>
          </div>
          <div>Familia #${req.user.family_id}</div>
        </div>
      </header>
      <div class="card">
        <h1>Importar desde imagen</h1>
        <form method="POST" action="/admin/import-scan" enctype="multipart/form-data">
          <label>Imagen (JPG/PNG)</label>
          <input name="file" type="file" accept="image/*" />
          <label>Paciente</label>
          <select name="user_id">
            ${
              users.rows.length
                ? users.rows
                    .map(
                      (u) =>
                        `<option value="${u.id}" ${
                          u.id === req.user.sub ? "selected" : ""
                        }>${escapeHtml(u.name)} · ${escapeHtml(u.email)}</option>`
                    )
                    .join("")
                : `<option value="">Sin usuarios</option>`
            }
          </select>
          <div class="row">
            <div>
              <label>Fecha de nacimiento (DD.MM.AAAA)</label>
              <input name="birth_date" placeholder="02.02.2026" />
            </div>
            <div>
              <label>OCR rápido</label>
              <input name="fast_ocr" type="checkbox" value="1" checked />
            </div>
            <div>
              <label>Omitir verificación de nombre (solo test)</label>
              <input name="skip_name_check" type="checkbox" value="1" />
            </div>
            <div>
              <label>Solo previsualizar (no guardar)</label>
              <input name="preview_only" type="checkbox" value="1" />
            </div>
          </div>
          <button type="submit">🧾 Procesar imagen</button>
        </form>
        <p class="note">Si falla el nombre, puedes probar con la fecha de nacimiento.</p>
      </div>
    </div>
  `;
  res.send(renderShell(req, "Escanear desde imagen", "imports", content));
});

app.post(
  "/admin/import-scan",
  requireRoleHtml(["admin", "superuser"]),
  upload.single("file"),
  async (req, res) => {
    const familyId = req.user.family_id;
    const userId = Number(req.body?.user_id || req.user.sub);
    const skipNameCheck = req.body?.skip_name_check === "1";
    const previewOnly = req.body?.preview_only === "1";
    const fastOcr = req.body?.fast_ocr !== "0";
    const birthDate = normalizeDateOnly(req.body?.birth_date);
    if (!familyId || !Number.isFinite(userId) || !req.file?.path) {
      return res.redirect("/admin/import-scan");
    }
    try {
      const userResult = await pool.query(
        `SELECT id, name, first_name, last_name, birth_date FROM users WHERE id = $1 AND family_id = $2`,
        [userId, familyId]
      );
      const user = userResult.rows[0];
      const text = fastOcr
        ? await runOcrOnImage(req.file.path, { lang: "deu+eng", psm: "6", oem: "1" })
        : await runOcrOnImageBest(req.file.path);
      const rawLines = (text || "")
        .split(/\r?\n/)
        .map((line) => line.trim())
        .filter((line) => line.length > 2);
      const lines = filterOcrLines(rawLines);
      const detectedText = filterOcrLinesForDisplay(rawLines).join("\n").slice(0, 300);
      const nameCandidate = extractMedicineName(lines);
      const dosage = extractDosage(lines);
      const qtyMatch = text.match(/(\d+)\s*(Stk|Tbl|Kapsel|Caps|Pcs|ml)\b/i);
      const qty = qtyMatch ? Number(qtyMatch[1]) : 0;
      let validatedByBirthDate = false;
      if (!skipNameCheck && (!user || !patientNameMatches(text, user))) {
        if (birthDate && user?.birth_date) {
          validatedByBirthDate = normalizeDateOnly(user.birth_date) === birthDate;
        }
        if (!validatedByBirthDate) {
          const content = `
            <div class="card">
              <h1>Nombre del paciente no coincide</h1>
              <p>Texto detectado:</p>
              <pre style="white-space:pre-wrap; background:#F8FAFC; border:1px solid var(--border); padding:12px; border-radius:12px;">${escapeHtml(
                detectedText || "Sin texto"
              )}</pre>
              <div style="margin-top:12px;">
                <a class="btn outline" href="/admin/import-scan">Volver</a>
              </div>
            </div>
          `;
          return res.send(renderShell(req, "Validación OCR", "imports", content));
        }
      }
      let medResult = null;
      if (!previewOnly) {
        medResult = await upsertMedicineForUser({
          familyId,
          userId,
          name: nameCandidate,
          dosage,
          qty,
          expiryDate: null,
          batchId: null,
        });
      }
      const content = `
        <div class="card">
          <h1>${previewOnly ? "Previsualización" : "Importación completada"}</h1>
          <p><strong>Nombre:</strong> ${escapeHtml(nameCandidate)}</p>
          <p><strong>Dosis:</strong> ${escapeHtml(dosage)}</p>
          <p><strong>Cantidad:</strong> ${qty}</p>
          ${medResult ? `<p><strong>Acción:</strong> ${medResult.action}</p>` : ""}
          <p><strong>Texto detectado:</strong></p>
          <pre style="white-space:pre-wrap; background:#F8FAFC; border:1px solid var(--border); padding:12px; border-radius:12px;">${escapeHtml(
            detectedText || "Sin texto"
          )}</pre>
          <div style="margin-top:12px;">
            <a class="btn outline" href="/admin/import-scan">Volver</a>
          </div>
        </div>
      `;
      return res.send(renderShell(req, "Importación desde imagen", "imports", content));
    } catch (error) {
      const content = `
        <div class="card">
          <h1>Error al procesar</h1>
          <p class="muted">${escapeHtml(error.message)}</p>
          <div style="margin-top:12px;">
            <a class="btn outline" href="/admin/import-scan">Volver</a>
          </div>
        </div>
      `;
      return res.send(renderShell(req, "Error OCR", "imports", content));
    }
  }
);

app.post(
  "/admin/import",
  requireRoleHtml(["admin", "superuser"]),
  upload.single("file"),
  async (req, res) => {
  const familyId = req.user.family_id;
  const filePath = req.file?.path || req.body?.file_path;
  const userId = Number(req.body?.user_id || req.user.sub);
  const useOcr = req.body?.use_ocr === "1";
  const skipNameCheck = req.body?.skip_name_check === "1";
  if (!filePath || !userId) {
    return res.redirect("/admin/import");
  }
  try {
    const result = await importMedsFromPdf(
      filePath,
      familyId,
      userId,
      useOcr,
      skipNameCheck
    );
    const debugSection = result.inserted === 0 ? `
      <div style="margin-top:16px; background:#fef3c7; border:1px solid #f59e0b; border-radius:14px; padding:16px;">
        <h3 style="margin:0 0 8px; font-size:14px; color:#92400e;">No se encontraron medicamentos</h3>
        <p style="font-size:12px; color:#78350f; margin-bottom:8px;">
          OCR utilizado: ${result.ocrUsed ? "Sí" : "No"} · Líneas procesadas: ${result.linesProcessed || 0}
        </p>
        <p style="font-size:11px; color:#92400e; margin-bottom:4px;">Texto extraído del PDF (primeros 2000 caracteres):</p>
        <pre style="background:#fffbeb; border:1px solid #fbbf24; border-radius:8px; padding:10px; font-size:11px; max-height:300px; overflow:auto; white-space:pre-wrap; word-break:break-all;">${escapeHtml(result.rawText || "(vacío)")}</pre>
        <p style="font-size:11px; color:#78350f; margin-top:8px;">
          <strong>Sugerencias:</strong> Si el texto está vacío, el PDF probablemente es una imagen escaneada — marca "Modo OCR" y reintenta. 
          Si hay texto pero 0 medicamentos, el formato del PDF no coincide con el parser esperado (columnas Mo/Mi/Ab/Na con "auf weiteres").
        </p>
      </div>` : "";
    const content = `
      <div class="card">
        <h1>Importación completa</h1>
        <p><span style="display:inline-block; background:${result.inserted > 0 ? "#111827" : "#dc2626"}; color:#fff; padding:6px 12px; border-radius:999px; font-size:12px;">${result.inserted} medicamentos</span></p>
        <p>Advertencias: ${result.warnings}</p>
        ${debugSection}
        <div style="margin-top:12px; display:flex; gap:10px; flex-wrap:wrap;">
          <a class="btn outline" href="/admin/meds-list?review=1">Revisar posibles errores</a>
          <a class="btn outline" href="/admin/import">Reintentar</a>
          <a class="btn outline" href="/dashboard">Volver</a>
        </div>
      </div>
    `;
    res.send(renderShell(req, "Importación completa", "imports", content));
  } catch (error) {
    const content = `
      <div class="card">
        <h1>Error al importar</h1>
        <p class="muted">${escapeHtml(error.message)}</p>
        <div style="margin-top:12px;">
          <a class="btn outline" href="/admin/import">Volver</a>
        </div>
      </div>
    `;
    res.send(renderShell(req, "Error importación", "imports", content));
  }
});

app.post(
  "/api/import-scan-validate",
  requireRole(["admin", "superuser", "user"]),
  upload.single("file"),
  async (req, res) => {
    const familyId = getFamilyId(req);
    const userId = Number(req.body?.user_id);
    const skipNameCheck = req.body?.skip_name_check === "1";
    const debugOcr = req.body?.debug_ocr === "1";
    const fastOcr = req.body?.fast_ocr !== "0";
    const birthDate = normalizeDateOnly(req.body?.birth_date);
    if (!familyId || !Number.isFinite(userId) || !req.file?.path) {
      return res.status(400).json({ error: "family_id, user_id y file son requeridos" });
    }
    try {
      if (skipNameCheck) {
        return res.json({ ok: true, match: true });
      }
      const userResult = await pool.query(
        `SELECT id, name, first_name, last_name, birth_date FROM users WHERE id = $1 AND family_id = $2`,
        [userId, familyId]
      );
      const user = userResult.rows[0];
      const text = fastOcr
        ? await runOcrOnImage(req.file.path, { lang: "deu+eng", psm: "6", oem: "1" })
        : await runOcrOnImageBest(req.file.path);
      const rawLines = (text || "")
        .split(/\r?\n/)
        .map((line) => line.trim())
        .filter((line) => line.length > 2);
      const filteredLines = filterOcrLinesForDisplay(rawLines);
      const detectedText = filteredLines.join("\n").slice(0, 300);
      let match = !!user && patientNameMatches(text, user);
      let validatedByBirthDate = false;
      if (!match && birthDate && user?.birth_date) {
        validatedByBirthDate =
          normalizeDateOnly(user.birth_date) === birthDate;
        if (validatedByBirthDate) match = true;
      }
      return res.json({
        ok: true,
        match,
        validated_by_birth_date: validatedByBirthDate,
        detected_text: detectedText,
        detected_text_full: debugOcr ? text || "" : undefined,
      });
    } catch (error) {
      return res.status(500).json({ error: error.message });
    }
  }
);

app.post(
  "/api/import-scan",
  requireRole(["admin", "superuser", "user"]),
  upload.single("file"),
  async (req, res) => {
    const familyId = getFamilyId(req);
    const userId = Number(req.body?.user_id);
    const skipNameCheck = req.body?.skip_name_check === "1";
    const fastImport = req.body?.fast_import === "1";
    const fastImportOcr = req.body?.fast_import_ocr === "1";
    const debugOcr = req.body?.debug_ocr === "1";
    const fastOcr = req.body?.fast_ocr !== "0";
    const birthDate = normalizeDateOnly(req.body?.birth_date);
    if (!familyId || !Number.isFinite(userId) || !req.file?.path) {
      return res.status(400).json({ error: "family_id, user_id y file son requeridos" });
    }
    try {
      // Manual entry or fast import (no OCR)
      const manualName = req.body?.manual_name;
      if (fastImport && !fastImportOcr && !debugOcr) {
        const medName = manualName?.trim() || "Medicamento escaneado";
        const medDosage = req.body?.manual_dosage?.trim() || "N/A";
        const medQty = parseInt(req.body?.manual_qty, 10) || 0;
        const medExpiry = req.body?.manual_expiry?.trim() || null;
        const medResult = await upsertMedicineForUser({
          familyId,
          userId,
          name: medName,
          dosage: medDosage,
          qty: medQty,
          expiryDate: medExpiry || null,
          batchId: null,
        });
        await ensureDefaultScheduleForMedicine({
          familyId,
          userId,
          medicineId: medResult.id,
        });
        return res.json({
          ok: true,
          action: medResult.action,
          medicine_id: medResult.id,
          extracted: { name: medName, dosage: medDosage, qty: medQty },
        });
      }
      const userResult = await pool.query(
        `SELECT id, name, first_name, last_name, birth_date FROM users WHERE id = $1 AND family_id = $2`,
        [userId, familyId]
      );
      const user = userResult.rows[0];
      const text = fastOcr
        ? await runOcrOnImage(req.file.path, { lang: "deu+eng", psm: "6", oem: "1" })
        : await runOcrOnImageBest(req.file.path);
      const rawLines = text
        .split(/\r?\n/)
        .map((line) => line.trim())
        .filter((line) => line.length > 2);
      const lines = filterOcrLines(rawLines);
      const detectedText = filterOcrLinesForDisplay(rawLines).join("\n").slice(0, 300);
      const nameCandidate = extractMedicineName(lines);
      const dosage = extractDosage(lines);
      const qtyMatch = text.match(/(\d+)\s*(Stk|Tbl|Kapsel|Caps|Pcs|ml)\b/i);
      const qty = qtyMatch ? Number(qtyMatch[1]) : 0;
      if (fastImport) {
        const medResult = await upsertMedicineForUser({
          familyId,
          userId,
          name: nameCandidate,
          dosage,
          qty,
          expiryDate: null,
          batchId: null,
        });
        await ensureDefaultScheduleForMedicine({
          familyId,
          userId,
          medicineId: medResult.id,
        });
        return res.json({
          ok: true,
          action: medResult.action,
          medicine_id: medResult.id,
          extracted: { name: nameCandidate, dosage, qty },
          detected_text_full: debugOcr ? text || "" : undefined,
        });
      }
      let validatedByBirthDate = false;
      if (!skipNameCheck && (!user || !patientNameMatches(text, user))) {
        if (birthDate && user?.birth_date) {
          validatedByBirthDate =
            normalizeDateOnly(user.birth_date) === birthDate;
        }
        if (!validatedByBirthDate) {
          return res.status(400).json({
            error: "Nombre de paciente no coincide o no se encontró en la etiqueta.",
            detected_text: detectedText,
            detected_text_full: debugOcr ? text || "" : undefined,
          });
        }
      }
      const nameLine = nameCandidate;

      const medResult = await upsertMedicineForUser({
        familyId,
        userId,
        name: nameLine,
        dosage,
        qty,
        expiryDate: null,
        batchId: null,
      });
      await ensureDefaultScheduleForMedicine({
        familyId,
        userId,
        medicineId: medResult.id,
      });

      res.json({
        ok: true,
        action: medResult.action,
        medicine_id: medResult.id,
        extracted: { name: nameLine, dosage, qty },
        validated_by_birth_date: validatedByBirthDate,
        detected_text_full: debugOcr ? text || "" : undefined,
      });
    } catch (error) {
      res.status(500).json({ error: error.message });
    }
  }
);

app.post("/admin/meds-reset", requireRoleHtml(["admin", "superuser"]), async (req, res) => {
  const familyId = req.user.family_id;
  const userId = Number(req.body?.user_id);
  const confirm = String(req.body?.confirm || "").trim();
  if (confirm !== "RESET") {
    return res.redirect("/admin/import");
  }
  if (!Number.isFinite(userId)) {
    return res.redirect("/admin/import");
  }
  const snapshotResult = await pool.query(
    `SELECT id, name, dosage, current_stock, expiration_date, import_batch_id
     FROM medicines
     WHERE family_id = $1 AND user_id = $2
     ORDER BY id`,
    [familyId, userId]
  );
  const snapshot = snapshotResult.rows || [];
  await pool.query(
    `DELETE FROM dose_logs
     WHERE schedule_id IN (SELECT id FROM schedules WHERE user_id = $1)`,
    [userId]
  );
  await pool.query(`DELETE FROM schedules WHERE user_id = $1`, [userId]);
  const result = await pool.query(`DELETE FROM medicines WHERE family_id = $1 AND user_id = $2`, [
    familyId,
    userId,
  ]);
  await pool.query(
    `INSERT INTO deletion_logs (family_id, user_id, deleted_count, snapshot)
     VALUES ($1, $2, $3, $4)`,
    [familyId, userId, result.rowCount || 0, JSON.stringify(snapshot)]
  );
  await pool.query(`DELETE FROM alerts WHERE family_id = $1 AND user_id = $2`, [
    familyId,
    userId,
  ]);
  res.redirect(
    `/admin/meds-list?reset=1&deleted=${result.rowCount || 0}&user_id=${userId}`
  );
});

app.post("/admin/meds-reset-all", requireRoleHtml(["admin", "superuser"]), async (req, res) => {
  const familyId = req.user.family_id;
  const confirm = String(req.body?.confirm || "").trim();
  if (confirm !== "RESET-TODO") {
    return res.redirect("/admin/import");
  }
  const snapshotResult = await pool.query(
    `SELECT id, user_id, name, dosage, current_stock, expiration_date, import_batch_id
     FROM medicines
     WHERE family_id = $1
     ORDER BY id`,
    [familyId]
  );
  const snapshot = snapshotResult.rows || [];
  const deletedCount = snapshot.length;
  await pool.query(
    `DELETE FROM dose_logs
     WHERE schedule_id IN (
       SELECT id FROM schedules WHERE user_id IN (SELECT id FROM users WHERE family_id = $1)
     )`,
    [familyId]
  );
  await pool.query(`DELETE FROM schedules WHERE user_id IN (SELECT id FROM users WHERE family_id = $1)`, [
    familyId,
  ]);
  await pool.query(`DELETE FROM medicines WHERE family_id = $1`, [familyId]);
  await pool.query(
    `INSERT INTO deletion_logs (family_id, user_id, deleted_count, snapshot)
     VALUES ($1, NULL, $2, $3)`,
    [familyId, deletedCount, JSON.stringify(snapshot)]
  );
  await pool.query(`DELETE FROM alerts WHERE family_id = $1`, [familyId]);
  res.redirect(`/admin/meds-list?reset=1&deleted=${deletedCount}`);
});

// Global error handler: evita que Express devuelva 500 genérico
app.use((err, _req, res, _next) => {
  console.error("[ERROR GLOBAL]", err.message || err);
  res.status(500).send(`
    <html><body style="font-family:sans-serif;padding:40px;text-center">
      <h2>Error temporal del servidor</h2>
      <p>Recarga la página en unos segundos.</p>
      <a href="/admin/login">Volver al login</a>
    </body></html>
  `);
});

// Evitar crash por promesas no manejadas
process.on("unhandledRejection", (reason) => {
  console.error("[UNHANDLED REJECTION]", reason);
});
process.on("uncaughtException", (err) => {
  console.error("[UNCAUGHT EXCEPTION]", err.message);
});

const port = Number(process.env.PORT || 4000);
app.listen(port, "0.0.0.0", () => {
  console.log(`Backend escuchando en puerto ${port}`);
});

// Job automático de alertas: cada 4 horas
setInterval(runAlertsJob, 4 * 60 * 60 * 1000);
setTimeout(runAlertsJob, 10000);

// ── Trial expiry check: cada 1 hora ──
async function checkTrialExpiry() {
  try {
    const expired = await pool.query(
      `SELECT f.id, f.name, u.email, u.first_name, u.last_name
       FROM families f
       JOIN users u ON u.family_id = f.id AND u.role IN ('admin','superuser','user')
       WHERE f.subscription_status = 'trial'
         AND f.trial_ends_at < NOW()
         AND (f.trial_email_sent IS NULL OR f.trial_email_sent = FALSE)
       ORDER BY f.id, u.id`
    );
    if (expired.rows.length === 0) return;
    const sentFamilies = new Set();
    for (const row of expired.rows) {
      if (sentFamilies.has(row.id)) continue;
      sentFamilies.add(row.id);
      if (!mailTransport || !row.email) continue;
      const FRONTEND = process.env.FRONTEND_URL || "https://medicamentos-frontend.vercel.app";
      try {
        await mailTransport.sendMail({
          from: process.env.SMTP_USER,
          to: row.email,
          subject: "Tu período de prueba ha finalizado – MediControl",
          html: `
<div style="font-family:Arial,sans-serif; max-width:600px; margin:0 auto; padding:20px;">
  <div style="background:linear-gradient(135deg,#0f172a,#1e40af); color:white; padding:30px; border-radius:16px 16px 0 0; text-align:center;">
    <h1 style="margin:0; font-size:24px;">⚕️ MediControl</h1>
    <p style="margin:8px 0 0; opacity:0.8;">Ihre Medikamente. Unter Kontrolle.</p>
  </div>
  <div style="background:white; padding:30px; border:1px solid #e2e8f0; border-top:none;">
    <p>Hola <strong>${row.first_name || row.name || "usuario"}</strong>,</p>
    <p>Tu período de prueba gratuito de 7 días ha finalizado. Durante este tiempo, pudiste gestionar hasta 5 medicamentos.</p>
    <h2 style="color:#1e40af; font-size:18px;">Activa tu suscripción</h2>
    <p>Para continuar usando todas las funciones sin límites:</p>
    <ul style="color:#475569;">
      <li>Medicamentos <strong>ilimitados</strong></li>
      <li>Alertas inteligentes y push notifications</li>
      <li>Escaneo OCR de recetas y medicamentos</li>
      <li>Historial médico completo</li>
      <li>Contacto directo con tu médico</li>
      <li>Soporte prioritario</li>
    </ul>
    <div style="text-align:center; margin:24px 0;">
      <a href="${FRONTEND}/billing" style="display:inline-block; background:#2563eb; color:white; padding:14px 32px; border-radius:12px; text-decoration:none; font-weight:bold; font-size:16px;">
        Activar suscripción – CHF 9.90/mes
      </a>
    </div>
    <hr style="border:none; border-top:1px solid #e2e8f0; margin:24px 0;">
    <h3 style="color:#0f172a; font-size:14px;">Información legal importante</h3>
    <p style="font-size:12px; color:#64748b; line-height:1.6;">
      MediControl es un servicio de software como servicio (SaaS) con domicilio en Suiza,
      sujeto al derecho suizo. El servicio proporciona una herramienta digital de apoyo para la
      gestión y el recordatorio de la medicación prescrita por el médico tratante del usuario.<br><br>
      <strong>Exclusión de responsabilidad médica:</strong> Esta aplicación NO sustituye, modifica
      ni reemplaza el diagnóstico, la prescripción ni las indicaciones de un profesional sanitario.
      El proveedor del servicio es exclusivamente responsable del correcto funcionamiento del software.
      No asume ninguna responsabilidad por decisiones médicas tomadas por el usuario sin consultar
      a su médico. El usuario se compromete a seguir siempre las instrucciones de su médico tratante.<br><br>
      <strong>Protección de datos:</strong> Los datos personales se procesan conforme a la Ley Federal
      de Protección de Datos de Suiza (nDSG/FADP) y, cuando aplique, al RGPD de la UE.
      Los datos se almacenan en servidores seguros con cifrado SSL/TLS.<br><br>
      <strong>Contrato:</strong> Al activar la suscripción, el usuario acepta los términos del servicio
      SaaS. La suscripción se renueva mensualmente y puede cancelarse en cualquier momento desde el
      panel de facturación. No hay período mínimo de permanencia.
    </p>
  </div>
  <div style="background:#f8fafc; padding:16px; border-radius:0 0 16px 16px; border:1px solid #e2e8f0; border-top:none; text-align:center;">
    <p style="font-size:11px; color:#94a3b8; margin:0;">
      © ${new Date().getFullYear()} MediControl · Suiza · 
      <a href="${FRONTEND}" style="color:#2563eb;">medicamentos-app.ch</a>
    </p>
  </div>
</div>`,
        });
        console.log(`[TRIAL] Email de oferta enviado a ${row.email} (familia ${row.id})`);
      } catch (emailErr) {
        console.error(`[TRIAL] Error enviando email a ${row.email}:`, emailErr.message);
      }
      // Marcar como enviado
      await pool.query(`UPDATE families SET trial_email_sent = TRUE WHERE id = $1`, [row.id]);
      // Notificar admin
      if (ADMIN_EMAIL && mailTransport) {
        try {
          await mailTransport.sendMail({
            from: process.env.SMTP_USER, to: ADMIN_EMAIL,
            subject: `Trial expirado: Familia ${row.name || row.id}`,
            html: `<p>El trial de la familia <strong>${row.name || row.id}</strong> (${row.email}) ha expirado. Se envió email de oferta.</p>`,
          });
        } catch {}
      }
    }
  } catch (err) {
    console.error("[TRIAL CHECK]", err.message);
  }
}
setInterval(checkTrialExpiry, 60 * 60 * 1000); // cada hora
setTimeout(checkTrialExpiry, 30000); // 30s después de arrancar
