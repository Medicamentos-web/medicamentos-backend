const fs = require("fs");
const path = require("path");
const pdfParse = require("pdf-parse");
const { Client } = require("pg");

const inputPath = process.argv[2];
const familyId = Number(process.argv[3] || 1);

if (!inputPath) {
  console.error("Uso: node scripts/import-meds.js <ruta_pdf> [family_id]");
  process.exit(1);
}

const absolutePath = path.isAbsolute(inputPath)
  ? inputPath
  : path.resolve(process.cwd(), inputPath);

function extractQuantity(line) {
  const match = line.match(/(\d+)\s*(Stk|ml|Amp|Btl)\b/i);
  if (!match) return { qty: 0, unit: "unidades" };
  return { qty: Number(match[1]), unit: match[2] };
}

function extractDosage(line) {
  const match = line.match(/(\d+(?:\.\d+)?)\s*(mg|mcg|g|IE\/ml|IU\/ml)\b/i);
  if (!match) return "N/A";
  return `${match[1]} ${match[2]}`;
}

function extractExpiry(line) {
  const match = line.match(/(\d{2}\.\d{2}\.\d{4})/);
  if (!match) return null;
  const [day, month, year] = match[1].split(".");
  return `${year}-${month}-${day}`;
}

function extractName(line) {
  const cleaned = line
    .replace(/\d+\s*(Stk|ml|Amp|Btl)\b/gi, "")
    .replace(/\d+(?:\.\d+)?\s*(mg|mcg|g|IE\/ml|IU\/ml)\b/gi, "")
    .replace(/\d{2}\.\d{2}\.\d{4}/g, "")
    .replace(/\b(auf weiteres)\b/gi, "")
    .replace(/[-–]\s*$/, "")
    .trim();
  return cleaned.replace(/\s{2,}/g, " ");
}

function parseColumns(line) {
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
}

async function run() {
  const buffer = fs.readFileSync(absolutePath);
  const pdf = await pdfParse(buffer);
  const lines = pdf.text
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter((line) => line && !line.startsWith("Medikament") && !line.startsWith("Seite"));

  const client = new Client({
    host: "db",
    port: 5432,
    user: "medicamentos",
    password: "medicamentos_secret",
    database: "medicamentos",
  });

  await client.connect();
  let inserted = 0;

  for (const line of lines) {
    if (line.startsWith("--")) continue;
    const name = extractName(line);
    if (!name || name.length < 3) continue;
    const dosage = extractDosage(line);
    const { qty } = extractQuantity(line);
    const expiryDate = extractExpiry(line);
    const columns = parseColumns(line);

    const medicineResult = await client.query(
      `INSERT INTO medicines (family_id, name, dosage, current_stock, expiration_date)
       VALUES ($1, $2, $3, $4, $5)
       RETURNING id`,
      [familyId, name, dosage, qty || 0, expiryDate]
    );

    const medicineId = medicineResult.rows[0].id;
    const scheduleTimes = [
      { key: "mo", time: "08:00" },
      { key: "mi", time: "14:00" },
      { key: "ab", time: "20:00" },
      { key: "na", time: "22:00" },
    ];

    const dayValue = { mo: columns.mo, mi: columns.mi, ab: columns.ab, na: columns.na };
    const defaultStart = process.env.DEFAULT_SCHEDULE_START_DATE || null;
    for (const slot of scheduleTimes) {
      const value = dayValue[slot.key];
      if (!value || value === "-" || value === "0") continue;
      await client.query(
        `INSERT INTO schedules (medicine_id, user_id, dose_time, frequency, days_of_week, start_date)
         VALUES ($1, $2, $3, $4, $5, $6)`,
        [
          medicineId,
          Number(process.env.DEFAULT_IMPORT_USER_ID || 1),
          slot.time,
          value,
          "1234567",
          defaultStart,
        ]
      );
    }
    inserted += 1;
  }

  await client.end();
  console.log(`Importación completa. Medicamentos insertados: ${inserted}`);
}

run().catch((error) => {
  console.error(error);
  process.exit(1);
});
