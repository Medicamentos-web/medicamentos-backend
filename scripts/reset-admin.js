const { Client } = require("pg");
const bcrypt = require("bcryptjs");

async function run() {
  const client = new Client({
    host: "db",
    port: 5432,
    user: "medicamentos",
    password: "medicamentos_secret",
    database: "medicamentos",
  });

  await client.connect();
  const hash = await bcrypt.hash("123456", 10);
  await client.query(
    "UPDATE users SET password_hash = $1 WHERE email = $2",
    [hash, "alertas.medicamentos@gmail.com"]
  );
  await client.end();
  console.log("updated");
}

run().catch((error) => {
  console.error(error);
  process.exit(1);
});
