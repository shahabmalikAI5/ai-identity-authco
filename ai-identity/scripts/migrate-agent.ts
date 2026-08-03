import { getMigrations } from "better-auth/db/migration";
import { auth } from "../src/lib/auth.ts";

async function main() {
  const { toBeCreated, toBeAdded, runMigrations } =
    await getMigrations(auth.options);

  console.log(
    "Tables to create:",
    toBeCreated.map((t) => t.table)
  );
  console.log(
    "Columns to add:",
    toBeAdded.map((t) => `${t.table}: ${Object.keys(t.fields).join(", ")}`)
  );

  if (toBeCreated.length === 0 && toBeAdded.length === 0) {
    console.log("Nothing to migrate — agent tables already present.");
    return;
  }

  await runMigrations();
  console.log("Migrations applied.");
}

main().catch((err) => {
  console.error("Migration failed:", err);
  process.exit(1);
});
