import { readFileSync, readdirSync } from "fs";
import { fileURLToPath } from "url";
import { dirname, join } from "path";
import { ARC56Generator, type ARC56Contract } from "@joe-p/algokit-lite";

const __dirname = dirname(fileURLToPath(import.meta.url));

const outDir = join(__dirname, "..", "contracts", "out");
const clientsDir = join(__dirname, "..", "contracts", "clients");

const specs = readdirSync(outDir)
  .filter((file) => file.endsWith(".arc56.json"))
  .sort();

for (const file of specs) {
  const arc56 = JSON.parse(
    readFileSync(join(outDir, file), "utf8"),
  ) as ARC56Contract;

  const generator = new ARC56Generator(arc56, {
    clientImportPath: "@joe-p/algokit-lite",
  });

  const clientPath = join(clientsDir, `${arc56.name}.ts`);
  await generator.generateToFile(clientPath);
  console.log(`Generated ${clientPath}`);
}
