import { readFileSync, writeFileSync } from "fs";
import { fileURLToPath } from "url";
import { dirname, join } from "path";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const lsigTeal = readFileSync(
  join(__dirname, "..", "contracts", "out", "PlonkVerifierLsig.teal"),
  "utf8",
);

const content = `export const LSIG_SOURCE = \`${lsigTeal}\`;\n`;

writeFileSync(
  join(__dirname, "..", "contracts", "out", "lsig_source.ts"),
  content,
);
console.log("Generated lsig_source.ts");
