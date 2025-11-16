import { readFileSync, writeFileSync } from "fs";
import { fileURLToPath } from "url";
import { dirname, join } from "path";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const plonkLsigTeal = readFileSync(
  join(__dirname, "..", "contracts", "out", "PlonkVerifierLsig.teal"),
  "utf8",
);

const groth16LsigTeal = readFileSync(
  join(__dirname, "..", "contracts", "out", "Groth16VerifierLsig.teal"),
  "utf8",
);

const content = `
export const PLONK_LSIG_SOURCE = \`${plonkLsigTeal}\`;
export const GROTH16_LSIG_SOURCE = \`${groth16LsigTeal}\`;
`;

writeFileSync(
  join(__dirname, "..", "contracts", "out", "lsig_source.ts"),
  content,
);
console.log("Generated lsig_source.ts");
