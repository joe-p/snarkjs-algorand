import { readFileSync, writeFileSync } from "fs";

const lsigTeal = readFileSync(
  __dirname + "/../contracts/out/PlonkVerifierLsig.teal",
  "utf8",
);

const content = `export const LSIG_SOURCE = \`${lsigTeal}\`;\n`;

writeFileSync(__dirname + "/../contracts/out/lsig_source.ts", content);
