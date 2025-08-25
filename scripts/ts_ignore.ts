import { readFileSync, writeFileSync } from "fs";

const files = [
  "contracts/clients/PlonkVerifier.ts",
  "contracts/clients/PlonkVerifierWithLogs.ts",
];

for (const file of files) {
  let content = readFileSync(file, "utf8");
  if (content.includes("// @ts-nocheck")) {
    console.log(`@ts-nocheck already present in ${file}, skipping`);
    continue;
  }
  content = "// @ts-nocheck\n" + content;
  writeFileSync(file, content, "utf8");
  console.log(`Added @ts-nocheck to ${file}`);
}
