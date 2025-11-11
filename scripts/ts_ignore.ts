import { readFileSync, writeFileSync, readdirSync } from "fs";
import { join } from "path";

const dir = "contracts/clients/";
const files = readdirSync(dir)
  .filter((file) => file.endsWith(".ts"))
  .map((file) => join(dir, file));

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
