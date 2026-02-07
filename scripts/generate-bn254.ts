import { readFileSync, writeFileSync } from "fs";
import { join, dirname } from "path";
import { fileURLToPath } from "url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

interface CurveConfig {
  name: string;
  scalarModulus: string;
  rMinus1: string;
  g1Size: number;
  g2Size: number;
  fieldSize: number;
}

const BN254: CurveConfig = {
  name: "BN254",
  scalarModulus:
    "30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001",
  rMinus1: "30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000000",
  g1Size: 64,
  g2Size: 128,
  fieldSize: 32,
};

type Substitution = [RegExp, string];

function getBaseSubstitutions(config: CurveConfig): Substitution[] {
  return [
    // Constants
    [/BLS12_381/g, config.name],

    // Hex values
    [
      /73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001/g,
      config.scalarModulus,
    ],
    [
      /73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000000/g,
      config.rMinus1,
    ],

    // Types (order matters: larger first to avoid partial matches)
    [/bytes<192>/g, `bytes<${config.g2Size}>`],
    [/bytes<96>/g, `bytes<${config.g1Size}>`],

    // toFixed length values (for G1 points)
    [
      /\.toFixed\(\{\s*\n?\s*length: 96,?\s*\n?\s*\}\)/g,
      `.toFixed({ length: ${config.g1Size} })`,
    ],
    [
      /\.toFixed\(\{ length: 96 \}\)/g,
      `.toFixed({ length: ${config.g1Size} })`,
    ],

    [/BLS12_381/g, config.name],
    [/BLS12-381/g, config.name],
    [/bls12381/g, config.name.toLowerCase()],
    [/Bls12381/g, "Bn254"],

    // Comments: byte sizes
    [/96-byte/g, `${config.g1Size}-byte`],
    [/192-byte/g, `${config.g2Size}-byte`],
    [/48-byte/g, `${config.fieldSize}-byte`],
  ];
}

function applySubstitutions(
  content: string,
  substitutions: Substitution[],
): string {
  for (const [pattern, replacement] of substitutions) {
    content = content.replace(pattern, replacement);
  }
  return content;
}

function generate(sourceFile: string, config: CurveConfig): void {
  const contractsDir = join(__dirname, "..", "contracts");
  const fullSourcePath = join(contractsDir, sourceFile);

  let content = readFileSync(fullSourcePath, "utf8");
  content = applySubstitutions(content, getBaseSubstitutions(config));

  const targetFile = fullSourcePath.replace(
    "bls12381",
    config.name.toLowerCase(),
  );
  writeFileSync(targetFile, content);
  console.log(`Generated ${targetFile}`);
}

console.log("Generating BN254 contracts...");
[
  "bls12381_common.algo.ts",
  "groth16_bls12381.algo.ts",
  "groth16_bls12381_verifier.algo.ts",
].forEach((baseName) => {
  generate(baseName, BN254);
});

import { execSync } from "child_process";
execSync(
  `npx prettier --write ${join(
    __dirname,
    "..",
    "contracts",
    "*bn254*.algo.ts",
  )}`,
  { stdio: "inherit" },
);

console.log("BN254 generation complete!");
