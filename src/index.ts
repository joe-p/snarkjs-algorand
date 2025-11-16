export function stringValuesToBigints(obj: any): any {
  for (const key in obj) {
    if (typeof obj[key] === "string" && /^\d+$/.test(obj[key])) {
      obj[key] = BigInt(obj[key]);
    } else if (typeof obj[key] === "object" && obj[key] !== null) {
      stringValuesToBigints(obj[key]);
    }
  }
}

export * from "./plonk";
export * from "./groth16";
