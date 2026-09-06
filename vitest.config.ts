import { defineConfig } from "vitest/config";

export default defineConfig({
  resolve: {
    // algokit-lite is linked from a sibling checkout during development, so it
    // carries its own algosdk install. Two copies of algosdk break the
    // `instanceof` checks algosdk uses on Address and Transaction, so pin every
    // import to this project's copy.
    dedupe: ["algosdk"],
  },
});
