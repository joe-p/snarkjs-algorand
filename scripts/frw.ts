import * as snarkjs from "snarkjs";
const curve = await snarkjs.curves.getCurveFromName("bls12_381");

const Fr = curve.Fr;
Fr.w.forEach((val, i) => {
  if (i === 0) return; // index 0 unused
  console.log(
    i,
    Buffer.from(
      Fr.toObject(val).toString(16).padStart(64, "0"),
      "hex",
    ).toString("hex"),
  );
});

await curve.terminate();
