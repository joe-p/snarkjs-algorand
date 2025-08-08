set -x 
set -e

snarkjs powersoftau new bls12381 14 pot14_0000.ptau -v
echo "blah" | snarkjs powersoftau contribute pot14_0000.ptau pot14_0001.ptau --name="First contribution" -v
snarkjs powersoftau prepare phase2 pot14_0001.ptau pot14_final.ptau -v
snarkjs powersoftau verify pot14_final.ptau

cat <<EOT > circuit.circom
pragma circom 2.0.0;

template Multiplier(n) {
    signal input a;
    signal input b;
    signal output c;

    signal int[n];

    int[0] <== a*a + b;
    for (var i=1; i<n; i++) {
        int[i] <== int[i-1]*int[i-1] + b;
    }

    c <== int[n-1];
}

component main = Multiplier(1000);
EOT

circom --r1cs --wasm --c --sym --inspect circuit.circom --prime bls12381

# Export contraints to JSON
snarkjs r1cs export json circuit.r1cs circuit.r1cs.json

# Public inputs (witness)
cat <<EOT > input.json
{"a": "3", "b": "11"}
EOT

snarkjs wtns calculate circuit_js/circuit.wasm input.json witness.wtns

snarkjs wtns check circuit.r1cs witness.wtns

snarkjs plonk setup circuit.r1cs pot14_final.ptau circuit_final.zkey

# Export verification key
snarkjs zkey export verificationkey circuit_final.zkey verification_key.json

# Prove
snarkjs plonk fullprove input.json circuit_js/circuit.wasm circuit_final.zkey proof.json public.json

# Verify proof
snarkjs plonk verify verification_key.json public.json proof.json


