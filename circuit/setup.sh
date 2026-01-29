set -x 
set -e

if [ ! -f witness.wtns ]; then
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
fi

########
# PLONK
########

if [ ! -f plonk_proof.json ]; then
snarkjs plonk setup circuit.r1cs pot14_final.ptau plonk_circuit_final.zkey

snarkjs zkey export verificationkey plonk_circuit_final.zkey plonk_verification_key.json

snarkjs plonk fullprove input.json circuit_js/circuit.wasm plonk_circuit_final.zkey plonk_proof.json public.json

snarkjs plonk verify plonk_verification_key.json public.json plonk_proof.json
fi

##########
# Groth16
##########

if [ ! -f groth16_proof.json ]; then
snarkjs groth16 setup circuit.r1cs pot14_final.ptau groth16_circuit_final.zkey

# Export verification key
snarkjs zkey export verificationkey groth16_circuit_final.zkey groth16_verification_key.json

# Prove
snarkjs groth16 fullprove input.json circuit_js/circuit.wasm groth16_circuit_final.zkey groth16_proof.json public.json

# Verify proof
snarkjs groth16 verify groth16_verification_key.json public.json groth16_proof.json
fi

################
# Groth16 BN254
################

if [ ! -f groth16_bn254_proof.json ]; then
# Powers of tau for BN254 (bn128 is the snarkjs name for BN254)
snarkjs powersoftau new bn128 14 pot14_bn254_0000.ptau -v
echo "blah" | snarkjs powersoftau contribute pot14_bn254_0000.ptau pot14_bn254_0001.ptau --name="First contribution" -v
snarkjs powersoftau prepare phase2 pot14_bn254_0001.ptau pot14_bn254_final.ptau -v
snarkjs powersoftau verify pot14_bn254_final.ptau

# Circuit for BN254
cat <<EOT > circuit_bn254.circom
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

circom --r1cs --wasm --c --sym --inspect circuit_bn254.circom --prime bn128

# Export contraints to JSON
snarkjs r1cs export json circuit_bn254.r1cs circuit_bn254.r1cs.json

# Calculate witness
snarkjs wtns calculate circuit_bn254_js/circuit_bn254.wasm input.json witness_bn254.wtns

snarkjs wtns check circuit_bn254.r1cs witness_bn254.wtns

# Setup Groth16 for BN254
snarkjs groth16 setup circuit_bn254.r1cs pot14_bn254_final.ptau groth16_bn254_circuit_final.zkey

# Export verification key
snarkjs zkey export verificationkey groth16_bn254_circuit_final.zkey groth16_bn254_verification_key.json

# Prove
snarkjs groth16 fullprove input.json circuit_bn254_js/circuit_bn254.wasm groth16_bn254_circuit_final.zkey groth16_bn254_proof.json public_bn254.json

# Verify proof
snarkjs groth16 verify groth16_bn254_verification_key.json public_bn254.json groth16_bn254_proof.json
fi



