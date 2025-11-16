export const PLONK_LSIG_SOURCE = `#pragma version 11
#pragma typetrack false

// contracts/plonk_verifier.algo.ts::program() -> uint64:
main:
    intcblock 32 96 1 0 384
    bytecblock 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001 0x 0x01 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000000 TMPL_VERIFICATION_KEY TMPL_ROOT_OF_UNITY
    intc_3 // 0
    dupn 17
    bytec_1 // ""
    dupn 2
    // contracts/plonk_verifier.algo.ts:54
    // assertMatch(Txn, { fee: 0, rekeyTo: Global.zeroAddress });
    txn Fee
    !
    txn RekeyTo
    global ZeroAddress
    ==
    &&
    assert // assert target is match for conditions
    // contracts/plonk_verifier.algo.ts:56
    // const lw = decodeArc4<LagrangeWitness>(Txn.applicationArgs(3));
    pushint 3 // 3
    txnas ApplicationArgs
    // contracts/plonk_verifier.algo.ts:57
    // const proof = decodeArc4<PlonkProof>(Txn.applicationArgs(2));
    pushint 2 // 2
    txnas ApplicationArgs
    // contracts/plonk_verifier.algo.ts:58
    // const signals = decodeArc4<Uint256[]>(Txn.applicationArgs(1));
    intc_2 // 1
    txnas ApplicationArgs
    dup
    uncover 2
    // contracts/plonk_bls12381.algo.ts:264
    // return verify(decodeArc4<PlonkVerificationKey>(vkBytes), signals, proof, lw);
    bytec 4 // TMPL_VERIFICATION_KEY
    dup
    cover 3
    cover 3
    // contracts/plonk_bls12381.algo.ts:329
    // assert(groupCheck(proof.A), "A not in G1");
    dup
    extract 0 96
    dup
    cover 4
    // contracts/plonk_bls12381.algo.ts:268
    // return op.EllipticCurve.subgroupCheck(op.Ec.BLS12_381g1, p);
    ec_subgroup_check BLS12_381g1
    // contracts/plonk_bls12381.algo.ts:329
    // assert(groupCheck(proof.A), "A not in G1");
    assert // A not in G1
    // contracts/plonk_bls12381.algo.ts:330
    // assert(groupCheck(proof.B), "B not in G1");
    dup
    extract 96 96
    dup
    cover 4
    // contracts/plonk_bls12381.algo.ts:268
    // return op.EllipticCurve.subgroupCheck(op.Ec.BLS12_381g1, p);
    ec_subgroup_check BLS12_381g1
    // contracts/plonk_bls12381.algo.ts:330
    // assert(groupCheck(proof.B), "B not in G1");
    assert // B not in G1
    // contracts/plonk_bls12381.algo.ts:331
    // assert(groupCheck(proof.C), "C not in G1");
    dup
    extract 192 96
    dup
    cover 4
    // contracts/plonk_bls12381.algo.ts:268
    // return op.EllipticCurve.subgroupCheck(op.Ec.BLS12_381g1, p);
    ec_subgroup_check BLS12_381g1
    // contracts/plonk_bls12381.algo.ts:331
    // assert(groupCheck(proof.C), "C not in G1");
    assert // C not in G1
    // contracts/plonk_bls12381.algo.ts:332
    // assert(groupCheck(proof.Z), "Z not in G1");
    dup
    pushint 288 // 288
    intc_1 // 96
    extract3
    dup
    cover 4
    // contracts/plonk_bls12381.algo.ts:268
    // return op.EllipticCurve.subgroupCheck(op.Ec.BLS12_381g1, p);
    ec_subgroup_check BLS12_381g1
    // contracts/plonk_bls12381.algo.ts:332
    // assert(groupCheck(proof.Z), "Z not in G1");
    assert // Z not in G1
    // contracts/plonk_bls12381.algo.ts:333
    // assert(groupCheck(proof.T1), "T1 not in G1");
    dup
    intc 4 // 384
    intc_1 // 96
    extract3
    dup
    cover 4
    // contracts/plonk_bls12381.algo.ts:268
    // return op.EllipticCurve.subgroupCheck(op.Ec.BLS12_381g1, p);
    ec_subgroup_check BLS12_381g1
    // contracts/plonk_bls12381.algo.ts:333
    // assert(groupCheck(proof.T1), "T1 not in G1");
    assert // T1 not in G1
    // contracts/plonk_bls12381.algo.ts:334
    // assert(groupCheck(proof.T2), "T2 not in G1");
    dup
    pushint 480 // 480
    intc_1 // 96
    extract3
    dup
    cover 4
    // contracts/plonk_bls12381.algo.ts:268
    // return op.EllipticCurve.subgroupCheck(op.Ec.BLS12_381g1, p);
    ec_subgroup_check BLS12_381g1
    // contracts/plonk_bls12381.algo.ts:334
    // assert(groupCheck(proof.T2), "T2 not in G1");
    assert // T2 not in G1
    // contracts/plonk_bls12381.algo.ts:335
    // assert(groupCheck(proof.T3), "T3 not in G1");
    dup
    pushint 576 // 576
    intc_1 // 96
    extract3
    dup
    cover 4
    // contracts/plonk_bls12381.algo.ts:268
    // return op.EllipticCurve.subgroupCheck(op.Ec.BLS12_381g1, p);
    ec_subgroup_check BLS12_381g1
    // contracts/plonk_bls12381.algo.ts:335
    // assert(groupCheck(proof.T3), "T3 not in G1");
    assert // T3 not in G1
    // contracts/plonk_bls12381.algo.ts:336
    // assert(groupCheck(proof.Wxi), "Wxi not in G1");
    dup
    pushint 672 // 672
    intc_1 // 96
    extract3
    dup
    cover 4
    // contracts/plonk_bls12381.algo.ts:268
    // return op.EllipticCurve.subgroupCheck(op.Ec.BLS12_381g1, p);
    ec_subgroup_check BLS12_381g1
    // contracts/plonk_bls12381.algo.ts:336
    // assert(groupCheck(proof.Wxi), "Wxi not in G1");
    assert // Wxi not in G1
    // contracts/plonk_bls12381.algo.ts:337
    // assert(groupCheck(proof.Wxiw), "Wxiw not in G1");
    dup
    pushint 768 // 768
    intc_1 // 96
    extract3
    dup
    cover 4
    // contracts/plonk_bls12381.algo.ts:268
    // return op.EllipticCurve.subgroupCheck(op.Ec.BLS12_381g1, p);
    ec_subgroup_check BLS12_381g1
    // contracts/plonk_bls12381.algo.ts:337
    // assert(groupCheck(proof.Wxiw), "Wxiw not in G1");
    assert // Wxiw not in G1
    // contracts/plonk_bls12381.algo.ts:320
    // assert(inField(proof.eval_a), "eval_a not in Fr");
    dup
    pushint 864 // 864
    intc_0 // 32
    extract3
    dup
    cover 4
    // contracts/bls12381_common.algo.ts:91
    // return value.asBigUint() < BLS12_381_SCALAR_MODULUS;
    bytec_0 // 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001
    b<
    // contracts/plonk_bls12381.algo.ts:320
    // assert(inField(proof.eval_a), "eval_a not in Fr");
    assert // eval_a not in Fr
    // contracts/plonk_bls12381.algo.ts:321
    // assert(inField(proof.eval_b), "eval_b not in Fr");
    dup
    pushint 896 // 896
    intc_0 // 32
    extract3
    dup
    cover 4
    // contracts/bls12381_common.algo.ts:91
    // return value.asBigUint() < BLS12_381_SCALAR_MODULUS;
    bytec_0 // 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001
    b<
    // contracts/plonk_bls12381.algo.ts:321
    // assert(inField(proof.eval_b), "eval_b not in Fr");
    assert // eval_b not in Fr
    // contracts/plonk_bls12381.algo.ts:322
    // assert(inField(proof.eval_c), "eval_c not in Fr");
    dup
    pushint 928 // 928
    intc_0 // 32
    extract3
    dup
    cover 4
    // contracts/bls12381_common.algo.ts:91
    // return value.asBigUint() < BLS12_381_SCALAR_MODULUS;
    bytec_0 // 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001
    b<
    // contracts/plonk_bls12381.algo.ts:322
    // assert(inField(proof.eval_c), "eval_c not in Fr");
    assert // eval_c not in Fr
    // contracts/plonk_bls12381.algo.ts:323
    // assert(inField(proof.eval_s1), "eval_s1 not in Fr");
    dup
    pushint 960 // 960
    intc_0 // 32
    extract3
    dup
    cover 4
    // contracts/bls12381_common.algo.ts:91
    // return value.asBigUint() < BLS12_381_SCALAR_MODULUS;
    bytec_0 // 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001
    b<
    // contracts/plonk_bls12381.algo.ts:323
    // assert(inField(proof.eval_s1), "eval_s1 not in Fr");
    assert // eval_s1 not in Fr
    // contracts/plonk_bls12381.algo.ts:324
    // assert(inField(proof.eval_s2), "eval_s2 not in Fr");
    dup
    pushint 992 // 992
    intc_0 // 32
    extract3
    dup
    cover 4
    // contracts/bls12381_common.algo.ts:91
    // return value.asBigUint() < BLS12_381_SCALAR_MODULUS;
    bytec_0 // 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001
    b<
    // contracts/plonk_bls12381.algo.ts:324
    // assert(inField(proof.eval_s2), "eval_s2 not in Fr");
    assert // eval_s2 not in Fr
    // contracts/plonk_bls12381.algo.ts:325
    // assert(inField(proof.eval_zw), "eval_zw not in Fr");
    pushint 1024 // 1024
    intc_0 // 32
    extract3
    dup
    cover 3
    // contracts/bls12381_common.algo.ts:91
    // return value.asBigUint() < BLS12_381_SCALAR_MODULUS;
    bytec_0 // 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001
    b<
    // contracts/plonk_bls12381.algo.ts:325
    // assert(inField(proof.eval_zw), "eval_zw not in Fr");
    assert // eval_zw not in Fr
    // contracts/plonk_bls12381.algo.ts:312
    // assert(signals.length === vk.nPublic, "Invalid number of public inputs");
    intc_3 // 0
    extract_uint16 // on error: invalid array length header
    dup
    uncover 2
    pushint 776 // 776
    extract_uint64
    dup
    cover 2
    ==
    assert // Invalid number of public inputs
    intc_3 // 0

main_for_header@2:
    // contracts/plonk_bls12381.algo.ts:314
    // for (const signal of signals) {
    dup
    dig 3
    <
    bz main_after_for@4
    dig 19
    extract 2 0
    dig 1
    dup
    cover 2
    intc_0 // 32
    *
    intc_0 // 32
    extract3 // on error: index access is out of bounds
    // contracts/bls12381_common.algo.ts:91
    // return value.asBigUint() < BLS12_381_SCALAR_MODULUS;
    bytec_0 // 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001
    b<
    // contracts/plonk_bls12381.algo.ts:315
    // assert(inField(signal), "public signal not in Fr");
    assert // public signal not in Fr
    intc_2 // 1
    +
    bury 1
    b main_for_header@2

main_after_for@4:
    // contracts/plonk_bls12381.algo.ts:457
    // let td = op.concat(vk.Qm, vk.Ql);
    dig 18
    dup
    extract 0 96
    dig 1
    extract 96 96
    concat
    // contracts/plonk_bls12381.algo.ts:458
    // td = op.concat(td, vk.Qr);
    dig 1
    extract 192 96
    concat
    // contracts/plonk_bls12381.algo.ts:459
    // td = op.concat(td, vk.Qo);
    dig 1
    pushint 288 // 288
    intc_1 // 96
    extract3
    concat
    dup
    bury 35
    // contracts/plonk_bls12381.algo.ts:460
    // td = op.concat(td, vk.Qc);
    dig 1
    intc 4 // 384
    intc_1 // 96
    extract3
    dup
    bury 43
    concat
    // contracts/plonk_bls12381.algo.ts:461
    // td = op.concat(td, vk.S1);
    dig 1
    pushint 480 // 480
    intc_1 // 96
    extract3
    dup
    bury 42
    concat
    // contracts/plonk_bls12381.algo.ts:462
    // td = op.concat(td, vk.S2);
    dig 1
    pushint 576 // 576
    intc_1 // 96
    extract3
    dup
    bury 41
    concat
    // contracts/plonk_bls12381.algo.ts:463
    // td = op.concat(td, vk.S3);
    swap
    pushint 672 // 672
    intc_1 // 96
    extract3
    dup
    bury 39
    concat
    bury 31
    intc_3 // 0
    bury 1

main_for_header@5:
    // contracts/plonk_bls12381.algo.ts:465
    // for (const signal of signals) {
    dup
    dig 3
    <
    bz main_after_for@7
    dig 19
    extract 2 0
    dig 1
    dup
    cover 2
    intc_0 // 32
    *
    intc_0 // 32
    extract3 // on error: index access is out of bounds
    // contracts/bls12381_common.algo.ts:37
    // return a % BLS12_381_SCALAR_MODULUS;
    bytec_0 // 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001
    b%
    // contracts/plonk_bls12381.algo.ts:466
    // td = op.concat(td, b32(frScalar(signal.asBigUint())));
    callsub b32
    dig 32
    swap
    concat
    bury 32
    intc_2 // 1
    +
    bury 1
    b main_for_header@5

main_after_for@7:
    // contracts/plonk_bls12381.algo.ts:470
    // td = op.concat(td, proof.A);
    dig 30
    dig 18
    concat
    // contracts/plonk_bls12381.algo.ts:471
    // td = op.concat(td, proof.B);
    dig 17
    concat
    // contracts/plonk_bls12381.algo.ts:472
    // td = op.concat(td, proof.C);
    dig 16
    concat
    // contracts/plonk_bls12381.algo.ts:474
    // const beta = getChallenge(td);
    callsub getChallenge
    // contracts/plonk_bls12381.algo.ts:479
    // const gamma = getChallenge(td);
    dup
    callsub getChallenge
    // contracts/plonk_bls12381.algo.ts:486
    // td = op.concat(td, gamma.bytes);
    concat
    dup
    bury 32
    // contracts/plonk_bls12381.algo.ts:487
    // td = op.concat(td, proof.Z);
    dig 15
    concat
    // contracts/plonk_bls12381.algo.ts:488
    // const alpha = getChallenge(td);
    callsub getChallenge
    dup
    bury 37
    // contracts/plonk_bls12381.algo.ts:495
    // td = op.concat(td, proof.T1);
    dig 14
    concat
    // contracts/plonk_bls12381.algo.ts:496
    // td = op.concat(td, proof.T2);
    dig 13
    concat
    // contracts/plonk_bls12381.algo.ts:497
    // td = op.concat(td, proof.T3);
    dig 12
    concat
    // contracts/plonk_bls12381.algo.ts:498
    // const xi = getChallenge(td);
    callsub getChallenge
    dup
    bury 28
    // contracts/plonk_bls12381.algo.ts:505
    // td = op.concat(td, proof.eval_a.bytes);
    dig 9
    concat
    // contracts/plonk_bls12381.algo.ts:506
    // td = op.concat(td, proof.eval_b.bytes);
    dig 8
    concat
    // contracts/plonk_bls12381.algo.ts:507
    // td = op.concat(td, proof.eval_c.bytes);
    dig 7
    concat
    // contracts/plonk_bls12381.algo.ts:508
    // td = op.concat(td, proof.eval_s1.bytes);
    dig 6
    concat
    // contracts/plonk_bls12381.algo.ts:509
    // td = op.concat(td, proof.eval_s2.bytes);
    dig 5
    concat
    // contracts/plonk_bls12381.algo.ts:510
    // td = op.concat(td, proof.eval_zw.bytes);
    dig 4
    concat
    // contracts/plonk_bls12381.algo.ts:512
    // const v = new FixedArray<Uint256, 6>();
    pushint 192 // 192
    bzero
    // contracts/plonk_bls12381.algo.ts:513
    // v[1] = getChallenge(td); // v1
    swap
    callsub getChallenge
    replace2 32 // on error: index access is out of bounds
    bury 30
    // contracts/plonk_bls12381.algo.ts:514
    // for (let i: uint64 = 2; i < 6; i++) {
    pushint 2 // 2
    bury 23

main_while_top@8:
    // contracts/plonk_bls12381.algo.ts:514
    // for (let i: uint64 = 2; i < 6; i++) {
    dig 22
    pushint 6 // 6
    <
    bz main_after_while@10
    // contracts/plonk_bls12381.algo.ts:516
    // frMul((v[i - 1] as Uint256).asBigUint(), v[1].asBigUint()),
    dig 22
    dup
    intc_2 // 1
    -
    intc_0 // 32
    *
    dig 31
    dup
    uncover 2
    intc_0 // 32
    extract3 // on error: index access is out of bounds
    dig 1
    extract 32 32 // on error: index access is out of bounds
    // contracts/plonk_bls12381.algo.ts:70
    // return (a * b) % BLS12_381_SCALAR_MODULUS;
    b*
    bytec_0 // 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001
    b%
    // contracts/plonk_bls12381.algo.ts:515-517
    // v[i] = new Uint256(
    //   frMul((v[i - 1] as Uint256).asBigUint(), v[1].asBigUint()),
    // ); // v[i] = v1^i
    dup
    len
    intc_0 // 32
    <=
    assert // overflow
    intc_0 // 32
    bzero
    b|
    dig 2
    intc_0 // 32
    *
    swap
    replace3 // on error: index access is out of bounds
    bury 31
    // contracts/plonk_bls12381.algo.ts:514
    // for (let i: uint64 = 2; i < 6; i++) {
    intc_2 // 1
    +
    bury 23
    b main_while_top@8

main_after_while@10:
    // contracts/plonk_bls12381.algo.ts:525
    // td = op.concat(td, proof.Wxiw);
    dig 10
    dig 10
    concat
    dup
    bury 33
    // contracts/plonk_bls12381.algo.ts:526
    // const u = getChallenge(td);
    callsub getChallenge
    // contracts/plonk_bls12381.algo.ts:528-537
    // return {
    //   beta,
    //   gamma,
    //   alpha,
    //   xi,
    //   v,
    //   u,
    //   xin: new Uint256(),
    //   zh: new Uint256(),
    // };
    dig 31
    dig 37
    concat
    dig 28
    concat
    dig 31
    concat
    swap
    concat
    pushbytes 0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
    concat
    bury 35
    // contracts/plonk_bls12381.algo.ts:272
    // assert(inField(lw.xin), "lw.xin not in Fr");
    dig 20
    dup
    extract 2 32
    dup
    bury 31
    // contracts/bls12381_common.algo.ts:91
    // return value.asBigUint() < BLS12_381_SCALAR_MODULUS;
    bytec_0 // 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001
    b<
    // contracts/plonk_bls12381.algo.ts:272
    // assert(inField(lw.xin), "lw.xin not in Fr");
    assert // lw.xin not in Fr
    // contracts/plonk_bls12381.algo.ts:273
    // assert(inField(lw.zh), "lw.zh not in Fr");
    extract 34 32
    dup
    bury 29
    // contracts/bls12381_common.algo.ts:91
    // return value.asBigUint() < BLS12_381_SCALAR_MODULUS;
    bytec_0 // 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001
    b<
    // contracts/plonk_bls12381.algo.ts:273
    // assert(inField(lw.zh), "lw.zh not in Fr");
    assert // lw.zh not in Fr
    // contracts/plonk_bls12381.algo.ts:274
    // for (let i: uint64 = 0; i < lw.L.length; i++) {
    intc_3 // 0
    bury 23

main_while_top@11:
    // contracts/plonk_bls12381.algo.ts:274
    // for (let i: uint64 = 0; i < lw.L.length; i++) {
    dig 20
    dup
    intc_3 // 0
    extract_uint16
    dig 1
    len
    substring3
    dup
    bury 43
    intc_3 // 0
    extract_uint16 // on error: invalid array length header
    dup
    bury 25
    dig 23
    >
    bz main_after_while@13
    // contracts/plonk_bls12381.algo.ts:274-275
    // for (let i: uint64 = 0; i < lw.L.length; i++) {
    //   assert(inField(lw.L[i] as Uint256), "lw.L not in Fr");
    dig 41
    extract 2 0
    dig 23
    dup
    cover 2
    intc_0 // 32
    *
    intc_0 // 32
    extract3 // on error: index access is out of bounds
    // contracts/bls12381_common.algo.ts:91
    // return value.asBigUint() < BLS12_381_SCALAR_MODULUS;
    bytec_0 // 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001
    b<
    // contracts/plonk_bls12381.algo.ts:275
    // assert(inField(lw.L[i] as Uint256), "lw.L not in Fr");
    assert // lw.L not in Fr
    // contracts/plonk_bls12381.algo.ts:274
    // for (let i: uint64 = 0; i < lw.L.length; i++) {
    intc_2 // 1
    +
    bury 23
    b main_while_top@11

main_after_while@13:
    // contracts/plonk_bls12381.algo.ts:287
    // let nPow: uint64 = 1;
    intc_2 // 1
    bury 22
    // contracts/plonk_bls12381.algo.ts:288
    // let xin = challenges.xi.asBigUint();
    dig 34
    extract 96 32
    dup
    bury 27
    // contracts/plonk_bls12381.algo.ts:289
    // for (let i: uint64 = 0; i < vk.power; i++) {
    intc_3 // 0
    bury 24
    bury 25

main_while_top@14:
    // contracts/plonk_bls12381.algo.ts:289
    // for (let i: uint64 = 0; i < vk.power; i++) {
    dig 18
    pushint 768 // 768
    extract_uint64
    dig 23
    >
    bz main_after_while@16
    // contracts/plonk_bls12381.algo.ts:70
    // return (a * b) % BLS12_381_SCALAR_MODULUS;
    dig 24
    dup
    b*
    bytec_0 // 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001
    b%
    bury 25
    // contracts/plonk_bls12381.algo.ts:291
    // nPow *= 2;
    dig 21
    pushint 2 // 2
    *
    bury 22
    // contracts/plonk_bls12381.algo.ts:289
    // for (let i: uint64 = 0; i < vk.power; i++) {
    dig 22
    intc_2 // 1
    +
    bury 23
    b main_while_top@14

main_after_while@16:
    // contracts/plonk_bls12381.algo.ts:293
    // const xinExpected = new Uint256(xin);
    dig 24
    dup
    len
    intc_0 // 32
    <=
    assert // overflow
    intc_0 // 32
    bzero
    dup
    bury 43
    swap
    dig 1
    b|
    // contracts/plonk_bls12381.algo.ts:294
    // assert(lw.xin.asBigUint() === xinExpected.asBigUint(), "lw.xin != xi^n");
    dig 30
    dig 1
    b==
    assert // lw.xin != xi^n
    // contracts/plonk_bls12381.algo.ts:297
    // const zhExpected = new Uint256(frSub(xinExpected.asBigUint(), BigUint(1)));
    bytec_2 // 0x01
    callsub frSub
    dup
    len
    intc_0 // 32
    <=
    assert // overflow
    b|
    // contracts/plonk_bls12381.algo.ts:298
    // assert(lw.zh.asBigUint() === zhExpected.asBigUint(), "lw.zh != xi^n - 1");
    dig 28
    b==
    assert // lw.zh != xi^n - 1
    // contracts/plonk_bls12381.algo.ts:301
    // const required: uint64 = vk.nPublic === 0 ? 1 : vk.nPublic;
    dig 1
    bnz main_ternary_false@18
    intc_2 // 1

main_ternary_merge@19:
    // contracts/plonk_bls12381.algo.ts:302
    // assert(lw.L.length >= required + 1, "lw.L length too short"); // L[0] unused; start at index 1
    intc_2 // 1
    +
    dig 24
    <=
    assert // lw.L length too short
    // contracts/plonk_bls12381.algo.ts:305
    // assert(challenges.xi.asBigUint() !== BigUint(1), "invalid xi (equals 1)");
    dig 25
    bytec_2 // 0x01
    b!=
    assert // invalid xi (equals 1)
    // contracts/plonk_bls12381.algo.ts:366
    // challenges.xin = lw.xin;
    dig 34
    pushint 352 // 352
    dig 30
    replace3
    // contracts/plonk_bls12381.algo.ts:367
    // challenges.zh = lw.zh;
    intc 4 // 384
    dig 29
    replace3
    bury 35
    // contracts/plonk_bls12381.algo.ts:600
    // let pi = BigUint(0);
    bytec_1 // 0x
    bury 34
    // contracts/plonk_bls12381.algo.ts:601
    // for (let i: uint64 = 0; i < publicSignals.length; i++) {
    intc_3 // 0
    bury 23

main_while_top@20:
    // contracts/plonk_bls12381.algo.ts:601
    // for (let i: uint64 = 0; i < publicSignals.length; i++) {
    dig 22
    dig 3
    <
    bz main_after_while@22
    // contracts/plonk_bls12381.algo.ts:602
    // const w = frScalar((publicSignals[i] as Uint256).asBigUint());
    dig 19
    extract 2 0
    dig 23
    dup
    cover 2
    intc_0 // 32
    *
    intc_0 // 32
    extract3 // on error: index access is out of bounds
    // contracts/bls12381_common.algo.ts:37
    // return a % BLS12_381_SCALAR_MODULUS;
    bytec_0 // 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001
    b%
    // contracts/plonk_bls12381.algo.ts:603
    // pi = frSub(pi, frMul(w, (L[i + 1] as Uint256).asBigUint()));
    swap
    intc_2 // 1
    +
    dup
    bury 25
    dig 43
    extract 2 0
    swap
    intc_0 // 32
    *
    intc_0 // 32
    extract3 // on error: index access is out of bounds
    // contracts/plonk_bls12381.algo.ts:70
    // return (a * b) % BLS12_381_SCALAR_MODULUS;
    b*
    bytec_0 // 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001
    b%
    // contracts/plonk_bls12381.algo.ts:603
    // pi = frSub(pi, frMul(w, (L[i + 1] as Uint256).asBigUint()));
    dig 34
    swap
    callsub frSub
    bury 34
    b main_while_top@20

main_after_while@22:
    // contracts/plonk_bls12381.algo.ts:605
    // return new Uint256(pi);
    dig 33
    dup
    len
    intc_0 // 32
    <=
    assert // overflow
    dig 41
    dup
    cover 2
    b|
    // contracts/plonk_bls12381.algo.ts:373
    // const r0 = calculateR0(proof, challenges, pi, lw.L[1] as Uint256);
    dig 43
    extract 34 32
    // contracts/plonk_bls12381.algo.ts:626
    // frMul(challenges.alpha.asBigUint(), challenges.alpha.asBigUint()),
    dig 37
    dup
    cover 2
    extract 64 32
    // contracts/plonk_bls12381.algo.ts:70
    // return (a * b) % BLS12_381_SCALAR_MODULUS;
    dup
    dig 1
    b*
    bytec_0 // 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001
    b%
    uncover 2
    b*
    bytec_0 // 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001
    b%
    // contracts/plonk_bls12381.algo.ts:633
    // frMul(challenges.beta.asBigUint(), proof.eval_s1.asBigUint()),
    dig 2
    extract 0 32
    // contracts/plonk_bls12381.algo.ts:70
    // return (a * b) % BLS12_381_SCALAR_MODULUS;
    dup
    dig 12
    dup
    cover 8
    b*
    bytec_0 // 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001
    b%
    // contracts/plonk_bls12381.algo.ts:144
    // const aN: biguint = a % r;
    dig 16
    dup
    cover 7
    bytec_0 // 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001
    b%
    // contracts/plonk_bls12381.algo.ts:145
    // const bN: biguint = b % r;
    swap
    bytec_0 // 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001
    b%
    // contracts/plonk_bls12381.algo.ts:146
    // return (aN + bN) % r;
    dig 1
    b+
    bytec_0 // 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001
    b%
    // contracts/plonk_bls12381.algo.ts:635
    // e3a = frAdd(e3a, challenges.gamma.asBigUint());
    dig 5
    extract 32 32
    // contracts/plonk_bls12381.algo.ts:144
    // const aN: biguint = a % r;
    swap
    bytec_0 // 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001
    b%
    // contracts/plonk_bls12381.algo.ts:145
    // const bN: biguint = b % r;
    swap
    bytec_0 // 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001
    b%
    // contracts/plonk_bls12381.algo.ts:146
    // return (aN + bN) % r;
    swap
    dig 1
    b+
    bytec_0 // 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001
    b%
    // contracts/plonk_bls12381.algo.ts:70
    // return (a * b) % BLS12_381_SCALAR_MODULUS;
    dig 3
    dig 16
    dup
    cover 12
    b*
    bytec_0 // 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001
    b%
    // contracts/plonk_bls12381.algo.ts:144
    // const aN: biguint = a % r;
    dig 20
    dup
    cover 4
    bytec_0 // 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001
    b%
    // contracts/plonk_bls12381.algo.ts:145
    // const bN: biguint = b % r;
    swap
    bytec_0 // 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001
    b%
    // contracts/plonk_bls12381.algo.ts:146
    // return (aN + bN) % r;
    dig 1
    b+
    bytec_0 // 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001
    b%
    // contracts/plonk_bls12381.algo.ts:144
    // const aN: biguint = a % r;
    bytec_0 // 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001
    b%
    // contracts/plonk_bls12381.algo.ts:146
    // return (aN + bN) % r;
    dig 3
    b+
    bytec_0 // 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001
    b%
    // contracts/plonk_bls12381.algo.ts:144
    // const aN: biguint = a % r;
    dig 21
    dup
    cover 14
    bytec_0 // 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001
    b%
    // contracts/plonk_bls12381.algo.ts:146
    // return (aN + bN) % r;
    dup
    dig 5
    b+
    bytec_0 // 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001
    b%
    // contracts/plonk_bls12381.algo.ts:70
    // return (a * b) % BLS12_381_SCALAR_MODULUS;
    uncover 4
    uncover 3
    b*
    bytec_0 // 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001
    b%
    dup
    uncover 2
    b*
    bytec_0 // 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001
    b%
    dig 20
    dup
    cover 14
    b*
    bytec_0 // 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001
    b%
    dig 9
    b*
    bytec_0 // 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001
    b%
    // contracts/plonk_bls12381.algo.ts:650
    // const r0 = frSub(frSub(e1, e2), e3);
    uncover 11
    dig 9
    callsub frSub
    swap
    callsub frSub
    // contracts/plonk_bls12381.algo.ts:651
    // return new Uint256(r0);
    dup
    len
    intc_0 // 32
    <=
    assert // overflow
    uncover 13
    b|
    // contracts/plonk_bls12381.algo.ts:679
    // points = op.concat(points, proof.T1);
    dig 48
    dig 30
    concat
    // contracts/plonk_bls12381.algo.ts:680
    // points = op.concat(points, proof.T2);
    dig 29
    concat
    // contracts/plonk_bls12381.algo.ts:681
    // points = op.concat(points, proof.T3);
    dig 28
    concat
    // contracts/plonk_bls12381.algo.ts:682
    // points = op.concat(points, vk.Qc);
    dig 56
    concat
    // contracts/plonk_bls12381.algo.ts:70
    // return (a * b) % BLS12_381_SCALAR_MODULUS;
    dig 12
    dig 7
    b*
    bytec_0 // 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001
    b%
    // contracts/plonk_bls12381.algo.ts:691
    // const quotientScalar1 = frSub(BigUint(0), challenges.zh.asBigUint()); // −zh (applies to T1)
    dig 12
    intc 4 // 384
    intc_0 // 32
    extract3
    bytec_1 // 0x
    dig 1
    callsub frSub
    // contracts/plonk_bls12381.algo.ts:694
    // frMul(challenges.xin.asBigUint(), challenges.zh.asBigUint()),
    dig 14
    pushint 352 // 352
    intc_0 // 32
    extract3
    // contracts/plonk_bls12381.algo.ts:70
    // return (a * b) % BLS12_381_SCALAR_MODULUS;
    dup
    dig 3
    b*
    bytec_0 // 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001
    b%
    // contracts/plonk_bls12381.algo.ts:693
    // BigUint(0),
    bytec_1 // 0x
    // contracts/plonk_bls12381.algo.ts:692-695
    // const quotientScalar2 = frSub(
    //   BigUint(0),
    //   frMul(challenges.xin.asBigUint(), challenges.zh.asBigUint()),
    // ); // −xin·zh (applies to T2)
    swap
    callsub frSub
    // contracts/plonk_bls12381.algo.ts:70
    // return (a * b) % BLS12_381_SCALAR_MODULUS;
    dig 1
    uncover 2
    b*
    bytec_0 // 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001
    b%
    uncover 3
    b*
    bytec_0 // 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001
    b%
    // contracts/plonk_bls12381.algo.ts:697
    // BigUint(0),
    bytec_1 // 0x
    // contracts/plonk_bls12381.algo.ts:696-702
    // const quotientScalar3 = frSub(
    //   BigUint(0),
    //   frMul(
    //     frMul(challenges.xin.asBigUint(), challenges.xin.asBigUint()),
    //     challenges.zh.asBigUint(),
    //   ),
    // ); // −xin²·zh (applies to T3)
    swap
    callsub frSub
    // contracts/plonk_bls12381.algo.ts:705
    // const betaxi = frMul(challenges.beta.asBigUint(), challenges.xi.asBigUint());
    dig 15
    extract 96 32
    // contracts/plonk_bls12381.algo.ts:70
    // return (a * b) % BLS12_381_SCALAR_MODULUS;
    dig 13
    dig 1
    b*
    bytec_0 // 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001
    b%
    // contracts/plonk_bls12381.algo.ts:145
    // const bN: biguint = b % r;
    dup
    bytec_0 // 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001
    b%
    // contracts/plonk_bls12381.algo.ts:146
    // return (aN + bN) % r;
    uncover 14
    b+
    bytec_0 // 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001
    b%
    // contracts/plonk_bls12381.algo.ts:144
    // const aN: biguint = a % r;
    bytec_0 // 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001
    b%
    // contracts/plonk_bls12381.algo.ts:146
    // return (aN + bN) % r;
    dig 12
    b+
    bytec_0 // 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001
    b%
    // contracts/plonk_bls12381.algo.ts:711
    // frAdd(proof.eval_b.asBigUint(), frMul(betaxi, BigUint(vk.k1))),
    dig 41
    dup
    cover 3
    pushints 784 8 // 784, 8
    extract3
    // contracts/plonk_bls12381.algo.ts:70
    // return (a * b) % BLS12_381_SCALAR_MODULUS;
    dig 2
    b*
    bytec_0 // 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001
    b%
    // contracts/plonk_bls12381.algo.ts:145
    // const bN: biguint = b % r;
    bytec_0 // 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001
    b%
    // contracts/plonk_bls12381.algo.ts:146
    // return (aN + bN) % r;
    uncover 13
    b+
    bytec_0 // 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001
    b%
    // contracts/plonk_bls12381.algo.ts:144
    // const aN: biguint = a % r;
    bytec_0 // 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001
    b%
    // contracts/plonk_bls12381.algo.ts:146
    // return (aN + bN) % r;
    dig 13
    b+
    bytec_0 // 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001
    b%
    // contracts/plonk_bls12381.algo.ts:715
    // frAdd(proof.eval_c.asBigUint(), frMul(betaxi, BigUint(vk.k2))),
    dig 3
    pushints 792 8 // 792, 8
    extract3
    // contracts/plonk_bls12381.algo.ts:70
    // return (a * b) % BLS12_381_SCALAR_MODULUS;
    uncover 3
    b*
    bytec_0 // 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001
    b%
    // contracts/plonk_bls12381.algo.ts:145
    // const bN: biguint = b % r;
    bytec_0 // 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001
    b%
    // contracts/plonk_bls12381.algo.ts:146
    // return (aN + bN) % r;
    uncover 12
    b+
    bytec_0 // 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001
    b%
    // contracts/plonk_bls12381.algo.ts:144
    // const aN: biguint = a % r;
    bytec_0 // 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001
    b%
    // contracts/plonk_bls12381.algo.ts:146
    // return (aN + bN) % r;
    uncover 12
    b+
    bytec_0 // 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001
    b%
    // contracts/plonk_bls12381.algo.ts:70
    // return (a * b) % BLS12_381_SCALAR_MODULUS;
    cover 2
    b*
    bytec_0 // 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001
    b%
    b*
    bytec_0 // 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001
    b%
    dig 13
    b*
    bytec_0 // 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001
    b%
    // contracts/plonk_bls12381.algo.ts:144
    // const aN: biguint = a % r;
    bytec_0 // 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001
    b%
    // contracts/plonk_bls12381.algo.ts:145
    // const bN: biguint = b % r;
    uncover 12
    bytec_0 // 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001
    b%
    // contracts/plonk_bls12381.algo.ts:146
    // return (aN + bN) % r;
    b+
    bytec_0 // 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001
    b%
    // contracts/plonk_bls12381.algo.ts:726
    // const zScalar = frAdd(frAdd(d2a, d2b), challenges.u.asBigUint());
    dig 13
    pushint 320 // 320
    intc_0 // 32
    extract3
    // contracts/plonk_bls12381.algo.ts:144
    // const aN: biguint = a % r;
    swap
    bytec_0 // 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001
    b%
    // contracts/plonk_bls12381.algo.ts:145
    // const bN: biguint = b % r;
    dig 1
    bytec_0 // 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001
    b%
    // contracts/plonk_bls12381.algo.ts:146
    // return (aN + bN) % r;
    b+
    bytec_0 // 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001
    b%
    // contracts/plonk_bls12381.algo.ts:70
    // return (a * b) % BLS12_381_SCALAR_MODULUS;
    uncover 13
    uncover 13
    b*
    bytec_0 // 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001
    b%
    dig 15
    b*
    bytec_0 // 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001
    b%
    uncover 11
    b*
    bytec_0 // 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001
    b%
    // contracts/plonk_bls12381.algo.ts:750
    // points = op.concat(points, proof.Z);
    uncover 9
    dig 32
    concat
    // contracts/plonk_bls12381.algo.ts:751
    // points = op.concat(points, vk.S3);
    dig 54
    concat
    // contracts/plonk_bls12381.algo.ts:752
    // points = op.concat(points, proof.A);
    dig 35
    concat
    // contracts/plonk_bls12381.algo.ts:753
    // points = op.concat(points, proof.B);
    dig 34
    concat
    // contracts/plonk_bls12381.algo.ts:754
    // points = op.concat(points, proof.C);
    dig 33
    concat
    // contracts/plonk_bls12381.algo.ts:755
    // points = op.concat(points, vk.S1);
    dig 56
    concat
    // contracts/plonk_bls12381.algo.ts:756
    // points = op.concat(points, vk.S2);
    dig 55
    concat
    // contracts/plonk_bls12381.algo.ts:759
    // let scalars = op.concat(b32(gateScalar1), b32(gateScalar2));
    uncover 9
    callsub b32
    dig 13
    callsub b32
    concat
    // contracts/plonk_bls12381.algo.ts:760
    // scalars = op.concat(scalars, b32(gateScalar3));
    dig 11
    callsub b32
    concat
    // contracts/plonk_bls12381.algo.ts:761
    // scalars = op.concat(scalars, b32(gateScalar4));
    dig 15
    callsub b32
    concat
    // contracts/plonk_bls12381.algo.ts:762
    // scalars = op.concat(scalars, b32(quotientScalar1));
    uncover 9
    callsub b32
    concat
    // contracts/plonk_bls12381.algo.ts:763
    // scalars = op.concat(scalars, b32(quotientScalar2));
    uncover 8
    callsub b32
    concat
    // contracts/plonk_bls12381.algo.ts:764
    // scalars = op.concat(scalars, b32(quotientScalar3));
    uncover 7
    callsub b32
    concat
    // contracts/plonk_bls12381.algo.ts:765
    // scalars = op.concat(scalars, b32(BigUint(1))); // Qc with scalar 1
    bytec_2 // 0x01
    callsub b32
    concat
    // contracts/plonk_bls12381.algo.ts:766
    // scalars = op.concat(scalars, b32(zScalar)); // Z with zScalar
    uncover 3
    callsub b32
    concat
    // contracts/plonk_bls12381.algo.ts:767
    // scalars = op.concat(scalars, b32(frSub(BigUint(0), s3Scalar))); // S3 with -s3Scalar
    bytec_1 // 0x
    uncover 3
    callsub frSub
    callsub b32
    concat
    // contracts/plonk_bls12381.algo.ts:768
    // scalars = op.concat(scalars, (challenges.v[1] as Uint256).bytes);
    uncover 7
    extract 128 192
    dup
    extract 32 32 // on error: index access is out of bounds
    uncover 2
    dig 1
    concat
    // contracts/plonk_bls12381.algo.ts:768-769
    // scalars = op.concat(scalars, (challenges.v[1] as Uint256).bytes);
    // scalars = op.concat(scalars, (challenges.v[2] as Uint256).bytes);
    dig 2
    extract 64 32 // on error: index access is out of bounds
    // contracts/plonk_bls12381.algo.ts:769
    // scalars = op.concat(scalars, (challenges.v[2] as Uint256).bytes);
    swap
    dig 1
    concat
    // contracts/plonk_bls12381.algo.ts:770
    // scalars = op.concat(scalars, (challenges.v[3] as Uint256).bytes);
    dig 3
    extract 96 32 // on error: index access is out of bounds
    swap
    dig 1
    concat
    // contracts/plonk_bls12381.algo.ts:771
    // scalars = op.concat(scalars, (challenges.v[4] as Uint256).bytes);
    dig 4
    extract 128 32 // on error: index access is out of bounds
    swap
    dig 1
    concat
    // contracts/plonk_bls12381.algo.ts:772
    // scalars = op.concat(scalars, (challenges.v[5] as Uint256).bytes);
    uncover 5
    extract 160 32 // on error: index access is out of bounds
    swap
    dig 1
    concat
    // contracts/plonk_bls12381.algo.ts:775-779
    // const F = op.EllipticCurve.scalarMulMulti(
    //   op.Ec.BLS12_381g1,
    //   points,
    //   scalars,
    // ).toFixed({ length: 96 });
    uncover 6
    swap
    ec_multi_scalar_mul BLS12_381g1
    dup
    len
    intc_1 // 96
    ==
    assert // Length must be 96
    // contracts/plonk_bls12381.algo.ts:70
    // return (a * b) % BLS12_381_SCALAR_MODULUS;
    uncover 5
    uncover 11
    b*
    bytec_0 // 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001
    b%
    // contracts/plonk_bls12381.algo.ts:795-798
    // let e = frSub(
    //   frMul((challenges.v[1] as Uint256).asBigUint(), proof.eval_a.asBigUint()),
    //   r0.asBigUint(),
    // );
    uncover 9
    callsub frSub
    // contracts/plonk_bls12381.algo.ts:70
    // return (a * b) % BLS12_381_SCALAR_MODULUS;
    uncover 5
    uncover 9
    b*
    bytec_0 // 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001
    b%
    // contracts/plonk_bls12381.algo.ts:144
    // const aN: biguint = a % r;
    swap
    bytec_0 // 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001
    b%
    // contracts/plonk_bls12381.algo.ts:145
    // const bN: biguint = b % r;
    swap
    bytec_0 // 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001
    b%
    // contracts/plonk_bls12381.algo.ts:146
    // return (aN + bN) % r;
    b+
    bytec_0 // 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001
    b%
    // contracts/plonk_bls12381.algo.ts:70
    // return (a * b) % BLS12_381_SCALAR_MODULUS;
    uncover 4
    uncover 9
    b*
    bytec_0 // 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001
    b%
    // contracts/plonk_bls12381.algo.ts:144
    // const aN: biguint = a % r;
    swap
    bytec_0 // 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001
    b%
    // contracts/plonk_bls12381.algo.ts:145
    // const bN: biguint = b % r;
    swap
    bytec_0 // 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001
    b%
    // contracts/plonk_bls12381.algo.ts:146
    // return (aN + bN) % r;
    b+
    bytec_0 // 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001
    b%
    // contracts/plonk_bls12381.algo.ts:70
    // return (a * b) % BLS12_381_SCALAR_MODULUS;
    uncover 3
    uncover 9
    b*
    bytec_0 // 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001
    b%
    // contracts/plonk_bls12381.algo.ts:144
    // const aN: biguint = a % r;
    swap
    bytec_0 // 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001
    b%
    // contracts/plonk_bls12381.algo.ts:145
    // const bN: biguint = b % r;
    swap
    bytec_0 // 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001
    b%
    // contracts/plonk_bls12381.algo.ts:146
    // return (aN + bN) % r;
    b+
    bytec_0 // 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001
    b%
    // contracts/plonk_bls12381.algo.ts:70
    // return (a * b) % BLS12_381_SCALAR_MODULUS;
    uncover 2
    uncover 7
    b*
    bytec_0 // 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001
    b%
    // contracts/plonk_bls12381.algo.ts:144
    // const aN: biguint = a % r;
    swap
    bytec_0 // 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001
    b%
    // contracts/plonk_bls12381.algo.ts:145
    // const bN: biguint = b % r;
    swap
    bytec_0 // 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001
    b%
    // contracts/plonk_bls12381.algo.ts:146
    // return (aN + bN) % r;
    b+
    bytec_0 // 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001
    b%
    // contracts/plonk_bls12381.algo.ts:70
    // return (a * b) % BLS12_381_SCALAR_MODULUS;
    dig 2
    uncover 6
    b*
    bytec_0 // 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001
    b%
    // contracts/plonk_bls12381.algo.ts:144
    // const aN: biguint = a % r;
    swap
    bytec_0 // 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001
    b%
    // contracts/plonk_bls12381.algo.ts:145
    // const bN: biguint = b % r;
    swap
    bytec_0 // 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001
    b%
    // contracts/plonk_bls12381.algo.ts:146
    // return (aN + bN) % r;
    b+
    bytec_0 // 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001
    b%
    // contracts/plonk_bls12381.algo.ts:817
    // const res = g1TimesFr(G1_ONE.toFixed({ length: 96 }), e);
    pushbytes 0x17f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb08b3f481e3aaa0f1a09e30ed741d8ae4fcf5e095d5d00af600db18cb2c04b3edd03cc744a2888ae40caa232946c5e7e1
    // contracts/bls12381_common.algo.ts:62
    // return op.EllipticCurve.scalarMul(op.Ec.BLS12_381g1, p, Bytes(s)).toFixed({
    swap
    ec_scalar_mul BLS12_381g1
    // contracts/bls12381_common.algo.ts:62-64
    // return op.EllipticCurve.scalarMul(op.Ec.BLS12_381g1, p, Bytes(s)).toFixed({
    //   length: 96,
    // });
    dup
    len
    intc_1 // 96
    ==
    assert // Length must be 96
    // contracts/bls12381_common.algo.ts:62
    // return op.EllipticCurve.scalarMul(op.Ec.BLS12_381g1, p, Bytes(s)).toFixed({
    dig 14
    dig 3
    ec_scalar_mul BLS12_381g1
    // contracts/bls12381_common.algo.ts:62-64
    // return op.EllipticCurve.scalarMul(op.Ec.BLS12_381g1, p, Bytes(s)).toFixed({
    //   length: 96,
    // });
    dup
    len
    intc_1 // 96
    ==
    assert // Length must be 96
    // contracts/bls12381_common.algo.ts:73
    // return op.EllipticCurve.add(op.Ec.BLS12_381g1, p1, p2).toFixed({
    dig 16
    swap
    ec_add BLS12_381g1
    // contracts/bls12381_common.algo.ts:73-75
    // return op.EllipticCurve.add(op.Ec.BLS12_381g1, p1, p2).toFixed({
    //   length: 96,
    // });
    dup
    len
    intc_1 // 96
    ==
    assert // Length must be 96
    // contracts/plonk_bls12381.algo.ts:70
    // return (a * b) % BLS12_381_SCALAR_MODULUS;
    uncover 3
    dig 5
    b*
    bytec_0 // 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001
    b%
    // contracts/plonk_bls12381.algo.ts:849
    // ROOT_OF_UNITY,
    bytec 5 // TMPL_ROOT_OF_UNITY
    // contracts/plonk_bls12381.algo.ts:70
    // return (a * b) % BLS12_381_SCALAR_MODULUS;
    b*
    bytec_0 // 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001
    b%
    // contracts/plonk_bls12381.algo.ts:851
    // const pairingScalars = op.concat(challenges.xi.bytes, b32(s));
    callsub b32
    uncover 5
    swap
    concat
    // contracts/plonk_bls12381.algo.ts:853-857
    // let B1 = op.EllipticCurve.scalarMulMulti(
    //   op.Ec.BLS12_381g1,
    //   pairingPoints,
    //   pairingScalars,
    // ).toFixed({ length: 96 });
    dig 36
    swap
    ec_multi_scalar_mul BLS12_381g1
    dup
    len
    intc_1 // 96
    ==
    assert // Length must be 96
    // contracts/bls12381_common.algo.ts:73
    // return op.EllipticCurve.add(op.Ec.BLS12_381g1, p1, p2).toFixed({
    uncover 3
    ec_add BLS12_381g1
    // contracts/bls12381_common.algo.ts:73-75
    // return op.EllipticCurve.add(op.Ec.BLS12_381g1, p1, p2).toFixed({
    //   length: 96,
    // });
    dup
    len
    intc_1 // 96
    ==
    assert // Length must be 96
    // contracts/bls12381_common.algo.ts:62
    // return op.EllipticCurve.scalarMul(op.Ec.BLS12_381g1, p, Bytes(s)).toFixed({
    uncover 2
    // contracts/bls12381_common.algo.ts:84
    // return g1TimesFr(p, R_MINUS_1);
    bytec_3 // 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000000
    // contracts/bls12381_common.algo.ts:62
    // return op.EllipticCurve.scalarMul(op.Ec.BLS12_381g1, p, Bytes(s)).toFixed({
    ec_scalar_mul BLS12_381g1
    // contracts/bls12381_common.algo.ts:62-64
    // return op.EllipticCurve.scalarMul(op.Ec.BLS12_381g1, p, Bytes(s)).toFixed({
    //   length: 96,
    // });
    dup
    len
    intc_1 // 96
    ==
    assert // Length must be 96
    // contracts/bls12381_common.algo.ts:73
    // return op.EllipticCurve.add(op.Ec.BLS12_381g1, p1, p2).toFixed({
    ec_add BLS12_381g1
    // contracts/bls12381_common.algo.ts:73-75
    // return op.EllipticCurve.add(op.Ec.BLS12_381g1, p1, p2).toFixed({
    //   length: 96,
    // });
    dup
    len
    intc_1 // 96
    ==
    assert // Length must be 96
    // contracts/bls12381_common.algo.ts:62
    // return op.EllipticCurve.scalarMul(op.Ec.BLS12_381g1, p, Bytes(s)).toFixed({
    swap
    // contracts/bls12381_common.algo.ts:84
    // return g1TimesFr(p, R_MINUS_1);
    bytec_3 // 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000000
    // contracts/bls12381_common.algo.ts:62
    // return op.EllipticCurve.scalarMul(op.Ec.BLS12_381g1, p, Bytes(s)).toFixed({
    ec_scalar_mul BLS12_381g1
    // contracts/bls12381_common.algo.ts:62-64
    // return op.EllipticCurve.scalarMul(op.Ec.BLS12_381g1, p, Bytes(s)).toFixed({
    //   length: 96,
    // });
    dup
    len
    intc_1 // 96
    ==
    assert // Length must be 96
    // contracts/plonk_bls12381.algo.ts:864
    // op.concat(g1Neg(A1), B1), // G1 points
    swap
    concat
    // contracts/plonk_bls12381.algo.ts:865
    // op.concat(vk.X_2, G2_ONE), // G2 points
    swap
    pushints 800 192 // 800, 192
    extract3
    pushbytes 0x024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb813e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e0ce5d527727d6e118cc9cdc6da2e351aadfd9baa8cbdd3a76d429a695160d12c923ac9cc3baca289e193548608b828010606c4a02ea734cc32acd2b02bc28b99cb3e287e85a763af267492ab572e99ab3f370d275cec1da1aaa9075ff05f79be
    concat
    // contracts/plonk_bls12381.algo.ts:862-866
    // const res = op.EllipticCurve.pairingCheck(
    //   op.Ec.BLS12_381g1,
    //   op.concat(g1Neg(A1), B1), // G1 points
    //   op.concat(vk.X_2, G2_ONE), // G2 points
    // );
    ec_pairing_check BLS12_381g1
    // contracts/plonk_verifier.algo.ts:60
    // assert(verifyPlonkFromTemplate(signals, proof, lw), "Verification failed");
    assert // Verification failed
    // contracts/plonk_verifier.algo.ts:62
    // return true;
    intc_2 // 1
    return

main_ternary_false@18:
    dig 1
    b main_ternary_merge@19


// contracts/bls12381_common.algo.ts::b32(a: bytes) -> bytes:
b32:
    // contracts/bls12381_common.algo.ts:44
    // export function b32(a: biguint): bytes<32> {
    proto 1 1
    // contracts/bls12381_common.algo.ts:45
    // return new Uint256(a).bytes.toFixed({ length: 32 });
    frame_dig -1
    len
    intc_0 // 32
    <=
    assert // overflow
    intc_0 // 32
    bzero
    frame_dig -1
    b|
    dup
    len
    intc_0 // 32
    ==
    assert // Length must be 32
    retsub


// contracts/plonk_bls12381.algo.ts::frSub(a: bytes, b: bytes) -> bytes:
frSub:
    // contracts/plonk_bls12381.algo.ts:130
    // function frSub(a: biguint, b: biguint): biguint {
    proto 2 1
    // contracts/plonk_bls12381.algo.ts:132
    // const aN: biguint = a % r;
    frame_dig -2
    bytec_0 // 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001
    b%
    // contracts/plonk_bls12381.algo.ts:133
    // const bN: biguint = b % r;
    frame_dig -1
    bytec_0 // 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001
    b%
    // contracts/plonk_bls12381.algo.ts:134
    // return (aN + r - bN) % r;
    swap
    bytec_0 // 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001
    b+
    swap
    b-
    bytec_0 // 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001
    b%
    retsub


// contracts/plonk_bls12381.algo.ts::getChallenge(td: bytes) -> bytes:
getChallenge:
    // contracts/plonk_bls12381.algo.ts:440
    // export function getChallenge(td: bytes): Uint256 {
    proto 1 1
    // contracts/plonk_bls12381.algo.ts:441
    // let hash = op.keccak256(td);
    frame_dig -1
    keccak256
    // contracts/bls12381_common.algo.ts:37
    // return a % BLS12_381_SCALAR_MODULUS;
    bytec_0 // 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001
    b%
    // contracts/plonk_bls12381.algo.ts:442
    // return new Uint256(frScalar(BigUint(hash)));
    dup
    len
    intc_0 // 32
    <=
    assert // overflow
    intc_0 // 32
    bzero
    b|
    retsub
`;
