
export const PLONK_LSIG_SOURCE = `#pragma version 11
#pragma typetrack false

// contracts/plonk_verifier.algo.ts::program() -> uint64:
main:
    intcblock 32 96 1 0 384 TMPL_APP_OFFSET
    bytecblock 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001 0x 0x01 TMPL_ROOT_OF_UNITY 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000000 TMPL_VERIFICATION_KEY
    intc_3 // 0
    dupn 23
    bytec_1 // ""
    dupn 3
    // contracts/plonk_verifier.algo.ts:53
    // assertMatch(Txn, { fee: 0, rekeyTo: Global.zeroAddress });
    txn Fee
    !
    txn RekeyTo
    global ZeroAddress
    ==
    &&
    assert // assert target is match for conditions
    // contracts/plonk_verifier.algo.ts:55
    // const idx: uint64 = Txn.groupIndex + APP_OFFSET;
    txn GroupIndex
    intc 5 // TMPL_APP_OFFSET
    +
    // contracts/plonk_verifier.algo.ts:57
    // const proof = decodeArc4<PlonkProof>(GTxn.applicationArgs(idx, 2));
    dup
    pushint 2 // 2
    gtxnsas ApplicationArgs
    // contracts/plonk_verifier.algo.ts:58
    // const signals = decodeArc4<PublicSignals>(GTxn.applicationArgs(idx, 1));
    swap
    intc_2 // 1
    gtxnsas ApplicationArgs
    dup
    uncover 2
    // contracts/plonk_bls12381.algo.ts:261
    // return verify(decodeArc4<PlonkVerificationKey>(vkBytes), signals, proof);
    bytec 5 // TMPL_VERIFICATION_KEY
    dup
    cover 3
    cover 3
    // contracts/plonk_bls12381.algo.ts:289
    // assert(groupCheck(proof.A), "A not in G1");
    dup
    extract 0 96
    dup
    cover 4
    // contracts/plonk_bls12381.algo.ts:265
    // return op.EllipticCurve.subgroupCheck(op.Ec.BLS12_381g1, p);
    ec_subgroup_check BLS12_381g1
    // contracts/plonk_bls12381.algo.ts:289
    // assert(groupCheck(proof.A), "A not in G1");
    assert // A not in G1
    // contracts/plonk_bls12381.algo.ts:290
    // assert(groupCheck(proof.B), "B not in G1");
    dup
    extract 96 96
    dup
    cover 4
    // contracts/plonk_bls12381.algo.ts:265
    // return op.EllipticCurve.subgroupCheck(op.Ec.BLS12_381g1, p);
    ec_subgroup_check BLS12_381g1
    // contracts/plonk_bls12381.algo.ts:290
    // assert(groupCheck(proof.B), "B not in G1");
    assert // B not in G1
    // contracts/plonk_bls12381.algo.ts:291
    // assert(groupCheck(proof.C), "C not in G1");
    dup
    extract 192 96
    dup
    cover 4
    // contracts/plonk_bls12381.algo.ts:265
    // return op.EllipticCurve.subgroupCheck(op.Ec.BLS12_381g1, p);
    ec_subgroup_check BLS12_381g1
    // contracts/plonk_bls12381.algo.ts:291
    // assert(groupCheck(proof.C), "C not in G1");
    assert // C not in G1
    // contracts/plonk_bls12381.algo.ts:292
    // assert(groupCheck(proof.Z), "Z not in G1");
    dup
    pushint 288 // 288
    intc_1 // 96
    extract3
    dup
    cover 4
    // contracts/plonk_bls12381.algo.ts:265
    // return op.EllipticCurve.subgroupCheck(op.Ec.BLS12_381g1, p);
    ec_subgroup_check BLS12_381g1
    // contracts/plonk_bls12381.algo.ts:292
    // assert(groupCheck(proof.Z), "Z not in G1");
    assert // Z not in G1
    // contracts/plonk_bls12381.algo.ts:293
    // assert(groupCheck(proof.T1), "T1 not in G1");
    dup
    intc 4 // 384
    intc_1 // 96
    extract3
    dup
    cover 4
    // contracts/plonk_bls12381.algo.ts:265
    // return op.EllipticCurve.subgroupCheck(op.Ec.BLS12_381g1, p);
    ec_subgroup_check BLS12_381g1
    // contracts/plonk_bls12381.algo.ts:293
    // assert(groupCheck(proof.T1), "T1 not in G1");
    assert // T1 not in G1
    // contracts/plonk_bls12381.algo.ts:294
    // assert(groupCheck(proof.T2), "T2 not in G1");
    dup
    pushint 480 // 480
    intc_1 // 96
    extract3
    dup
    cover 4
    // contracts/plonk_bls12381.algo.ts:265
    // return op.EllipticCurve.subgroupCheck(op.Ec.BLS12_381g1, p);
    ec_subgroup_check BLS12_381g1
    // contracts/plonk_bls12381.algo.ts:294
    // assert(groupCheck(proof.T2), "T2 not in G1");
    assert // T2 not in G1
    // contracts/plonk_bls12381.algo.ts:295
    // assert(groupCheck(proof.T3), "T3 not in G1");
    dup
    pushint 576 // 576
    intc_1 // 96
    extract3
    dup
    cover 4
    // contracts/plonk_bls12381.algo.ts:265
    // return op.EllipticCurve.subgroupCheck(op.Ec.BLS12_381g1, p);
    ec_subgroup_check BLS12_381g1
    // contracts/plonk_bls12381.algo.ts:295
    // assert(groupCheck(proof.T3), "T3 not in G1");
    assert // T3 not in G1
    // contracts/plonk_bls12381.algo.ts:296
    // assert(groupCheck(proof.Wxi), "Wxi not in G1");
    dup
    pushint 672 // 672
    intc_1 // 96
    extract3
    dup
    cover 4
    // contracts/plonk_bls12381.algo.ts:265
    // return op.EllipticCurve.subgroupCheck(op.Ec.BLS12_381g1, p);
    ec_subgroup_check BLS12_381g1
    // contracts/plonk_bls12381.algo.ts:296
    // assert(groupCheck(proof.Wxi), "Wxi not in G1");
    assert // Wxi not in G1
    // contracts/plonk_bls12381.algo.ts:297
    // assert(groupCheck(proof.Wxiw), "Wxiw not in G1");
    dup
    pushint 768 // 768
    intc_1 // 96
    extract3
    dup
    cover 4
    // contracts/plonk_bls12381.algo.ts:265
    // return op.EllipticCurve.subgroupCheck(op.Ec.BLS12_381g1, p);
    ec_subgroup_check BLS12_381g1
    // contracts/plonk_bls12381.algo.ts:297
    // assert(groupCheck(proof.Wxiw), "Wxiw not in G1");
    assert // Wxiw not in G1
    // contracts/plonk_bls12381.algo.ts:280
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
    // contracts/plonk_bls12381.algo.ts:280
    // assert(inField(proof.eval_a), "eval_a not in Fr");
    assert // eval_a not in Fr
    // contracts/plonk_bls12381.algo.ts:281
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
    // contracts/plonk_bls12381.algo.ts:281
    // assert(inField(proof.eval_b), "eval_b not in Fr");
    assert // eval_b not in Fr
    // contracts/plonk_bls12381.algo.ts:282
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
    // contracts/plonk_bls12381.algo.ts:282
    // assert(inField(proof.eval_c), "eval_c not in Fr");
    assert // eval_c not in Fr
    // contracts/plonk_bls12381.algo.ts:283
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
    // contracts/plonk_bls12381.algo.ts:283
    // assert(inField(proof.eval_s1), "eval_s1 not in Fr");
    assert // eval_s1 not in Fr
    // contracts/plonk_bls12381.algo.ts:284
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
    // contracts/plonk_bls12381.algo.ts:284
    // assert(inField(proof.eval_s2), "eval_s2 not in Fr");
    assert // eval_s2 not in Fr
    // contracts/plonk_bls12381.algo.ts:285
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
    // contracts/plonk_bls12381.algo.ts:285
    // assert(inField(proof.eval_zw), "eval_zw not in Fr");
    assert // eval_zw not in Fr
    // contracts/plonk_bls12381.algo.ts:272
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
    // contracts/plonk_bls12381.algo.ts:274
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
    // contracts/plonk_bls12381.algo.ts:275
    // assert(inField(signal), "public signal not in Fr");
    assert // public signal not in Fr
    intc_2 // 1
    +
    bury 1
    b main_for_header@2

main_after_for@4:
    // contracts/plonk_bls12381.algo.ts:414
    // let td = vk.Qm.concat(vk.Ql)
    dig 18
    dup
    extract 0 96
    dig 1
    extract 96 96
    concat
    // contracts/plonk_bls12381.algo.ts:415
    // .concat(vk.Qr)
    dig 1
    extract 192 96
    // contracts/plonk_bls12381.algo.ts:414-415
    // let td = vk.Qm.concat(vk.Ql)
    //   .concat(vk.Qr)
    concat
    // contracts/plonk_bls12381.algo.ts:416
    // .concat(vk.Qo)
    dig 1
    pushint 288 // 288
    intc_1 // 96
    extract3
    // contracts/plonk_bls12381.algo.ts:414-416
    // let td = vk.Qm.concat(vk.Ql)
    //   .concat(vk.Qr)
    //   .concat(vk.Qo)
    concat
    dup
    bury 31
    // contracts/plonk_bls12381.algo.ts:417
    // .concat(vk.Qc)
    dig 1
    intc 4 // 384
    intc_1 // 96
    extract3
    dup
    bury 48
    // contracts/plonk_bls12381.algo.ts:414-417
    // let td = vk.Qm.concat(vk.Ql)
    //   .concat(vk.Qr)
    //   .concat(vk.Qo)
    //   .concat(vk.Qc)
    concat
    // contracts/plonk_bls12381.algo.ts:418
    // .concat(vk.S1)
    dig 1
    pushint 480 // 480
    intc_1 // 96
    extract3
    dup
    bury 47
    // contracts/plonk_bls12381.algo.ts:414-418
    // let td = vk.Qm.concat(vk.Ql)
    //   .concat(vk.Qr)
    //   .concat(vk.Qo)
    //   .concat(vk.Qc)
    //   .concat(vk.S1)
    concat
    // contracts/plonk_bls12381.algo.ts:419
    // .concat(vk.S2)
    dig 1
    pushint 576 // 576
    intc_1 // 96
    extract3
    dup
    bury 46
    // contracts/plonk_bls12381.algo.ts:414-419
    // let td = vk.Qm.concat(vk.Ql)
    //   .concat(vk.Qr)
    //   .concat(vk.Qo)
    //   .concat(vk.Qc)
    //   .concat(vk.S1)
    //   .concat(vk.S2)
    concat
    // contracts/plonk_bls12381.algo.ts:420
    // .concat(vk.S3);
    swap
    pushint 672 // 672
    intc_1 // 96
    extract3
    dup
    bury 44
    // contracts/plonk_bls12381.algo.ts:414-420
    // let td = vk.Qm.concat(vk.Ql)
    //   .concat(vk.Qr)
    //   .concat(vk.Qo)
    //   .concat(vk.Qc)
    //   .concat(vk.S1)
    //   .concat(vk.S2)
    //   .concat(vk.S3);
    concat
    bury 31
    intc_3 // 0
    bury 1

main_for_header@5:
    // contracts/plonk_bls12381.algo.ts:422
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
    // contracts/plonk_bls12381.algo.ts:423
    // td = td.concat(b32(frScalar(signal.asBigUint())));
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
    // contracts/plonk_bls12381.algo.ts:427
    // td = td.concat(proof.A).concat(proof.B).concat(proof.C);
    dig 30
    dig 18
    concat
    dig 17
    concat
    dig 16
    concat
    // contracts/plonk_bls12381.algo.ts:429
    // const beta = getChallenge(td);
    callsub getChallenge
    // contracts/plonk_bls12381.algo.ts:432
    // const gamma = getChallenge(beta.bytes);
    dup
    callsub getChallenge
    // contracts/plonk_bls12381.algo.ts:437
    // const alpha = getChallenge(beta.bytes.concat(gamma.bytes).concat(proof.Z));
    concat
    dup
    bury 31
    dig 15
    concat
    callsub getChallenge
    dup
    bury 42
    // contracts/plonk_bls12381.algo.ts:443
    // alpha.bytes.concat(proof.T1).concat(proof.T2).concat(proof.T3),
    dig 14
    concat
    dig 13
    concat
    dig 12
    concat
    // contracts/plonk_bls12381.algo.ts:442-444
    // const xi = getChallenge(
    //   alpha.bytes.concat(proof.T1).concat(proof.T2).concat(proof.T3),
    // );
    callsub getChallenge
    dup
    bury 27
    // contracts/plonk_bls12381.algo.ts:449
    // const v = new FixedArray<Uint256, 6>();
    pushint 192 // 192
    bzero
    // contracts/plonk_bls12381.algo.ts:451-452
    // xi.bytes
    //   .concat(proof.eval_a.bytes)
    swap
    dig 10
    concat
    // contracts/plonk_bls12381.algo.ts:451-453
    // xi.bytes
    //   .concat(proof.eval_a.bytes)
    //   .concat(proof.eval_b.bytes)
    dig 9
    concat
    // contracts/plonk_bls12381.algo.ts:451-454
    // xi.bytes
    //   .concat(proof.eval_a.bytes)
    //   .concat(proof.eval_b.bytes)
    //   .concat(proof.eval_c.bytes)
    dig 8
    concat
    // contracts/plonk_bls12381.algo.ts:451-455
    // xi.bytes
    //   .concat(proof.eval_a.bytes)
    //   .concat(proof.eval_b.bytes)
    //   .concat(proof.eval_c.bytes)
    //   .concat(proof.eval_s1.bytes)
    dig 7
    concat
    // contracts/plonk_bls12381.algo.ts:451-456
    // xi.bytes
    //   .concat(proof.eval_a.bytes)
    //   .concat(proof.eval_b.bytes)
    //   .concat(proof.eval_c.bytes)
    //   .concat(proof.eval_s1.bytes)
    //   .concat(proof.eval_s2.bytes)
    dig 6
    concat
    // contracts/plonk_bls12381.algo.ts:451-457
    // xi.bytes
    //   .concat(proof.eval_a.bytes)
    //   .concat(proof.eval_b.bytes)
    //   .concat(proof.eval_c.bytes)
    //   .concat(proof.eval_s1.bytes)
    //   .concat(proof.eval_s2.bytes)
    //   .concat(proof.eval_zw.bytes),
    dig 5
    concat
    // contracts/plonk_bls12381.algo.ts:450-458
    // v[1] = getChallenge(
    //   xi.bytes
    //     .concat(proof.eval_a.bytes)
    //     .concat(proof.eval_b.bytes)
    //     .concat(proof.eval_c.bytes)
    //     .concat(proof.eval_s1.bytes)
    //     .concat(proof.eval_s2.bytes)
    //     .concat(proof.eval_zw.bytes),
    // ); // v1
    callsub getChallenge
    replace2 32 // on error: index access is out of bounds
    bury 28
    // contracts/plonk_bls12381.algo.ts:459
    // for (let i: uint64 = 2; i < 6; i++) {
    pushint 2 // 2
    bury 23

main_while_top@8:
    // contracts/plonk_bls12381.algo.ts:459
    // for (let i: uint64 = 2; i < 6; i++) {
    dig 22
    pushint 6 // 6
    <
    bz main_after_while@10
    // contracts/plonk_bls12381.algo.ts:461
    // frMul((v[i - 1] as Uint256).asBigUint(), v[1].asBigUint()),
    dig 22
    dup
    intc_2 // 1
    -
    intc_0 // 32
    *
    dig 29
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
    // contracts/plonk_bls12381.algo.ts:460-462
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
    bury 29
    // contracts/plonk_bls12381.algo.ts:459
    // for (let i: uint64 = 2; i < 6; i++) {
    intc_2 // 1
    +
    bury 23
    b main_while_top@8

main_after_while@10:
    // contracts/plonk_bls12381.algo.ts:468
    // const u = getChallenge(proof.Wxi.concat(proof.Wxiw));
    dig 10
    dig 10
    concat
    dup
    bury 35
    callsub getChallenge
    // contracts/plonk_bls12381.algo.ts:470-479
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
    dig 30
    dig 42
    concat
    dig 27
    concat
    dig 29
    concat
    swap
    concat
    pushbytes 0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
    concat
    dup
    bury 38
    // contracts/plonk_bls12381.algo.ts:490
    // let xin = challenges.xi.asBigUint();
    extract 96 32
    bury 25
    // contracts/plonk_bls12381.algo.ts:493
    // let domainSize: uint64 = 1;
    intc_2 // 1
    bury 24
    // contracts/plonk_bls12381.algo.ts:494
    // for (let i: uint64 = 0; i < vk.power; i++) {
    intc_3 // 0
    bury 23

main_while_top@11:
    // contracts/plonk_bls12381.algo.ts:494
    // for (let i: uint64 = 0; i < vk.power; i++) {
    dig 18
    pushint 768 // 768
    extract_uint64
    dig 23
    >
    bz main_after_while@13
    // contracts/plonk_bls12381.algo.ts:70
    // return (a * b) % BLS12_381_SCALAR_MODULUS;
    dig 24
    dup
    b*
    bytec_0 // 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001
    b%
    bury 25
    // contracts/plonk_bls12381.algo.ts:496
    // domainSize *= 2;
    dig 23
    pushint 2 // 2
    *
    bury 24
    // contracts/plonk_bls12381.algo.ts:494
    // for (let i: uint64 = 0; i < vk.power; i++) {
    dig 22
    intc_2 // 1
    +
    bury 23
    b main_while_top@11

main_after_while@13:
    // contracts/plonk_bls12381.algo.ts:499
    // challenges.xin = new Uint256(xin);
    dig 24
    dup
    len
    intc_0 // 32
    <=
    assert // overflow
    intc_0 // 32
    bzero
    dup
    bury 48
    dup2
    b|
    dig 39
    pushint 352 // 352
    uncover 2
    replace3
    // contracts/plonk_bls12381.algo.ts:500
    // challenges.zh = new Uint256(frSub(xin, BigUint(1))); // Vanishing polynomial Z_H(ξ) = ξ^n - 1
    uncover 2
    bytec_2 // 0x01
    callsub frSub
    dup
    len
    intc_0 // 32
    <=
    assert // overflow
    uncover 2
    b|
    intc 4 // 384
    swap
    replace3
    bury 39
    // contracts/plonk_bls12381.algo.ts:502
    // const n = frScalar(BigUint(domainSize));
    dig 23
    itob
    // contracts/bls12381_common.algo.ts:37
    // return a % BLS12_381_SCALAR_MODULUS;
    bytec_0 // 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001
    b%
    bury 35
    // contracts/plonk_bls12381.algo.ts:508
    // let w = BigUint(1);
    bytec_2 // 0x01
    bury 27
    // contracts/plonk_bls12381.algo.ts:517
    // const L: Uint256[] = [new Uint256()];
    pushbytes 0x00010000000000000000000000000000000000000000000000000000000000000000
    bury 48
    // contracts/plonk_bls12381.algo.ts:520
    // const iterations: uint64 = vk.nPublic === 0 ? 1 : vk.nPublic;
    dig 1
    bnz main_ternary_false@15
    intc_2 // 1
    bury 22

main_ternary_merge@16:
    // contracts/plonk_bls12381.algo.ts:521
    // for (let i: uint64 = 1; i <= iterations; i++) {
    intc_2 // 1
    bury 21

main_while_top@17:
    // contracts/plonk_bls12381.algo.ts:521
    // for (let i: uint64 = 1; i <= iterations; i++) {
    dig 20
    dig 22
    <=
    bz main_after_while@19
    // contracts/plonk_bls12381.algo.ts:525
    // frMul(w, challenges.zh.asBigUint()),
    dig 38
    dup
    intc 4 // 384
    intc_0 // 32
    extract3
    // contracts/plonk_bls12381.algo.ts:70
    // return (a * b) % BLS12_381_SCALAR_MODULUS;
    dig 28
    dup
    uncover 2
    b*
    bytec_0 // 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001
    b%
    // contracts/plonk_bls12381.algo.ts:526
    // frMul(n, frSub(challenges.xi.asBigUint(), w)),
    uncover 2
    extract 96 32
    uncover 2
    callsub frSub
    // contracts/plonk_bls12381.algo.ts:70
    // return (a * b) % BLS12_381_SCALAR_MODULUS;
    dig 36
    b*
    bytec_0 // 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001
    b%
    // contracts/bls12381_common.algo.ts:37
    // return a % BLS12_381_SCALAR_MODULUS;
    swap
    bytec_0 // 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001
    b%
    bury 48
    bytec_0 // 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001
    b%
    // contracts/plonk_bls12381.algo.ts:108
    // assert(x !== (0n as biguint), "Fr inverse of zero");
    dup
    bytec_1 // 0x
    b!=
    assert // Fr inverse of zero
    // contracts/plonk_bls12381.algo.ts:109
    // const inv = modPow(x, BLS12_381_R_MINUS_2, r);
    pushbytes 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfefffffffeffffffff
    // contracts/plonk_bls12381.algo.ts:87
    // let result = 1n as biguint;
    bytec_2 // 0x01
    bury 34
    // contracts/plonk_bls12381.algo.ts:88
    // let b: biguint = base % mod;
    swap
    // contracts/plonk_bls12381.algo.ts:109
    // const inv = modPow(x, BLS12_381_R_MINUS_2, r);
    bytec_0 // 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001
    // contracts/plonk_bls12381.algo.ts:88
    // let b: biguint = base % mod;
    b%
    bury 41
    bury 38

main_while_top@26:
    // contracts/plonk_bls12381.algo.ts:90
    // while (e > (0n as biguint)) {
    dig 37
    bytec_1 // 0x
    b>
    // contracts/plonk_bls12381.algo.ts:90-96
    // while (e > (0n as biguint)) {
    //   if ((e & (1n as biguint)) !== (0n as biguint)) {
    //     result = (result * b) % mod;
    //   }
    //   b = (b * b) % mod;
    //   e = e / BigUint(2);
    // }
    bz main_after_while@30
    // contracts/plonk_bls12381.algo.ts:91
    // if ((e & (1n as biguint)) !== (0n as biguint)) {
    dig 37
    bytec_2 // 0x01
    b&
    bytec_1 // 0x
    b!=
    bz main_after_if_else@29
    // contracts/plonk_bls12381.algo.ts:92
    // result = (result * b) % mod;
    dig 31
    dig 40
    b*
    // contracts/plonk_bls12381.algo.ts:109
    // const inv = modPow(x, BLS12_381_R_MINUS_2, r);
    bytec_0 // 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001
    // contracts/plonk_bls12381.algo.ts:92
    // result = (result * b) % mod;
    b%
    bury 32

main_after_if_else@29:
    // contracts/plonk_bls12381.algo.ts:94
    // b = (b * b) % mod;
    dig 39
    dup
    b*
    // contracts/plonk_bls12381.algo.ts:109
    // const inv = modPow(x, BLS12_381_R_MINUS_2, r);
    bytec_0 // 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001
    // contracts/plonk_bls12381.algo.ts:94
    // b = (b * b) % mod;
    b%
    bury 40
    // contracts/plonk_bls12381.algo.ts:95
    // e = e / BigUint(2);
    dig 37
    pushbytes 0x02
    b/
    bury 38
    b main_while_top@26

main_after_while@30:
    // contracts/plonk_bls12381.algo.ts:122
    // return (aN * bInv) % r;
    dig 46
    dig 32
    b*
    bytec_0 // 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001
    b%
    // contracts/plonk_bls12381.algo.ts:523-528
    // new Uint256(
    //   frDiv(
    //     frMul(w, challenges.zh.asBigUint()),
    //     frMul(n, frSub(challenges.xi.asBigUint(), w)),
    //   ),
    // ),
    dup
    len
    intc_0 // 32
    <=
    assert // overflow
    dig 46
    b|
    // contracts/plonk_bls12381.algo.ts:522-529
    // L.push(
    //   new Uint256(
    //     frDiv(
    //       frMul(w, challenges.zh.asBigUint()),
    //       frMul(n, frSub(challenges.xi.asBigUint(), w)),
    //     ),
    //   ),
    // );
    dig 48
    dup
    uncover 2
    concat // on error: max array length exceeded
    swap
    intc_3 // 0
    extract_uint16
    intc_2 // 1
    +
    itob
    extract 6 2
    replace2 0
    bury 48
    // contracts/plonk_bls12381.algo.ts:70
    // return (a * b) % BLS12_381_SCALAR_MODULUS;
    dig 26
    // contracts/plonk_bls12381.algo.ts:530
    // w = frMul(w, ROOT_OF_UNITY); // Next root of unity step (ω^i)
    bytec_3 // TMPL_ROOT_OF_UNITY
    // contracts/plonk_bls12381.algo.ts:70
    // return (a * b) % BLS12_381_SCALAR_MODULUS;
    b*
    bytec_0 // 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001
    b%
    bury 27
    // contracts/plonk_bls12381.algo.ts:521
    // for (let i: uint64 = 1; i <= iterations; i++) {
    dig 20
    intc_2 // 1
    +
    bury 21
    b main_while_top@17

main_after_while@19:
    // contracts/plonk_bls12381.algo.ts:532
    // return { L, challenges };
    pushbytes 0x01a2
    dig 39
    concat
    dig 48
    concat
    bury 36
    // contracts/plonk_bls12381.algo.ts:542
    // let pi = BigUint(0);
    bytec_1 // 0x
    bury 33
    // contracts/plonk_bls12381.algo.ts:543
    // for (let i: uint64 = 0; i < publicSignals.length; i++) {
    intc_3 // 0
    bury 23

main_while_top@20:
    // contracts/plonk_bls12381.algo.ts:543
    // for (let i: uint64 = 0; i < publicSignals.length; i++) {
    dig 22
    dig 3
    <
    bz main_after_while@22
    // contracts/plonk_bls12381.algo.ts:544
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
    // contracts/plonk_bls12381.algo.ts:545
    // pi = frSub(pi, frMul(w, (L[i + 1] as Uint256).asBigUint()));
    swap
    intc_2 // 1
    +
    dup
    bury 25
    dig 37
    dup
    intc_3 // 0
    extract_uint16
    dig 1
    len
    substring3
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
    // contracts/plonk_bls12381.algo.ts:545
    // pi = frSub(pi, frMul(w, (L[i + 1] as Uint256).asBigUint()));
    dig 33
    swap
    callsub frSub
    bury 33
    b main_while_top@20

main_after_while@22:
    // contracts/plonk_bls12381.algo.ts:547
    // return new Uint256(pi);
    dig 32
    dup
    len
    intc_0 // 32
    <=
    assert // overflow
    dig 46
    dup
    cover 2
    b|
    // contracts/plonk_bls12381.algo.ts:331
    // const r0 = calculateR0(proof, challenges, pi, lw.L[1] as Uint256);
    dig 37
    dup
    intc_3 // 0
    extract_uint16
    dig 1
    len
    dig 2
    cover 2
    substring3
    extract 34 32
    // contracts/plonk_bls12381.algo.ts:568
    // frMul(challenges.alpha.asBigUint(), challenges.alpha.asBigUint()),
    swap
    pushints 2 416 // 2, 416
    extract3
    dup
    extract 64 32
    // contracts/plonk_bls12381.algo.ts:70
    // return (a * b) % BLS12_381_SCALAR_MODULUS;
    dup
    dig 1
    b*
    bytec_0 // 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001
    b%
    uncover 3
    b*
    bytec_0 // 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001
    b%
    // contracts/plonk_bls12381.algo.ts:575
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
    cover 6
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
    // contracts/plonk_bls12381.algo.ts:577
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
    // contracts/plonk_bls12381.algo.ts:592
    // const r0 = frSub(frSub(e1, e2), e3);
    uncover 12
    dig 9
    callsub frSub
    swap
    callsub frSub
    // contracts/plonk_bls12381.algo.ts:593
    // return new Uint256(r0);
    dup
    len
    intc_0 // 32
    <=
    assert // overflow
    uncover 13
    b|
    // contracts/plonk_bls12381.algo.ts:618-621
    // let points = vk.Qm.concat(vk.Ql)
    //   .concat(vk.Qr)
    //   .concat(vk.Qo)
    //   .concat(proof.T1)
    dig 44
    dig 30
    concat
    // contracts/plonk_bls12381.algo.ts:618-622
    // let points = vk.Qm.concat(vk.Ql)
    //   .concat(vk.Qr)
    //   .concat(vk.Qo)
    //   .concat(proof.T1)
    //   .concat(proof.T2)
    dig 29
    concat
    // contracts/plonk_bls12381.algo.ts:618-623
    // let points = vk.Qm.concat(vk.Ql)
    //   .concat(vk.Qr)
    //   .concat(vk.Qo)
    //   .concat(proof.T1)
    //   .concat(proof.T2)
    //   .concat(proof.T3)
    dig 28
    concat
    // contracts/plonk_bls12381.algo.ts:618-624
    // let points = vk.Qm.concat(vk.Ql)
    //   .concat(vk.Qr)
    //   .concat(vk.Qo)
    //   .concat(proof.T1)
    //   .concat(proof.T2)
    //   .concat(proof.T3)
    //   .concat(vk.Qc);
    dig 61
    concat
    // contracts/plonk_bls12381.algo.ts:70
    // return (a * b) % BLS12_381_SCALAR_MODULUS;
    dig 12
    dig 7
    b*
    bytec_0 // 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001
    b%
    // contracts/plonk_bls12381.algo.ts:633
    // const quotientScalar1 = frSub(BigUint(0), challenges.zh.asBigUint()); // −zh (applies to T1)
    dig 12
    intc 4 // 384
    intc_0 // 32
    extract3
    bytec_1 // 0x
    dig 1
    callsub frSub
    // contracts/plonk_bls12381.algo.ts:636
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
    // contracts/plonk_bls12381.algo.ts:635
    // BigUint(0),
    bytec_1 // 0x
    // contracts/plonk_bls12381.algo.ts:634-637
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
    // contracts/plonk_bls12381.algo.ts:639
    // BigUint(0),
    bytec_1 // 0x
    // contracts/plonk_bls12381.algo.ts:638-644
    // const quotientScalar3 = frSub(
    //   BigUint(0),
    //   frMul(
    //     frMul(challenges.xin.asBigUint(), challenges.xin.asBigUint()),
    //     challenges.zh.asBigUint(),
    //   ),
    // ); // −xin²·zh (applies to T3)
    swap
    callsub frSub
    // contracts/plonk_bls12381.algo.ts:647
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
    // contracts/plonk_bls12381.algo.ts:653
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
    // contracts/plonk_bls12381.algo.ts:657
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
    // contracts/plonk_bls12381.algo.ts:668
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
    // contracts/plonk_bls12381.algo.ts:692-693
    // points = points
    //   .concat(proof.Z)
    uncover 9
    dig 32
    concat
    // contracts/plonk_bls12381.algo.ts:692-694
    // points = points
    //   .concat(proof.Z)
    //   .concat(vk.S3)
    dig 59
    concat
    // contracts/plonk_bls12381.algo.ts:692-695
    // points = points
    //   .concat(proof.Z)
    //   .concat(vk.S3)
    //   .concat(proof.A)
    dig 35
    concat
    // contracts/plonk_bls12381.algo.ts:692-696
    // points = points
    //   .concat(proof.Z)
    //   .concat(vk.S3)
    //   .concat(proof.A)
    //   .concat(proof.B)
    dig 34
    concat
    // contracts/plonk_bls12381.algo.ts:692-697
    // points = points
    //   .concat(proof.Z)
    //   .concat(vk.S3)
    //   .concat(proof.A)
    //   .concat(proof.B)
    //   .concat(proof.C)
    dig 33
    concat
    // contracts/plonk_bls12381.algo.ts:692-698
    // points = points
    //   .concat(proof.Z)
    //   .concat(vk.S3)
    //   .concat(proof.A)
    //   .concat(proof.B)
    //   .concat(proof.C)
    //   .concat(vk.S1)
    dig 61
    concat
    // contracts/plonk_bls12381.algo.ts:692-699
    // points = points
    //   .concat(proof.Z)
    //   .concat(vk.S3)
    //   .concat(proof.A)
    //   .concat(proof.B)
    //   .concat(proof.C)
    //   .concat(vk.S1)
    //   .concat(vk.S2);
    dig 60
    concat
    // contracts/plonk_bls12381.algo.ts:702
    // let scalars = b32(gateScalar1)
    uncover 9
    callsub b32
    // contracts/plonk_bls12381.algo.ts:703
    // .concat(b32(gateScalar2))
    dig 13
    callsub b32
    // contracts/plonk_bls12381.algo.ts:702-703
    // let scalars = b32(gateScalar1)
    //   .concat(b32(gateScalar2))
    concat
    // contracts/plonk_bls12381.algo.ts:704
    // .concat(b32(gateScalar3))
    dig 11
    callsub b32
    // contracts/plonk_bls12381.algo.ts:702-704
    // let scalars = b32(gateScalar1)
    //   .concat(b32(gateScalar2))
    //   .concat(b32(gateScalar3))
    concat
    // contracts/plonk_bls12381.algo.ts:705
    // .concat(b32(gateScalar4))
    dig 15
    callsub b32
    // contracts/plonk_bls12381.algo.ts:702-705
    // let scalars = b32(gateScalar1)
    //   .concat(b32(gateScalar2))
    //   .concat(b32(gateScalar3))
    //   .concat(b32(gateScalar4))
    concat
    // contracts/plonk_bls12381.algo.ts:706
    // .concat(b32(quotientScalar1))
    uncover 9
    callsub b32
    // contracts/plonk_bls12381.algo.ts:702-706
    // let scalars = b32(gateScalar1)
    //   .concat(b32(gateScalar2))
    //   .concat(b32(gateScalar3))
    //   .concat(b32(gateScalar4))
    //   .concat(b32(quotientScalar1))
    concat
    // contracts/plonk_bls12381.algo.ts:707
    // .concat(b32(quotientScalar2))
    uncover 8
    callsub b32
    // contracts/plonk_bls12381.algo.ts:702-707
    // let scalars = b32(gateScalar1)
    //   .concat(b32(gateScalar2))
    //   .concat(b32(gateScalar3))
    //   .concat(b32(gateScalar4))
    //   .concat(b32(quotientScalar1))
    //   .concat(b32(quotientScalar2))
    concat
    // contracts/plonk_bls12381.algo.ts:708
    // .concat(b32(quotientScalar3))
    uncover 7
    callsub b32
    // contracts/plonk_bls12381.algo.ts:702-708
    // let scalars = b32(gateScalar1)
    //   .concat(b32(gateScalar2))
    //   .concat(b32(gateScalar3))
    //   .concat(b32(gateScalar4))
    //   .concat(b32(quotientScalar1))
    //   .concat(b32(quotientScalar2))
    //   .concat(b32(quotientScalar3))
    concat
    // contracts/plonk_bls12381.algo.ts:709
    // .concat(b32(BigUint(1))) // Qc with scalar 1
    bytec_2 // 0x01
    callsub b32
    // contracts/plonk_bls12381.algo.ts:702-709
    // let scalars = b32(gateScalar1)
    //   .concat(b32(gateScalar2))
    //   .concat(b32(gateScalar3))
    //   .concat(b32(gateScalar4))
    //   .concat(b32(quotientScalar1))
    //   .concat(b32(quotientScalar2))
    //   .concat(b32(quotientScalar3))
    //   .concat(b32(BigUint(1))) // Qc with scalar 1
    concat
    // contracts/plonk_bls12381.algo.ts:710
    // .concat(b32(zScalar)) // Z with zScalar
    uncover 3
    callsub b32
    // contracts/plonk_bls12381.algo.ts:702-710
    // let scalars = b32(gateScalar1)
    //   .concat(b32(gateScalar2))
    //   .concat(b32(gateScalar3))
    //   .concat(b32(gateScalar4))
    //   .concat(b32(quotientScalar1))
    //   .concat(b32(quotientScalar2))
    //   .concat(b32(quotientScalar3))
    //   .concat(b32(BigUint(1))) // Qc with scalar 1
    //   .concat(b32(zScalar)) // Z with zScalar
    concat
    // contracts/plonk_bls12381.algo.ts:711
    // .concat(b32(frSub(BigUint(0), s3Scalar))) // S3 with -s3Scalar
    bytec_1 // 0x
    uncover 3
    callsub frSub
    callsub b32
    // contracts/plonk_bls12381.algo.ts:702-711
    // let scalars = b32(gateScalar1)
    //   .concat(b32(gateScalar2))
    //   .concat(b32(gateScalar3))
    //   .concat(b32(gateScalar4))
    //   .concat(b32(quotientScalar1))
    //   .concat(b32(quotientScalar2))
    //   .concat(b32(quotientScalar3))
    //   .concat(b32(BigUint(1))) // Qc with scalar 1
    //   .concat(b32(zScalar)) // Z with zScalar
    //   .concat(b32(frSub(BigUint(0), s3Scalar))) // S3 with -s3Scalar
    concat
    // contracts/plonk_bls12381.algo.ts:712
    // .concat((challenges.v[1] as Uint256).bytes)
    uncover 7
    extract 128 192
    dup
    extract 32 32 // on error: index access is out of bounds
    // contracts/plonk_bls12381.algo.ts:702-712
    // let scalars = b32(gateScalar1)
    //   .concat(b32(gateScalar2))
    //   .concat(b32(gateScalar3))
    //   .concat(b32(gateScalar4))
    //   .concat(b32(quotientScalar1))
    //   .concat(b32(quotientScalar2))
    //   .concat(b32(quotientScalar3))
    //   .concat(b32(BigUint(1))) // Qc with scalar 1
    //   .concat(b32(zScalar)) // Z with zScalar
    //   .concat(b32(frSub(BigUint(0), s3Scalar))) // S3 with -s3Scalar
    //   .concat((challenges.v[1] as Uint256).bytes)
    uncover 2
    dig 1
    concat
    // contracts/plonk_bls12381.algo.ts:712-713
    // .concat((challenges.v[1] as Uint256).bytes)
    // .concat((challenges.v[2] as Uint256).bytes)
    dig 2
    extract 64 32 // on error: index access is out of bounds
    // contracts/plonk_bls12381.algo.ts:702-713
    // let scalars = b32(gateScalar1)
    //   .concat(b32(gateScalar2))
    //   .concat(b32(gateScalar3))
    //   .concat(b32(gateScalar4))
    //   .concat(b32(quotientScalar1))
    //   .concat(b32(quotientScalar2))
    //   .concat(b32(quotientScalar3))
    //   .concat(b32(BigUint(1))) // Qc with scalar 1
    //   .concat(b32(zScalar)) // Z with zScalar
    //   .concat(b32(frSub(BigUint(0), s3Scalar))) // S3 with -s3Scalar
    //   .concat((challenges.v[1] as Uint256).bytes)
    //   .concat((challenges.v[2] as Uint256).bytes)
    swap
    dig 1
    concat
    // contracts/plonk_bls12381.algo.ts:714
    // .concat((challenges.v[3] as Uint256).bytes)
    dig 3
    extract 96 32 // on error: index access is out of bounds
    // contracts/plonk_bls12381.algo.ts:702-714
    // let scalars = b32(gateScalar1)
    //   .concat(b32(gateScalar2))
    //   .concat(b32(gateScalar3))
    //   .concat(b32(gateScalar4))
    //   .concat(b32(quotientScalar1))
    //   .concat(b32(quotientScalar2))
    //   .concat(b32(quotientScalar3))
    //   .concat(b32(BigUint(1))) // Qc with scalar 1
    //   .concat(b32(zScalar)) // Z with zScalar
    //   .concat(b32(frSub(BigUint(0), s3Scalar))) // S3 with -s3Scalar
    //   .concat((challenges.v[1] as Uint256).bytes)
    //   .concat((challenges.v[2] as Uint256).bytes)
    //   .concat((challenges.v[3] as Uint256).bytes)
    swap
    dig 1
    concat
    // contracts/plonk_bls12381.algo.ts:715
    // .concat((challenges.v[4] as Uint256).bytes)
    dig 4
    extract 128 32 // on error: index access is out of bounds
    // contracts/plonk_bls12381.algo.ts:702-715
    // let scalars = b32(gateScalar1)
    //   .concat(b32(gateScalar2))
    //   .concat(b32(gateScalar3))
    //   .concat(b32(gateScalar4))
    //   .concat(b32(quotientScalar1))
    //   .concat(b32(quotientScalar2))
    //   .concat(b32(quotientScalar3))
    //   .concat(b32(BigUint(1))) // Qc with scalar 1
    //   .concat(b32(zScalar)) // Z with zScalar
    //   .concat(b32(frSub(BigUint(0), s3Scalar))) // S3 with -s3Scalar
    //   .concat((challenges.v[1] as Uint256).bytes)
    //   .concat((challenges.v[2] as Uint256).bytes)
    //   .concat((challenges.v[3] as Uint256).bytes)
    //   .concat((challenges.v[4] as Uint256).bytes)
    swap
    dig 1
    concat
    // contracts/plonk_bls12381.algo.ts:716
    // .concat((challenges.v[5] as Uint256).bytes);
    uncover 5
    extract 160 32 // on error: index access is out of bounds
    // contracts/plonk_bls12381.algo.ts:702-716
    // let scalars = b32(gateScalar1)
    //   .concat(b32(gateScalar2))
    //   .concat(b32(gateScalar3))
    //   .concat(b32(gateScalar4))
    //   .concat(b32(quotientScalar1))
    //   .concat(b32(quotientScalar2))
    //   .concat(b32(quotientScalar3))
    //   .concat(b32(BigUint(1))) // Qc with scalar 1
    //   .concat(b32(zScalar)) // Z with zScalar
    //   .concat(b32(frSub(BigUint(0), s3Scalar))) // S3 with -s3Scalar
    //   .concat((challenges.v[1] as Uint256).bytes)
    //   .concat((challenges.v[2] as Uint256).bytes)
    //   .concat((challenges.v[3] as Uint256).bytes)
    //   .concat((challenges.v[4] as Uint256).bytes)
    //   .concat((challenges.v[5] as Uint256).bytes);
    swap
    dig 1
    concat
    // contracts/plonk_bls12381.algo.ts:719-723
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
    // contracts/plonk_bls12381.algo.ts:739-742
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
    // contracts/plonk_bls12381.algo.ts:761
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
    // contracts/plonk_bls12381.algo.ts:793
    // ROOT_OF_UNITY,
    bytec_3 // TMPL_ROOT_OF_UNITY
    // contracts/plonk_bls12381.algo.ts:70
    // return (a * b) % BLS12_381_SCALAR_MODULUS;
    b*
    bytec_0 // 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001
    b%
    // contracts/plonk_bls12381.algo.ts:795
    // const pairingScalars = challenges.xi.bytes.concat(b32(s));
    callsub b32
    uncover 5
    swap
    concat
    // contracts/plonk_bls12381.algo.ts:797-801
    // let B1 = op.EllipticCurve.scalarMulMulti(
    //   op.Ec.BLS12_381g1,
    //   pairingPoints,
    //   pairingScalars,
    // ).toFixed({ length: 96 });
    dig 38
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
    bytec 4 // 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000000
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
    bytec 4 // 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000000
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
    // contracts/plonk_bls12381.algo.ts:808
    // g1Neg(A1).concat(B1), // G1 points
    swap
    concat
    // contracts/plonk_bls12381.algo.ts:809
    // vk.X_2.concat(G2_ONE), // G2 points
    swap
    pushints 800 192 // 800, 192
    extract3
    pushbytes 0x024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb813e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e0ce5d527727d6e118cc9cdc6da2e351aadfd9baa8cbdd3a76d429a695160d12c923ac9cc3baca289e193548608b828010606c4a02ea734cc32acd2b02bc28b99cb3e287e85a763af267492ab572e99ab3f370d275cec1da1aaa9075ff05f79be
    concat
    // contracts/plonk_bls12381.algo.ts:806-810
    // const res = op.EllipticCurve.pairingCheck(
    //   op.Ec.BLS12_381g1,
    //   g1Neg(A1).concat(B1), // G1 points
    //   vk.X_2.concat(G2_ONE), // G2 points
    // );
    ec_pairing_check BLS12_381g1
    // contracts/plonk_verifier.algo.ts:60
    // assert(verifyPlonkFromTemplate(signals, proof), "Verification failed");
    assert // Verification failed
    // contracts/plonk_verifier.algo.ts:62
    // return true;
    intc_2 // 1
    return

main_ternary_false@15:
    dig 1
    bury 22
    b main_ternary_merge@16


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
    // contracts/plonk_bls12381.algo.ts:397
    // export function getChallenge(td: bytes): Uint256 {
    proto 1 1
    // contracts/plonk_bls12381.algo.ts:398
    // let hash = op.keccak256(td);
    frame_dig -1
    keccak256
    // contracts/bls12381_common.algo.ts:37
    // return a % BLS12_381_SCALAR_MODULUS;
    bytec_0 // 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001
    b%
    // contracts/plonk_bls12381.algo.ts:399
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
export const GROTH16_LSIG_SOURCE = `#pragma version 11
#pragma typetrack false

// contracts/groth16_bls12381_verifier.algo.ts::program() -> uint64:
main:
    intcblock 32 1 96 0 680 TMPL_APP_OFFSET
    bytecblock 0x 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001 TMPL_VERIFICATION_KEY
    intc_3 // 0
    dup
    bytec_0 // ""
    // contracts/groth16_bls12381_verifier.algo.ts:49
    // assertMatch(Txn, { fee: 0, rekeyTo: Global.zeroAddress });
    txn Fee
    !
    txn RekeyTo
    global ZeroAddress
    ==
    &&
    assert // assert target is match for conditions
    // contracts/groth16_bls12381_verifier.algo.ts:50
    // const idx: uint64 = Txn.groupIndex + APP_OFFSET;
    txn GroupIndex
    intc 5 // TMPL_APP_OFFSET
    +
    // contracts/groth16_bls12381_verifier.algo.ts:52-54
    // const proof = decodeArc4<Groth16Bls12381Proof>(
    //   GTxn.applicationArgs(idx, 2),
    // );
    dup
    // contracts/groth16_bls12381_verifier.algo.ts:53
    // GTxn.applicationArgs(idx, 2),
    pushint 2 // 2
    gtxnsas ApplicationArgs
    // contracts/groth16_bls12381_verifier.algo.ts:55
    // const signals = decodeArc4<PublicSignals>(GTxn.applicationArgs(idx, 1));
    swap
    intc_1 // 1
    gtxnsas ApplicationArgs
    dup
    uncover 2
    // contracts/groth16_bls12381.algo.ts:253
    // decodeArc4<Groth16Bls12381VerificationKey>(vkBytes),
    bytec_2 // TMPL_VERIFICATION_KEY
    dup
    cover 3
    cover 3
    // contracts/groth16_bls12381.algo.ts:84
    // assert(g1GroupCheck(proof.pi_a), "pi_a not in G1");
    dup
    extract 0 96
    dup
    cover 4
    // contracts/groth16_bls12381.algo.ts:70
    // return op.EllipticCurve.subgroupCheck(op.Ec.BLS12_381g1, p);
    ec_subgroup_check BLS12_381g1
    // contracts/groth16_bls12381.algo.ts:84
    // assert(g1GroupCheck(proof.pi_a), "pi_a not in G1");
    assert // pi_a not in G1
    // contracts/groth16_bls12381.algo.ts:85
    // assert(g2GroupCheck(proof.pi_b), "pi_b not in G2");
    dup
    extract 96 192
    dup
    cover 4
    // contracts/groth16_bls12381.algo.ts:77
    // return op.EllipticCurve.subgroupCheck(op.Ec.BLS12_381g2, p);
    ec_subgroup_check BLS12_381g2
    // contracts/groth16_bls12381.algo.ts:85
    // assert(g2GroupCheck(proof.pi_b), "pi_b not in G2");
    assert // pi_b not in G2
    // contracts/groth16_bls12381.algo.ts:86
    // assert(g1GroupCheck(proof.pi_c), "pi_c not in G1");
    pushint 288 // 288
    intc_2 // 96
    extract3
    dup
    cover 3
    // contracts/groth16_bls12381.algo.ts:70
    // return op.EllipticCurve.subgroupCheck(op.Ec.BLS12_381g1, p);
    ec_subgroup_check BLS12_381g1
    // contracts/groth16_bls12381.algo.ts:86
    // assert(g1GroupCheck(proof.pi_c), "pi_c not in G1");
    assert // pi_c not in G1
    // contracts/groth16_bls12381.algo.ts:96
    // assert(signals.length === vk.nPublic, "Invalid number of public inputs");
    intc_3 // 0
    extract_uint16 // on error: invalid array length header
    dup
    uncover 2
    pushint 672 // 672
    extract_uint64
    ==
    assert // Invalid number of public inputs
    intc_3 // 0

main_for_header@2:
    // contracts/groth16_bls12381.algo.ts:98
    // for (const signal of signals) {
    dup
    dig 2
    <
    bz main_after_for@4
    dig 6
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
    bytec_1 // 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001
    b<
    // contracts/groth16_bls12381.algo.ts:99
    // assert(inField(signal), "public signal not in Fr");
    assert // public signal not in Fr
    intc_1 // 1
    +
    bury 1
    b main_for_header@2

main_after_for@4:
    // contracts/groth16_bls12381.algo.ts:128
    // if (signals.length === 0) {
    dig 1
    bnz main_after_if_else@6
    // contracts/groth16_bls12381.algo.ts:130
    // return vk.IC[0] as bytes<96>;
    dig 5
    dup
    intc 4 // 680
    extract_uint16
    dig 1
    len
    substring3
    extract 2 96

main_after_inlined_contracts/groth16_bls12381.algo.ts::computeCpub@13:
    // contracts/bls12381_common.algo.ts:62
    // return op.EllipticCurve.scalarMul(op.Ec.BLS12_381g1, p, Bytes(s)).toFixed({
    dig 5
    // contracts/bls12381_common.algo.ts:84
    // return g1TimesFr(p, R_MINUS_1);
    pushbytes 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000000
    // contracts/bls12381_common.algo.ts:62
    // return op.EllipticCurve.scalarMul(op.Ec.BLS12_381g1, p, Bytes(s)).toFixed({
    ec_scalar_mul BLS12_381g1
    // contracts/bls12381_common.algo.ts:62-64
    // return op.EllipticCurve.scalarMul(op.Ec.BLS12_381g1, p, Bytes(s)).toFixed({
    //   length: 96,
    // });
    dup
    len
    intc_2 // 96
    ==
    assert // Length must be 96
    // contracts/groth16_bls12381.algo.ts:181
    // const g1Points = negPiA.concat(cpub).concat(proof.pi_c).concat(vk.vk_alpha_1);
    swap
    concat
    dig 3
    concat
    dig 6
    dup
    cover 2
    extract 0 96
    concat
    // contracts/groth16_bls12381.algo.ts:185
    // .concat(vk.vk_gamma_2)
    dig 1
    pushints 288 192 // 288, 192
    extract3
    // contracts/groth16_bls12381.algo.ts:184-185
    // const g2Points = proof.pi_b
    //   .concat(vk.vk_gamma_2)
    dig 6
    swap
    concat
    // contracts/groth16_bls12381.algo.ts:186
    // .concat(vk.vk_delta_2)
    dig 2
    pushints 480 192 // 480, 192
    extract3
    // contracts/groth16_bls12381.algo.ts:184-186
    // const g2Points = proof.pi_b
    //   .concat(vk.vk_gamma_2)
    //   .concat(vk.vk_delta_2)
    concat
    // contracts/groth16_bls12381.algo.ts:187
    // .concat(vk.vk_beta_2);
    uncover 2
    extract 96 192
    // contracts/groth16_bls12381.algo.ts:184-187
    // const g2Points = proof.pi_b
    //   .concat(vk.vk_gamma_2)
    //   .concat(vk.vk_delta_2)
    //   .concat(vk.vk_beta_2);
    concat
    // contracts/groth16_bls12381.algo.ts:190-194
    // const res = op.EllipticCurve.pairingCheck(
    //   op.Ec.BLS12_381g1,
    //   g1Points,
    //   g2Points,
    // );
    ec_pairing_check BLS12_381g1
    // contracts/groth16_bls12381_verifier.algo.ts:57
    // assert(verifyFromTemplate(signals, proof), "Verification failed");
    assert // Verification failed
    // contracts/groth16_bls12381_verifier.algo.ts:59
    // return true;
    intc_1 // 1
    return

main_after_if_else@6:
    // contracts/groth16_bls12381.algo.ts:134
    // let icPoints = Bytes();
    bytec_0 // 0x
    bury 10
    // contracts/groth16_bls12381.algo.ts:135
    // for (let i: uint64 = 1; i <= signals.length; i++) {
    intc_1 // 1
    bury 8

main_while_top@7:
    // contracts/groth16_bls12381.algo.ts:135
    // for (let i: uint64 = 1; i <= signals.length; i++) {
    dig 7
    dig 2
    <=
    bz main_after_while@9
    // contracts/groth16_bls12381.algo.ts:136
    // icPoints = icPoints.concat(vk.IC.at(i)!);
    dig 5
    dup
    intc 4 // 680
    extract_uint16
    dig 1
    len
    substring3
    extract 2 0
    dig 8
    dup
    cover 2
    intc_2 // 96
    *
    intc_2 // 96
    extract3 // on error: index access is out of bounds
    dig 11
    swap
    concat
    bury 11
    // contracts/groth16_bls12381.algo.ts:135
    // for (let i: uint64 = 1; i <= signals.length; i++) {
    intc_1 // 1
    +
    bury 8
    b main_while_top@7

main_after_while@9:
    // contracts/groth16_bls12381.algo.ts:140
    // let scalars = Bytes();
    bytec_0 // 0x
    bury 9
    intc_3 // 0
    bury 1

main_for_header@10:
    // contracts/groth16_bls12381.algo.ts:141
    // for (const signal of signals) {
    dup
    dig 2
    <
    bz main_after_for@12
    dig 6
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
    bytec_1 // 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001
    b%
    // contracts/bls12381_common.algo.ts:45
    // return new Uint256(a).bytes.toFixed({ length: 32 });
    dup
    len
    intc_0 // 32
    <=
    assert // overflow
    intc_0 // 32
    bzero
    b|
    dup
    len
    intc_0 // 32
    ==
    assert // Length must be 32
    // contracts/groth16_bls12381.algo.ts:142
    // scalars = scalars.concat(b32(frScalar(signal.asBigUint())));
    dig 10
    swap
    concat
    bury 10
    intc_1 // 1
    +
    bury 1
    b main_for_header@10

main_after_for@12:
    // contracts/groth16_bls12381.algo.ts:146-150
    // let cpub = op.EllipticCurve.scalarMulMulti(
    //   op.Ec.BLS12_381g1,
    //   icPoints,
    //   scalars,
    // ).toFixed({ length: 96 });
    dig 9
    dig 9
    ec_multi_scalar_mul BLS12_381g1
    dup
    len
    intc_2 // 96
    ==
    assert // Length must be 96
    // contracts/groth16_bls12381.algo.ts:153
    // cpub = g1Add(cpub, vk.IC[0] as bytes<96>);
    dig 6
    dup
    intc 4 // 680
    extract_uint16
    dig 1
    len
    substring3
    extract 2 96
    // contracts/bls12381_common.algo.ts:73
    // return op.EllipticCurve.add(op.Ec.BLS12_381g1, p1, p2).toFixed({
    ec_add BLS12_381g1
    dup
    // contracts/bls12381_common.algo.ts:73-75
    // return op.EllipticCurve.add(op.Ec.BLS12_381g1, p1, p2).toFixed({
    //   length: 96,
    // });
    len
    intc_2 // 96
    ==
    assert // Length must be 96
    // contracts/groth16_bls12381.algo.ts:175
    // const cpub = computeCpub(vk, signals);
    b main_after_inlined_contracts/groth16_bls12381.algo.ts::computeCpub@13
`;
export const GROTH16_BN254_LSIG_SOURCE = `#pragma version 11
#pragma typetrack false

// contracts/groth16_bn254_verifier.algo.ts::program() -> uint64:
main:
    intcblock 32 1 64 0 456 TMPL_APP_OFFSET
    bytecblock 0x 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001 TMPL_VERIFICATION_KEY
    intc_3 // 0
    dup
    bytec_0 // ""
    // contracts/groth16_bn254_verifier.algo.ts:49
    // assertMatch(Txn, { fee: 0, rekeyTo: Global.zeroAddress });
    txn Fee
    !
    txn RekeyTo
    global ZeroAddress
    ==
    &&
    assert // assert target is match for conditions
    // contracts/groth16_bn254_verifier.algo.ts:50
    // const idx: uint64 = Txn.groupIndex + APP_OFFSET;
    txn GroupIndex
    intc 5 // TMPL_APP_OFFSET
    +
    // contracts/groth16_bn254_verifier.algo.ts:52
    // const proof = decodeArc4<Groth16Bn254Proof>(GTxn.applicationArgs(idx, 2));
    dup
    pushint 2 // 2
    gtxnsas ApplicationArgs
    // contracts/groth16_bn254_verifier.algo.ts:53
    // const signals = decodeArc4<PublicSignals>(GTxn.applicationArgs(idx, 1));
    swap
    intc_1 // 1
    gtxnsas ApplicationArgs
    dup
    uncover 2
    // contracts/groth16_bn254.algo.ts:245
    // decodeArc4<Groth16Bn254VerificationKey>(vkBytes),
    bytec_2 // TMPL_VERIFICATION_KEY
    dup
    cover 3
    cover 3
    // contracts/groth16_bn254.algo.ts:84
    // assert(g1GroupCheck(proof.pi_a), "pi_a not in G1");
    dup
    extract 0 64
    dup
    cover 4
    // contracts/groth16_bn254.algo.ts:70
    // return op.EllipticCurve.subgroupCheck(op.Ec.BN254g1, p);
    ec_subgroup_check BN254g1
    // contracts/groth16_bn254.algo.ts:84
    // assert(g1GroupCheck(proof.pi_a), "pi_a not in G1");
    assert // pi_a not in G1
    // contracts/groth16_bn254.algo.ts:85
    // assert(g2GroupCheck(proof.pi_b), "pi_b not in G2");
    dup
    extract 64 128
    dup
    cover 4
    // contracts/groth16_bn254.algo.ts:77
    // return op.EllipticCurve.subgroupCheck(op.Ec.BN254g2, p);
    ec_subgroup_check BN254g2
    // contracts/groth16_bn254.algo.ts:85
    // assert(g2GroupCheck(proof.pi_b), "pi_b not in G2");
    assert // pi_b not in G2
    // contracts/groth16_bn254.algo.ts:86
    // assert(g1GroupCheck(proof.pi_c), "pi_c not in G1");
    extract 192 64
    dup
    cover 3
    // contracts/groth16_bn254.algo.ts:70
    // return op.EllipticCurve.subgroupCheck(op.Ec.BN254g1, p);
    ec_subgroup_check BN254g1
    // contracts/groth16_bn254.algo.ts:86
    // assert(g1GroupCheck(proof.pi_c), "pi_c not in G1");
    assert // pi_c not in G1
    // contracts/groth16_bn254.algo.ts:96
    // assert(signals.length === vk.nPublic, "Invalid number of public inputs");
    intc_3 // 0
    extract_uint16 // on error: invalid array length header
    dup
    uncover 2
    pushint 448 // 448
    extract_uint64
    ==
    assert // Invalid number of public inputs
    intc_3 // 0

main_for_header@2:
    // contracts/groth16_bn254.algo.ts:98
    // for (const signal of signals) {
    dup
    dig 2
    <
    bz main_after_for@4
    dig 6
    extract 2 0
    dig 1
    dup
    cover 2
    intc_0 // 32
    *
    intc_0 // 32
    extract3 // on error: index access is out of bounds
    // contracts/bn254_common.algo.ts:89
    // return value.asBigUint() < BN254_SCALAR_MODULUS;
    bytec_1 // 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001
    b<
    // contracts/groth16_bn254.algo.ts:99
    // assert(inField(signal), "public signal not in Fr");
    assert // public signal not in Fr
    intc_1 // 1
    +
    bury 1
    b main_for_header@2

main_after_for@4:
    // contracts/groth16_bn254.algo.ts:128
    // if (signals.length === 0) {
    dig 1
    bnz main_after_if_else@6
    // contracts/groth16_bn254.algo.ts:130
    // return vk.IC[0] as bytes<64>;
    dig 5
    dup
    intc 4 // 456
    extract_uint16
    dig 1
    len
    substring3
    extract 2 64

main_after_inlined_contracts/groth16_bn254.algo.ts::computeCpub@13:
    // contracts/bn254_common.algo.ts:62
    // return op.EllipticCurve.scalarMul(op.Ec.BN254g1, p, Bytes(s)).toFixed({
    dig 5
    // contracts/bn254_common.algo.ts:82
    // return g1TimesFr(p, R_MINUS_1);
    pushbytes 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000000
    // contracts/bn254_common.algo.ts:62
    // return op.EllipticCurve.scalarMul(op.Ec.BN254g1, p, Bytes(s)).toFixed({
    ec_scalar_mul BN254g1
    // contracts/bn254_common.algo.ts:62-64
    // return op.EllipticCurve.scalarMul(op.Ec.BN254g1, p, Bytes(s)).toFixed({
    //   length: 64,
    // });
    dup
    len
    intc_2 // 64
    ==
    assert // Length must be 64
    // contracts/groth16_bn254.algo.ts:181
    // const g1Points = negPiA.concat(cpub).concat(proof.pi_c).concat(vk.vk_alpha_1);
    swap
    concat
    dig 3
    concat
    dig 6
    dup
    cover 2
    extract 0 64
    concat
    // contracts/groth16_bn254.algo.ts:185
    // .concat(vk.vk_gamma_2)
    dig 1
    extract 192 128
    // contracts/groth16_bn254.algo.ts:184-185
    // const g2Points = proof.pi_b
    //   .concat(vk.vk_gamma_2)
    dig 6
    swap
    concat
    // contracts/groth16_bn254.algo.ts:186
    // .concat(vk.vk_delta_2)
    dig 2
    pushints 320 128 // 320, 128
    extract3
    // contracts/groth16_bn254.algo.ts:184-186
    // const g2Points = proof.pi_b
    //   .concat(vk.vk_gamma_2)
    //   .concat(vk.vk_delta_2)
    concat
    // contracts/groth16_bn254.algo.ts:187
    // .concat(vk.vk_beta_2);
    uncover 2
    extract 64 128
    // contracts/groth16_bn254.algo.ts:184-187
    // const g2Points = proof.pi_b
    //   .concat(vk.vk_gamma_2)
    //   .concat(vk.vk_delta_2)
    //   .concat(vk.vk_beta_2);
    concat
    // contracts/groth16_bn254.algo.ts:190
    // const res = op.EllipticCurve.pairingCheck(op.Ec.BN254g1, g1Points, g2Points);
    ec_pairing_check BN254g1
    // contracts/groth16_bn254_verifier.algo.ts:55
    // assert(verifyFromTemplate(signals, proof), "Verification failed");
    assert // Verification failed
    // contracts/groth16_bn254_verifier.algo.ts:57
    // return true;
    intc_1 // 1
    return

main_after_if_else@6:
    // contracts/groth16_bn254.algo.ts:134
    // let icPoints = Bytes();
    bytec_0 // 0x
    bury 10
    // contracts/groth16_bn254.algo.ts:135
    // for (let i: uint64 = 1; i <= signals.length; i++) {
    intc_1 // 1
    bury 8

main_while_top@7:
    // contracts/groth16_bn254.algo.ts:135
    // for (let i: uint64 = 1; i <= signals.length; i++) {
    dig 7
    dig 2
    <=
    bz main_after_while@9
    // contracts/groth16_bn254.algo.ts:136
    // icPoints = icPoints.concat(vk.IC.at(i)!);
    dig 5
    dup
    intc 4 // 456
    extract_uint16
    dig 1
    len
    substring3
    extract 2 0
    dig 8
    dup
    cover 2
    intc_2 // 64
    *
    intc_2 // 64
    extract3 // on error: index access is out of bounds
    dig 11
    swap
    concat
    bury 11
    // contracts/groth16_bn254.algo.ts:135
    // for (let i: uint64 = 1; i <= signals.length; i++) {
    intc_1 // 1
    +
    bury 8
    b main_while_top@7

main_after_while@9:
    // contracts/groth16_bn254.algo.ts:140
    // let scalars = Bytes();
    bytec_0 // 0x
    bury 9
    intc_3 // 0
    bury 1

main_for_header@10:
    // contracts/groth16_bn254.algo.ts:141
    // for (const signal of signals) {
    dup
    dig 2
    <
    bz main_after_for@12
    dig 6
    extract 2 0
    dig 1
    dup
    cover 2
    intc_0 // 32
    *
    intc_0 // 32
    extract3 // on error: index access is out of bounds
    // contracts/bn254_common.algo.ts:37
    // return a % BN254_SCALAR_MODULUS;
    bytec_1 // 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001
    b%
    // contracts/bn254_common.algo.ts:45
    // return new Uint256(a).bytes.toFixed({ length: 32 });
    dup
    len
    intc_0 // 32
    <=
    assert // overflow
    intc_0 // 32
    bzero
    b|
    dup
    len
    intc_0 // 32
    ==
    assert // Length must be 32
    // contracts/groth16_bn254.algo.ts:142
    // scalars = scalars.concat(b32(frScalar(signal.asBigUint())));
    dig 10
    swap
    concat
    bury 10
    intc_1 // 1
    +
    bury 1
    b main_for_header@10

main_after_for@12:
    // contracts/groth16_bn254.algo.ts:146-150
    // let cpub = op.EllipticCurve.scalarMulMulti(
    //   op.Ec.BN254g1,
    //   icPoints,
    //   scalars,
    // ).toFixed({ length: 64 });
    dig 9
    dig 9
    ec_multi_scalar_mul BN254g1
    dup
    len
    intc_2 // 64
    ==
    assert // Length must be 64
    // contracts/groth16_bn254.algo.ts:153
    // cpub = g1Add(cpub, vk.IC[0] as bytes<64>);
    dig 6
    dup
    intc 4 // 456
    extract_uint16
    dig 1
    len
    substring3
    extract 2 64
    // contracts/bn254_common.algo.ts:73
    // return op.EllipticCurve.add(op.Ec.BN254g1, p1, p2).toFixed({ length: 64 });
    ec_add BN254g1
    dup
    len
    intc_2 // 64
    ==
    assert // Length must be 64
    // contracts/groth16_bn254.algo.ts:175
    // const cpub = computeCpub(vk, signals);
    b main_after_inlined_contracts/groth16_bn254.algo.ts::computeCpub@13
`;
