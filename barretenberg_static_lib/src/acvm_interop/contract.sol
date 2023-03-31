// SPDX-License-Identifier: Apache-2.0
// Copyright 2022 Aztec
pragma solidity >=0.8.4;
// gas cost at 5000 optimizer runs 0.8.10: 287,589 (includes 21,000 base cost)

/**
 * @title Ultra Plonk proof verification contract
 * @dev Top level Plonk proof verification contract, which allows Plonk proof to be verified
 */
abstract contract BaseUltraVerifier {
    // VERIFICATION KEY MEMORY LOCATIONS
    uint256 internal constant N_LOC = 0x380;
    uint256 internal constant NUM_INPUTS_LOC = 0x3a0;
    uint256 internal constant OMEGA_LOC = 0x3c0;
    uint256 internal constant DOMAIN_INVERSE_LOC = 0x3e0;
    uint256 internal constant Q1_X_LOC = 0x400;
    uint256 internal constant Q1_Y_LOC = 0x420;
    uint256 internal constant Q2_X_LOC = 0x440;
    uint256 internal constant Q2_Y_LOC = 0x460;
    uint256 internal constant Q3_X_LOC = 0x480;
    uint256 internal constant Q3_Y_LOC = 0x4a0;
    uint256 internal constant Q4_X_LOC = 0x4c0;
    uint256 internal constant Q4_Y_LOC = 0x4e0;
    uint256 internal constant QM_X_LOC = 0x500;
    uint256 internal constant QM_Y_LOC = 0x520;
    uint256 internal constant QC_X_LOC = 0x540;
    uint256 internal constant QC_Y_LOC = 0x560;
    uint256 internal constant QARITH_X_LOC = 0x580;
    uint256 internal constant QARITH_Y_LOC = 0x5a0;
    uint256 internal constant QSORT_X_LOC = 0x5c0;
    uint256 internal constant QSORT_Y_LOC = 0x5e0;
    uint256 internal constant QELLIPTIC_X_LOC = 0x600;
    uint256 internal constant QELLIPTIC_Y_LOC = 0x620;
    uint256 internal constant QAUX_X_LOC = 0x640;
    uint256 internal constant QAUX_Y_LOC = 0x660;
    uint256 internal constant SIGMA1_X_LOC = 0x680;
    uint256 internal constant SIGMA1_Y_LOC = 0x6a0;
    uint256 internal constant SIGMA2_X_LOC = 0x6c0;
    uint256 internal constant SIGMA2_Y_LOC = 0x6e0;
    uint256 internal constant SIGMA3_X_LOC = 0x700;
    uint256 internal constant SIGMA3_Y_LOC = 0x720;
    uint256 internal constant SIGMA4_X_LOC = 0x740;
    uint256 internal constant SIGMA4_Y_LOC = 0x760;
    uint256 internal constant TABLE1_X_LOC = 0x780;
    uint256 internal constant TABLE1_Y_LOC = 0x7a0;
    uint256 internal constant TABLE2_X_LOC = 0x7c0;
    uint256 internal constant TABLE2_Y_LOC = 0x7e0;
    uint256 internal constant TABLE3_X_LOC = 0x800;
    uint256 internal constant TABLE3_Y_LOC = 0x820;
    uint256 internal constant TABLE4_X_LOC = 0x840;
    uint256 internal constant TABLE4_Y_LOC = 0x860;
    uint256 internal constant TABLE_TYPE_X_LOC = 0x880;
    uint256 internal constant TABLE_TYPE_Y_LOC = 0x8a0;
    uint256 internal constant ID1_X_LOC = 0x8c0;
    uint256 internal constant ID1_Y_LOC = 0x8e0;
    uint256 internal constant ID2_X_LOC = 0x900;
    uint256 internal constant ID2_Y_LOC = 0x920;
    uint256 internal constant ID3_X_LOC = 0x940;
    uint256 internal constant ID3_Y_LOC = 0x960;
    uint256 internal constant ID4_X_LOC = 0x980;
    uint256 internal constant ID4_Y_LOC = 0x9a0;
    uint256 internal constant CONTAINS_RECURSIVE_PROOF_LOC = 0x9c0;
    uint256 internal constant RECURSIVE_PROOF_PUBLIC_INPUT_INDICES_LOC = 0x9e0;
    uint256 internal constant G2X_X0_LOC = 0xa00;
    uint256 internal constant G2X_X1_LOC = 0xa20;
    uint256 internal constant G2X_Y0_LOC = 0xa40;
    uint256 internal constant G2X_Y1_LOC = 0xa60;
    // 26

    // ### PROOF DATA MEMORY LOCATIONS
    uint256 internal constant W1_X_LOC = 0x1200;
    uint256 internal constant W1_Y_LOC = 0x1220;
    uint256 internal constant W2_X_LOC = 0x1240;
    uint256 internal constant W2_Y_LOC = 0x1260;
    uint256 internal constant W3_X_LOC = 0x1280;
    uint256 internal constant W3_Y_LOC = 0x12a0;
    uint256 internal constant W4_X_LOC = 0x12c0;
    uint256 internal constant W4_Y_LOC = 0x12e0;
    uint256 internal constant S_X_LOC = 0x1300;
    uint256 internal constant S_Y_LOC = 0x1320;
    uint256 internal constant Z_X_LOC = 0x1340;
    uint256 internal constant Z_Y_LOC = 0x1360;
    uint256 internal constant Z_LOOKUP_X_LOC = 0x1380;
    uint256 internal constant Z_LOOKUP_Y_LOC = 0x13a0;
    uint256 internal constant T1_X_LOC = 0x13c0;
    uint256 internal constant T1_Y_LOC = 0x13e0;
    uint256 internal constant T2_X_LOC = 0x1400;
    uint256 internal constant T2_Y_LOC = 0x1420;
    uint256 internal constant T3_X_LOC = 0x1440;
    uint256 internal constant T3_Y_LOC = 0x1460;
    uint256 internal constant T4_X_LOC = 0x1480;
    uint256 internal constant T4_Y_LOC = 0x14a0;

    uint256 internal constant W1_EVAL_LOC = 0x1600;
    uint256 internal constant W2_EVAL_LOC = 0x1620;
    uint256 internal constant W3_EVAL_LOC = 0x1640;
    uint256 internal constant W4_EVAL_LOC = 0x1660;
    uint256 internal constant S_EVAL_LOC = 0x1680;
    uint256 internal constant Z_EVAL_LOC = 0x16a0;
    uint256 internal constant Z_LOOKUP_EVAL_LOC = 0x16c0;
    uint256 internal constant Q1_EVAL_LOC = 0x16e0;
    uint256 internal constant Q2_EVAL_LOC = 0x1700;
    uint256 internal constant Q3_EVAL_LOC = 0x1720;
    uint256 internal constant Q4_EVAL_LOC = 0x1740;
    uint256 internal constant QM_EVAL_LOC = 0x1760;
    uint256 internal constant QC_EVAL_LOC = 0x1780;
    uint256 internal constant QARITH_EVAL_LOC = 0x17a0;
    uint256 internal constant QSORT_EVAL_LOC = 0x17c0;
    uint256 internal constant QELLIPTIC_EVAL_LOC = 0x17e0;
    uint256 internal constant QAUX_EVAL_LOC = 0x1800;
    uint256 internal constant TABLE1_EVAL_LOC = 0x1840;
    uint256 internal constant TABLE2_EVAL_LOC = 0x1860;
    uint256 internal constant TABLE3_EVAL_LOC = 0x1880;
    uint256 internal constant TABLE4_EVAL_LOC = 0x18a0;
    uint256 internal constant TABLE_TYPE_EVAL_LOC = 0x18c0;
    uint256 internal constant ID1_EVAL_LOC = 0x18e0;
    uint256 internal constant ID2_EVAL_LOC = 0x1900;
    uint256 internal constant ID3_EVAL_LOC = 0x1920;
    uint256 internal constant ID4_EVAL_LOC = 0x1940;
    uint256 internal constant SIGMA1_EVAL_LOC = 0x1960;
    uint256 internal constant SIGMA2_EVAL_LOC = 0x1980;
    uint256 internal constant SIGMA3_EVAL_LOC = 0x19a0;
    uint256 internal constant SIGMA4_EVAL_LOC = 0x19c0;
    uint256 internal constant W1_OMEGA_EVAL_LOC = 0x19e0;
    uint256 internal constant W2_OMEGA_EVAL_LOC = 0x2000;
    uint256 internal constant W3_OMEGA_EVAL_LOC = 0x2020;
    uint256 internal constant W4_OMEGA_EVAL_LOC = 0x2040;
    uint256 internal constant S_OMEGA_EVAL_LOC = 0x2060;
    uint256 internal constant Z_OMEGA_EVAL_LOC = 0x2080;
    uint256 internal constant Z_LOOKUP_OMEGA_EVAL_LOC = 0x20a0;
    uint256 internal constant TABLE1_OMEGA_EVAL_LOC = 0x20c0;
    uint256 internal constant TABLE2_OMEGA_EVAL_LOC = 0x20e0;
    uint256 internal constant TABLE3_OMEGA_EVAL_LOC = 0x2100;
    uint256 internal constant TABLE4_OMEGA_EVAL_LOC = 0x2120;

    uint256 internal constant PI_Z_X_LOC = 0x2300;
    uint256 internal constant PI_Z_Y_LOC = 0x2320;
    uint256 internal constant PI_Z_OMEGA_X_LOC = 0x2340;
    uint256 internal constant PI_Z_OMEGA_Y_LOC = 0x2360;

    // Used for elliptic widget. These are alias names for wire + shifted wire evaluations
    uint256 internal constant X1_EVAL_LOC = W2_EVAL_LOC;
    uint256 internal constant X2_EVAL_LOC = W1_OMEGA_EVAL_LOC;
    uint256 internal constant X3_EVAL_LOC = W2_OMEGA_EVAL_LOC;
    uint256 internal constant Y1_EVAL_LOC = W3_EVAL_LOC;
    uint256 internal constant Y2_EVAL_LOC = W4_OMEGA_EVAL_LOC;
    uint256 internal constant Y3_EVAL_LOC = W3_OMEGA_EVAL_LOC;
    uint256 internal constant QBETA_LOC = Q3_EVAL_LOC;
    uint256 internal constant QBETA_SQR_LOC = Q4_EVAL_LOC;
    uint256 internal constant QSIGN_LOC = Q1_EVAL_LOC;

    // ### CHALLENGES MEMORY OFFSETS

    uint256 internal constant C_BETA_LOC = 0x2600;
    uint256 internal constant C_GAMMA_LOC = 0x2620;
    uint256 internal constant C_ALPHA_LOC = 0x2640;
    uint256 internal constant C_ETA_LOC = 0x2660;
    uint256 internal constant C_ETA_SQR_LOC = 0x2680;
    uint256 internal constant C_ETA_CUBE_LOC = 0x26a0;

    uint256 internal constant C_ZETA_LOC = 0x26c0;
    uint256 internal constant C_CURRENT_LOC = 0x26e0;
    uint256 internal constant C_V0_LOC = 0x2700;
    uint256 internal constant C_V1_LOC = 0x2720;
    uint256 internal constant C_V2_LOC = 0x2740;
    uint256 internal constant C_V3_LOC = 0x2760;
    uint256 internal constant C_V4_LOC = 0x2780;
    uint256 internal constant C_V5_LOC = 0x27a0;
    uint256 internal constant C_V6_LOC = 0x27c0;
    uint256 internal constant C_V7_LOC = 0x27e0;
    uint256 internal constant C_V8_LOC = 0x2800;
    uint256 internal constant C_V9_LOC = 0x2820;
    uint256 internal constant C_V10_LOC = 0x2840;
    uint256 internal constant C_V11_LOC = 0x2860;
    uint256 internal constant C_V12_LOC = 0x2880;
    uint256 internal constant C_V13_LOC = 0x28a0;
    uint256 internal constant C_V14_LOC = 0x28c0;
    uint256 internal constant C_V15_LOC = 0x28e0;
    uint256 internal constant C_V16_LOC = 0x2900;
    uint256 internal constant C_V17_LOC = 0x2920;
    uint256 internal constant C_V18_LOC = 0x2940;
    uint256 internal constant C_V19_LOC = 0x2960;
    uint256 internal constant C_V20_LOC = 0x2980;
    uint256 internal constant C_V21_LOC = 0x29a0;
    uint256 internal constant C_V22_LOC = 0x29c0;
    uint256 internal constant C_V23_LOC = 0x29e0;
    uint256 internal constant C_V24_LOC = 0x2a00;
    uint256 internal constant C_V25_LOC = 0x2a20;
    uint256 internal constant C_V26_LOC = 0x2a40;
    uint256 internal constant C_V27_LOC = 0x2a60;
    uint256 internal constant C_V28_LOC = 0x2a80;
    uint256 internal constant C_V29_LOC = 0x2aa0;
    uint256 internal constant C_V30_LOC = 0x2ac0;

    uint256 internal constant C_U_LOC = 0x2b00;
    // 13

    // ### LOCAL VARIABLES MEMORY OFFSETS
    uint256 internal constant DELTA_NUMERATOR_LOC = 0x3000;
    uint256 internal constant DELTA_DENOMINATOR_LOC = 0x3020;
    uint256 internal constant ZETA_POW_N_LOC = 0x3040;
    uint256 internal constant PUBLIC_INPUT_DELTA_LOC = 0x3060;
    uint256 internal constant ZERO_POLY_LOC = 0x3080;
    uint256 internal constant L_START_LOC = 0x30a0;
    uint256 internal constant L_END_LOC = 0x30c0;
    uint256 internal constant R_ZERO_EVAL_LOC = 0x30e0;

    uint256 internal constant PLOOKUP_DELTA_NUMERATOR_LOC = 0x3100;
    uint256 internal constant PLOOKUP_DELTA_DENOMINATOR_LOC = 0x3120;
    uint256 internal constant PLOOKUP_DELTA_LOC = 0x3140;

    uint256 internal constant ACCUMULATOR_X_LOC = 0x3160;
    uint256 internal constant ACCUMULATOR_Y_LOC = 0x3180;
    uint256 internal constant ACCUMULATOR2_X_LOC = 0x31a0;
    uint256 internal constant ACCUMULATOR2_Y_LOC = 0x31c0;
    uint256 internal constant PAIRING_LHS_X_LOC = 0x31e0;
    uint256 internal constant PAIRING_LHS_Y_LOC = 0x3200;
    uint256 internal constant PAIRING_RHS_X_LOC = 0x3220;
    uint256 internal constant PAIRING_RHS_Y_LOC = 0x3240;
    // 16

    // ### SUCCESS FLAG MEMORY LOCATIONS
    uint256 internal constant GRAND_PRODUCT_SUCCESS_FLAG = 0x3300;
    uint256 internal constant ARITHMETIC_TERM_SUCCESS_FLAG = 0x3020;
    uint256 internal constant BATCH_OPENING_SUCCESS_FLAG = 0x3340;
    uint256 internal constant OPENING_COMMITMENT_SUCCESS_FLAG = 0x3360;
    uint256 internal constant PAIRING_PREAMBLE_SUCCESS_FLAG = 0x3380;
    uint256 internal constant PAIRING_SUCCESS_FLAG = 0x33a0;
    uint256 internal constant RESULT_FLAG = 0x33c0;
    // 7

    // misc stuff
    uint256 internal constant OMEGA_INVERSE_LOC = 0x3400;
    uint256 internal constant C_ALPHA_SQR_LOC = 0x3420;
    uint256 internal constant C_ALPHA_CUBE_LOC = 0x3440;
    uint256 internal constant C_ALPHA_QUAD_LOC = 0x3460;
    uint256 internal constant C_ALPHA_BASE_LOC = 0x3480;

    // 2

    // ### RECURSION VARIABLE MEMORY LOCATIONS
    uint256 internal constant RECURSIVE_P1_X_LOC = 0x3500;
    uint256 internal constant RECURSIVE_P1_Y_LOC = 0x3520;
    uint256 internal constant RECURSIVE_P2_X_LOC = 0x3540;
    uint256 internal constant RECURSIVE_P2_Y_LOC = 0x3560;

    uint256 internal constant PUBLIC_INPUTS_HASH_LOCATION = 0x3580;

    // sub-identity storage
    uint256 internal constant PERMUTATION_IDENTITY = 0x3600;
    uint256 internal constant PLOOKUP_IDENTITY = 0x3620;
    uint256 internal constant ARITHMETIC_IDENTITY = 0x3640;
    uint256 internal constant SORT_IDENTITY = 0x3660;
    uint256 internal constant ELLIPTIC_IDENTITY = 0x3680;
    uint256 internal constant AUX_IDENTITY = 0x36a0;
    uint256 internal constant AUX_NON_NATIVE_FIELD_EVALUATION = 0x36c0;
    uint256 internal constant AUX_LIMB_ACCUMULATOR_EVALUATION = 0x36e0;
    uint256 internal constant AUX_RAM_CONSISTENCY_EVALUATION = 0x3700;
    uint256 internal constant AUX_ROM_CONSISTENCY_EVALUATION = 0x3720;
    uint256 internal constant AUX_MEMORY_EVALUATION = 0x3740;

    uint256 internal constant QUOTIENT_EVAL_LOC = 0x3760;
    uint256 internal constant ZERO_POLY_INVERSE_LOC = 0x3780;

    // when hashing public inputs we use memory at NU_CHALLENGE_INPUT_LOC_A, as the hash input size is unknown at compile time
    uint256 internal constant NU_CHALLENGE_INPUT_LOC_A = 0x37a0;
    uint256 internal constant NU_CHALLENGE_INPUT_LOC_B = 0x37c0;
    uint256 internal constant NU_CHALLENGE_INPUT_LOC_C = 0x37e0;

    bytes4 internal constant PUBLIC_INPUT_INVALID_BN128_G1_POINT_SELECTOR = 0xeba9f4a6;
    bytes4 internal constant PUBLIC_INPUT_GE_P_SELECTOR = 0x374a972f;
    bytes4 internal constant MOD_EXP_FAILURE_SELECTOR = 0xf894a7bc;
    bytes4 internal constant EC_SCALAR_MUL_FAILURE_SELECTOR = 0xf755f369;
    bytes4 internal constant PROOF_FAILURE_SELECTOR = 0x0711fcec;

    uint256 internal constant ETA_INPUT_LENGTH = 0xc0; // W1, W2, W3 = 6 * 0x20 bytes

    // We need to hash 41 field elements when generating the NU challenge
    // w1, w2, w3, w4, s, z, z_lookup, q1, q2, q3, q4, qm, qc, qarith (14)
    // qsort, qelliptic, qaux, sigma1, sigma2, sigma, sigma4, (7)
    // table1, table2, table3, table4, tabletype, id1, id2, id3, id4, (9)
    // w1_omega, w2_omega, w3_omega, w4_omega, s_omega, z_omega, z_lookup_omega, (7)
    // table1_omega, table2_omega, table3_omega, table4_omega (4)
    uint256 internal constant NU_INPUT_LENGTH = 0x520; // 0x520 = 41 * 0x20

    // There are ELEVEN G1 group elements added into the transcript in the `beta` round, that we need to skip over
    // W1, W2, W3, W4, S, Z, Z_LOOKUP, T1, T2, T3, T4
    uint256 internal constant NU_CALLDATA_SKIP_LENGTH = 0x2c0; // 11 * 0x40 = 0x2c0

    uint256 internal constant NEGATIVE_INVERSE_OF_2_MODULO_P =
        0x183227397098d014dc2822db40c0ac2e9419f4243cdcb848a1f0fac9f8000000;
    uint256 internal constant LIMB_SIZE = 0x100000000000000000; // 2<<68
    uint256 internal constant SUBLIMB_SHIFT = 0x4000; // 2<<14

    error PUBLIC_INPUTS_HASH_VERIFICATION_FAILED(uint256, uint256);
    error PUBLIC_INPUT_INVALID_BN128_G1_POINT();
    error PUBLIC_INPUT_GE_P();
    error MOD_EXP_FAILURE();
    error EC_SCALAR_MUL_FAILURE();
    error PROOF_FAILURE();

    function getVerificationKeyHash() public pure virtual returns (bytes32);

    function loadVerificationKey(uint256 vk, uint256 _omegaInverseLoc) internal pure virtual;

    /**
     * @notice Verify a Ultra Plonk proof
     * @param _proof - The serialized proof
     * @param _publicInputs - An array of the public inputs
     * @return True if proof is valid, reverts otherwise
     */
    function verify(bytes calldata _proof, bytes32[] calldata _publicInputs) external returns (bool) {
        loadVerificationKey(N_LOC, OMEGA_INVERSE_LOC);

        assembly {
            let q := 21888242871839275222246405745257275088696311157297823662689037894645226208583 // EC group order
            let p := 21888242871839275222246405745257275088548364400416034343698204186575808495617 // Prime field order

            /**
             * LOAD PROOF FROM CALLDATA
             */
            {
                let data_ptr := add(calldataload(0x04), 0x24)

                mstore(W1_Y_LOC, mod(calldataload(data_ptr), q))
                mstore(W1_X_LOC, mod(calldataload(add(data_ptr, 0x20)), q))

                mstore(W2_Y_LOC, mod(calldataload(add(data_ptr, 0x40)), q))
                mstore(W2_X_LOC, mod(calldataload(add(data_ptr, 0x60)), q))

                mstore(W3_Y_LOC, mod(calldataload(add(data_ptr, 0x80)), q))
                mstore(W3_X_LOC, mod(calldataload(add(data_ptr, 0xa0)), q))

                mstore(W4_Y_LOC, mod(calldataload(add(data_ptr, 0xc0)), q))
                mstore(W4_X_LOC, mod(calldataload(add(data_ptr, 0xe0)), q))

                mstore(S_Y_LOC, mod(calldataload(add(data_ptr, 0x100)), q))
                mstore(S_X_LOC, mod(calldataload(add(data_ptr, 0x120)), q))
                mstore(Z_Y_LOC, mod(calldataload(add(data_ptr, 0x140)), q))
                mstore(Z_X_LOC, mod(calldataload(add(data_ptr, 0x160)), q))
                mstore(Z_LOOKUP_Y_LOC, mod(calldataload(add(data_ptr, 0x180)), q))
                mstore(Z_LOOKUP_X_LOC, mod(calldataload(add(data_ptr, 0x1a0)), q))
                mstore(T1_Y_LOC, mod(calldataload(add(data_ptr, 0x1c0)), q))
                mstore(T1_X_LOC, mod(calldataload(add(data_ptr, 0x1e0)), q))

                mstore(T2_Y_LOC, mod(calldataload(add(data_ptr, 0x200)), q))
                mstore(T2_X_LOC, mod(calldataload(add(data_ptr, 0x220)), q))

                mstore(T3_Y_LOC, mod(calldataload(add(data_ptr, 0x240)), q))
                mstore(T3_X_LOC, mod(calldataload(add(data_ptr, 0x260)), q))

                mstore(T4_Y_LOC, mod(calldataload(add(data_ptr, 0x280)), q))
                mstore(T4_X_LOC, mod(calldataload(add(data_ptr, 0x2a0)), q))

                mstore(W1_EVAL_LOC, mod(calldataload(add(data_ptr, 0x2c0)), p))
                mstore(W2_EVAL_LOC, mod(calldataload(add(data_ptr, 0x2e0)), p))
                mstore(W3_EVAL_LOC, mod(calldataload(add(data_ptr, 0x300)), p))
                mstore(W4_EVAL_LOC, mod(calldataload(add(data_ptr, 0x320)), p))
                mstore(S_EVAL_LOC, mod(calldataload(add(data_ptr, 0x340)), p))
                mstore(Z_EVAL_LOC, mod(calldataload(add(data_ptr, 0x360)), p))
                mstore(Z_LOOKUP_EVAL_LOC, mod(calldataload(add(data_ptr, 0x380)), p))
                mstore(Q1_EVAL_LOC, mod(calldataload(add(data_ptr, 0x3a0)), p))
                mstore(Q2_EVAL_LOC, mod(calldataload(add(data_ptr, 0x3c0)), p))
                mstore(Q3_EVAL_LOC, mod(calldataload(add(data_ptr, 0x3e0)), p))
                mstore(Q4_EVAL_LOC, mod(calldataload(add(data_ptr, 0x400)), p))
                mstore(QM_EVAL_LOC, mod(calldataload(add(data_ptr, 0x420)), p))
                mstore(QC_EVAL_LOC, mod(calldataload(add(data_ptr, 0x440)), p))
                mstore(QARITH_EVAL_LOC, mod(calldataload(add(data_ptr, 0x460)), p))
                mstore(QSORT_EVAL_LOC, mod(calldataload(add(data_ptr, 0x480)), p))
                mstore(QELLIPTIC_EVAL_LOC, mod(calldataload(add(data_ptr, 0x4a0)), p))
                mstore(QAUX_EVAL_LOC, mod(calldataload(add(data_ptr, 0x4c0)), p))

                mstore(SIGMA1_EVAL_LOC, mod(calldataload(add(data_ptr, 0x4e0)), p))
                mstore(SIGMA2_EVAL_LOC, mod(calldataload(add(data_ptr, 0x500)), p))

                mstore(SIGMA3_EVAL_LOC, mod(calldataload(add(data_ptr, 0x520)), p))
                mstore(SIGMA4_EVAL_LOC, mod(calldataload(add(data_ptr, 0x540)), p))

                mstore(TABLE1_EVAL_LOC, mod(calldataload(add(data_ptr, 0x560)), p))
                mstore(TABLE2_EVAL_LOC, mod(calldataload(add(data_ptr, 0x580)), p))
                mstore(TABLE3_EVAL_LOC, mod(calldataload(add(data_ptr, 0x5a0)), p))
                mstore(TABLE4_EVAL_LOC, mod(calldataload(add(data_ptr, 0x5c0)), p))
                mstore(TABLE_TYPE_EVAL_LOC, mod(calldataload(add(data_ptr, 0x5e0)), p))

                mstore(ID1_EVAL_LOC, mod(calldataload(add(data_ptr, 0x600)), p))
                mstore(ID2_EVAL_LOC, mod(calldataload(add(data_ptr, 0x620)), p))
                mstore(ID3_EVAL_LOC, mod(calldataload(add(data_ptr, 0x640)), p))
                mstore(ID4_EVAL_LOC, mod(calldataload(add(data_ptr, 0x660)), p))

                mstore(W1_OMEGA_EVAL_LOC, mod(calldataload(add(data_ptr, 0x680)), p))
                mstore(W2_OMEGA_EVAL_LOC, mod(calldataload(add(data_ptr, 0x6a0)), p))
                mstore(W3_OMEGA_EVAL_LOC, mod(calldataload(add(data_ptr, 0x6c0)), p))
                mstore(W4_OMEGA_EVAL_LOC, mod(calldataload(add(data_ptr, 0x6e0)), p))
                mstore(S_OMEGA_EVAL_LOC, mod(calldataload(add(data_ptr, 0x700)), p))

                mstore(Z_OMEGA_EVAL_LOC, mod(calldataload(add(data_ptr, 0x720)), p))

                mstore(Z_LOOKUP_OMEGA_EVAL_LOC, mod(calldataload(add(data_ptr, 0x740)), p))
                mstore(TABLE1_OMEGA_EVAL_LOC, mod(calldataload(add(data_ptr, 0x760)), p))
                mstore(TABLE2_OMEGA_EVAL_LOC, mod(calldataload(add(data_ptr, 0x780)), p))
                mstore(TABLE3_OMEGA_EVAL_LOC, mod(calldataload(add(data_ptr, 0x7a0)), p))
                mstore(TABLE4_OMEGA_EVAL_LOC, mod(calldataload(add(data_ptr, 0x7c0)), p))

                mstore(PI_Z_Y_LOC, mod(calldataload(add(data_ptr, 0x7e0)), q))
                mstore(PI_Z_X_LOC, mod(calldataload(add(data_ptr, 0x800)), q))

                mstore(PI_Z_OMEGA_Y_LOC, mod(calldataload(add(data_ptr, 0x820)), q))
                mstore(PI_Z_OMEGA_X_LOC, mod(calldataload(add(data_ptr, 0x840)), q))
            }

            /**
             * LOAD RECURSIVE PROOF INTO MEMORY
             */
            {
                if mload(CONTAINS_RECURSIVE_PROOF_LOC) {
                    let public_inputs_ptr := add(calldataload(0x24), 0x24)
                    let index_counter := add(shl(5, mload(RECURSIVE_PROOF_PUBLIC_INPUT_INDICES_LOC)), public_inputs_ptr)

                    let x0 := calldataload(index_counter)
                    x0 := add(x0, shl(68, calldataload(add(index_counter, 0x20))))
                    x0 := add(x0, shl(136, calldataload(add(index_counter, 0x40))))
                    x0 := add(x0, shl(204, calldataload(add(index_counter, 0x60))))
                    let y0 := calldataload(add(index_counter, 0x80))
                    y0 := add(y0, shl(68, calldataload(add(index_counter, 0xa0))))
                    y0 := add(y0, shl(136, calldataload(add(index_counter, 0xc0))))
                    y0 := add(y0, shl(204, calldataload(add(index_counter, 0xe0))))
                    let x1 := calldataload(add(index_counter, 0x100))
                    x1 := add(x1, shl(68, calldataload(add(index_counter, 0x120))))
                    x1 := add(x1, shl(136, calldataload(add(index_counter, 0x140))))
                    x1 := add(x1, shl(204, calldataload(add(index_counter, 0x160))))
                    let y1 := calldataload(add(index_counter, 0x180))
                    y1 := add(y1, shl(68, calldataload(add(index_counter, 0x1a0))))
                    y1 := add(y1, shl(136, calldataload(add(index_counter, 0x1c0))))
                    y1 := add(y1, shl(204, calldataload(add(index_counter, 0x1e0))))
                    mstore(RECURSIVE_P1_X_LOC, x0)
                    mstore(RECURSIVE_P1_Y_LOC, y0)
                    mstore(RECURSIVE_P2_X_LOC, x1)
                    mstore(RECURSIVE_P2_Y_LOC, y1)

                    // validate these are valid bn128 G1 points
                    if iszero(and(and(lt(x0, q), lt(x1, q)), and(lt(y0, q), lt(y1, q)))) {
                        mstore(0x00, PUBLIC_INPUT_INVALID_BN128_G1_POINT_SELECTOR)
                        revert(0x00, 0x04)
                    }
                }
            }

            {
                /**
                 * Generate initial challenge
                 */

                mstore(0x00, shl(224, mload(N_LOC)))
                mstore(0x04, shl(224, mload(NUM_INPUTS_LOC)))
                let challenge := keccak256(0x00, 0x08)

                /**
                 * Generate eta challenge
                 */
                mstore(PUBLIC_INPUTS_HASH_LOCATION, challenge)
                // The public input location is stored at 0x24, we then add 0x24 to skip selector and the length of public inputs
                let public_inputs_start := add(calldataload(0x24), 0x24)
                // copy the public inputs over
                let public_input_size := mul(mload(NUM_INPUTS_LOC), 0x20)
                calldatacopy(add(PUBLIC_INPUTS_HASH_LOCATION, 0x20), public_inputs_start, public_input_size)

                // copy W1, W2, W3 into challenge. Each point is 0x40 bytes, so load 0xc0 = 3 * 0x40 bytes (ETA input length)
                let w_start := add(calldataload(0x04), 0x24)
                calldatacopy(add(add(PUBLIC_INPUTS_HASH_LOCATION, 0x20), public_input_size), w_start, ETA_INPUT_LENGTH)

                // Challenge is the old challenge + public inputs + W1, W2, W3 (0x20 + public_input_size + 0xc0)
                let challenge_bytes_size := add(0x20, add(public_input_size, ETA_INPUT_LENGTH))

                challenge := keccak256(PUBLIC_INPUTS_HASH_LOCATION, challenge_bytes_size)
                {
                    let eta := mod(challenge, p)
                    mstore(C_ETA_LOC, eta)
                    mstore(C_ETA_SQR_LOC, mulmod(eta, eta, p))
                    mstore(C_ETA_CUBE_LOC, mulmod(mload(C_ETA_SQR_LOC), eta, p))
                }

                /**
                 * Generate beta, gamma challenges
                 */
                mstore(0x00, challenge)
                mstore(0x20, mload(W4_Y_LOC))
                mstore(0x40, mload(W4_X_LOC))
                mstore(0x60, mload(S_Y_LOC))
                mstore(0x80, mload(S_X_LOC))
                challenge := keccak256(0x00, 0xa0)
                mstore(C_BETA_LOC, mod(challenge, p))

                mstore(0x00, challenge)
                mstore8(0x20, 0x01)
                challenge := keccak256(0x00, 0x21)
                mstore(C_GAMMA_LOC, mod(challenge, p))

                /**
                 * Generate alpha challenge
                 */
                mstore(0x00, challenge)
                mstore(0x20, mload(Z_Y_LOC))
                mstore(0x40, mload(Z_X_LOC))
                mstore(0x60, mload(Z_LOOKUP_Y_LOC))
                mstore(0x80, mload(Z_LOOKUP_X_LOC))
                challenge := keccak256(0x00, 0xa0)
                mstore(C_ALPHA_LOC, mod(challenge, p))

                /**
                 * Compute and store some powers of alpha for future computations
                 */
                {
                    let alpha := mload(C_ALPHA_LOC)
                    mstore(C_ALPHA_SQR_LOC, mulmod(alpha, alpha, p))
                    mstore(C_ALPHA_CUBE_LOC, mulmod(mload(C_ALPHA_SQR_LOC), alpha, p))
                    mstore(C_ALPHA_QUAD_LOC, mulmod(mload(C_ALPHA_CUBE_LOC), alpha, p))

                    mstore(C_ALPHA_BASE_LOC, alpha)
                }
                /**
                 * Generate zeta challenge
                 */
                mstore(0x00, challenge)
                mstore(0x20, mload(T1_Y_LOC))
                mstore(0x40, mload(T1_X_LOC))
                mstore(0x60, mload(T2_Y_LOC))
                mstore(0x80, mload(T2_X_LOC))
                mstore(0xa0, mload(T3_Y_LOC))
                mstore(0xc0, mload(T3_X_LOC))
                mstore(0xe0, mload(T4_Y_LOC))
                mstore(0x100, mload(T4_X_LOC))

                challenge := keccak256(0x00, 0x120)

                mstore(C_ZETA_LOC, mod(challenge, p))
                mstore(C_CURRENT_LOC, challenge)
            }

            /**
             * EVALUATE FIELD OPERATIONS
             */

            /**
             * COMPUTE PUBLIC INPUT DELTA
             */
            {
                let gamma := mload(C_GAMMA_LOC)
                let work_root := mload(OMEGA_LOC)
                let endpoint := sub(mul(mload(NUM_INPUTS_LOC), 0x20), 0x20)
                let public_inputs
                let root_1 := mload(C_BETA_LOC)
                let root_2 := root_1
                let numerator_value := 1
                let denominator_value := 1

                let p_clone := p // move p to the front of the stack
                let valid := true

                root_1 := mulmod(root_1, 0x05, p_clone) // k1.beta
                root_2 := mulmod(root_2, 0x07, p_clone) // 0x05 + 0x07 = 0x0c = external coset generator

                public_inputs := add(calldataload(0x24), 0x24)
                endpoint := add(endpoint, public_inputs)

                for {} lt(public_inputs, endpoint) {} {
                    let input0 := calldataload(public_inputs)
                    let N0 := add(root_1, add(input0, gamma))
                    let D0 := add(root_2, N0) // 4x overloaded

                    root_1 := mulmod(root_1, work_root, p_clone)
                    root_2 := mulmod(root_2, work_root, p_clone)

                    let input1 := calldataload(add(public_inputs, 0x20))
                    let N1 := add(root_1, add(input1, gamma))

                    denominator_value := mulmod(mulmod(D0, denominator_value, p_clone), add(N1, root_2), p_clone)
                    numerator_value := mulmod(mulmod(N1, N0, p_clone), numerator_value, p_clone)

                    root_1 := mulmod(root_1, work_root, p_clone)
                    root_2 := mulmod(root_2, work_root, p_clone)

                    valid := and(valid, and(lt(input0, p_clone), lt(input1, p_clone)))
                    public_inputs := add(public_inputs, 0x40)

                    // validate public inputs are field elements (i.e. < p)
                    if iszero(and(lt(input0, p_clone), lt(input1, p_clone))) {
                        mstore(0x00, PUBLIC_INPUT_GE_P_SELECTOR)
                        revert(0x00, 0x04)
                    }
                }

                endpoint := add(endpoint, 0x20)
                for {} lt(public_inputs, endpoint) { public_inputs := add(public_inputs, 0x20) } {
                    let input0 := calldataload(public_inputs)

                    // validate public inputs are field elements (i.e. < p)
                    if iszero(lt(input0, p_clone)) {
                        mstore(0x00, PUBLIC_INPUT_GE_P_SELECTOR)
                        revert(0x00, 0x04)
                    }

                    valid := and(valid, lt(input0, p_clone))
                    let T0 := addmod(input0, gamma, p_clone)
                    numerator_value :=
                        mulmod(
                            numerator_value,
                            add(root_1, T0), // 0x05 = coset_generator0
                            p_clone
                        )
                    denominator_value :=
                        mulmod(
                            denominator_value,
                            add(add(root_1, root_2), T0), // 0x0c = coset_generator7
                            p_clone
                        )
                    root_1 := mulmod(root_1, work_root, p_clone)
                    root_2 := mulmod(root_2, work_root, p_clone)
                }

                mstore(DELTA_NUMERATOR_LOC, numerator_value)
                mstore(DELTA_DENOMINATOR_LOC, denominator_value)
            }

            /**
             * Compute Plookup delta factor [γ(1 + β)]^{n-k}
             * k = num roots cut out of Z_H = 4
             */
            {
                let delta_base := mulmod(mload(C_GAMMA_LOC), addmod(mload(C_BETA_LOC), 1, p), p)
                let delta_numerator := delta_base
                {
                    let exponent := mload(N_LOC)
                    let count := 1
                    for {} lt(count, exponent) { count := add(count, count) } {
                        delta_numerator := mulmod(delta_numerator, delta_numerator, p)
                    }
                }
                mstore(PLOOKUP_DELTA_NUMERATOR_LOC, delta_numerator)

                let delta_denominator := mulmod(delta_base, delta_base, p)
                delta_denominator := mulmod(delta_denominator, delta_denominator, p)
                mstore(PLOOKUP_DELTA_DENOMINATOR_LOC, delta_denominator)
            }
            /**
             * Compute lagrange poly and vanishing poly fractions
             */
            {
                let zeta := mload(C_ZETA_LOC)

                // compute zeta^n, where n is a power of 2
                let vanishing_numerator := zeta
                {
                    // pow_small
                    let exponent := mload(N_LOC)
                    let count := 1
                    for {} lt(count, exponent) { count := add(count, count) } {
                        vanishing_numerator := mulmod(vanishing_numerator, vanishing_numerator, p)
                    }
                }
                mstore(ZETA_POW_N_LOC, vanishing_numerator)
                vanishing_numerator := addmod(vanishing_numerator, sub(p, 1), p)

                let accumulating_root := mload(OMEGA_INVERSE_LOC)
                let work_root := sub(p, accumulating_root)
                let domain_inverse := mload(DOMAIN_INVERSE_LOC)

                let vanishing_denominator := addmod(zeta, work_root, p)
                work_root := mulmod(work_root, accumulating_root, p)
                vanishing_denominator := mulmod(vanishing_denominator, addmod(zeta, work_root, p), p)
                work_root := mulmod(work_root, accumulating_root, p)
                vanishing_denominator := mulmod(vanishing_denominator, addmod(zeta, work_root, p), p)
                vanishing_denominator :=
                    mulmod(vanishing_denominator, addmod(zeta, mulmod(work_root, accumulating_root, p), p), p)

                work_root := mload(OMEGA_LOC)

                let lagrange_numerator := mulmod(vanishing_numerator, domain_inverse, p)
                let l_start_denominator := addmod(zeta, sub(p, 1), p)

                // l_end_denominator term contains a term \omega^5 to cut out 5 roots of unity from vanishing poly
                accumulating_root := mulmod(work_root, work_root, p)

                let l_end_denominator :=
                    addmod(
                        mulmod(mulmod(mulmod(accumulating_root, accumulating_root, p), work_root, p), zeta, p), sub(p, 1), p
                    )

                /**
                 * Compute inversions using Montgomery's batch inversion trick
                 */
                let accumulator := mload(DELTA_DENOMINATOR_LOC)
                let t0 := accumulator
                accumulator := mulmod(accumulator, vanishing_denominator, p)
                let t1 := accumulator
                accumulator := mulmod(accumulator, vanishing_numerator, p)
                let t2 := accumulator
                accumulator := mulmod(accumulator, l_start_denominator, p)
                let t3 := accumulator
                accumulator := mulmod(accumulator, mload(PLOOKUP_DELTA_DENOMINATOR_LOC), p)
                let t4 := accumulator
                {
                    mstore(0, 0x20)
                    mstore(0x20, 0x20)
                    mstore(0x40, 0x20)
                    mstore(0x60, mulmod(accumulator, l_end_denominator, p))
                    mstore(0x80, sub(p, 2))
                    mstore(0xa0, p)
                    if iszero(staticcall(gas(), 0x05, 0x00, 0xc0, 0x00, 0x20)) {
                        mstore(0x0, MOD_EXP_FAILURE_SELECTOR)
                        revert(0x00, 0x04)
                    }
                    accumulator := mload(0x00)
                }

                t4 := mulmod(accumulator, t4, p)
                accumulator := mulmod(accumulator, l_end_denominator, p)

                t3 := mulmod(accumulator, t3, p)
                accumulator := mulmod(accumulator, mload(PLOOKUP_DELTA_DENOMINATOR_LOC), p)

                t2 := mulmod(accumulator, t2, p)
                accumulator := mulmod(accumulator, l_start_denominator, p)

                t1 := mulmod(accumulator, t1, p)
                accumulator := mulmod(accumulator, vanishing_numerator, p)

                t0 := mulmod(accumulator, t0, p)
                accumulator := mulmod(accumulator, vanishing_denominator, p)

                accumulator := mulmod(mulmod(accumulator, accumulator, p), mload(DELTA_DENOMINATOR_LOC), p)

                mstore(PUBLIC_INPUT_DELTA_LOC, mulmod(mload(DELTA_NUMERATOR_LOC), accumulator, p))
                mstore(ZERO_POLY_LOC, mulmod(vanishing_numerator, t0, p))
                mstore(ZERO_POLY_INVERSE_LOC, mulmod(vanishing_denominator, t1, p))
                mstore(L_START_LOC, mulmod(lagrange_numerator, t2, p))
                mstore(PLOOKUP_DELTA_LOC, mulmod(mload(PLOOKUP_DELTA_NUMERATOR_LOC), t3, p))
                mstore(L_END_LOC, mulmod(lagrange_numerator, t4, p))
            }

            /**
             * UltraPlonk Widget Ordering:
             *
             * 1. Permutation widget
             * 2. Plookup widget
             * 3. Arithmetic widget
             * 4. Fixed base widget (?)
             * 5. GenPermSort widget
             * 6. Elliptic widget
             * 7. Auxiliary widget
             */

            /**
             * COMPUTE PERMUTATION WIDGET EVALUATION
             */
            {
                let alpha := mload(C_ALPHA_LOC)
                let beta := mload(C_BETA_LOC)
                let gamma := mload(C_GAMMA_LOC)

                let result := 0
                let t1 :=
                    mulmod(
                        add(add(mload(W1_EVAL_LOC), gamma), mulmod(beta, mload(ID1_EVAL_LOC), p)),
                        add(add(mload(W2_EVAL_LOC), gamma), mulmod(beta, mload(ID2_EVAL_LOC), p)),
                        p
                    )

                result :=
                    addmod(
                        mulmod(
                            mload(C_ALPHA_BASE_LOC),
                            mulmod(
                                mload(Z_EVAL_LOC),
                                mulmod(
                                    t1,
                                    mulmod(
                                        add(add(mload(W3_EVAL_LOC), gamma), mulmod(beta, mload(ID3_EVAL_LOC), p)),
                                        add(add(mload(W4_EVAL_LOC), gamma), mulmod(beta, mload(ID4_EVAL_LOC), p)),
                                        p
                                    ),
                                    p
                                ),
                                p
                            ),
                            p
                        ),
                        sub(
                            p,
                            mulmod(
                                mload(C_ALPHA_BASE_LOC),
                                mulmod(
                                    mload(Z_OMEGA_EVAL_LOC),
                                    mulmod(
                                        mulmod(
                                            add(add(mload(W1_EVAL_LOC), gamma), mulmod(beta, mload(SIGMA1_EVAL_LOC), p)),
                                            add(add(mload(W2_EVAL_LOC), gamma), mulmod(beta, mload(SIGMA2_EVAL_LOC), p)),
                                            p
                                        ),
                                        mulmod(
                                            add(add(mload(W3_EVAL_LOC), gamma), mulmod(beta, mload(SIGMA3_EVAL_LOC), p)),
                                            add(add(mload(W4_EVAL_LOC), gamma), mulmod(beta, mload(SIGMA4_EVAL_LOC), p)),
                                            p
                                        ),
                                        p
                                    ),
                                    p
                                ),
                                p
                            )
                        ),
                        p
                    )

                // update alpha
                mstore(C_ALPHA_BASE_LOC, mulmod(mload(C_ALPHA_BASE_LOC), mload(C_ALPHA_LOC), p))

                // Validate final grand-product equals public input delta
                // L_{n-k}(ʓ).(z(ʓ.ω) - ∆_{PI})
                result :=
                    addmod(
                        result,
                        mulmod(
                            mload(C_ALPHA_BASE_LOC),
                            mulmod(
                                mload(L_END_LOC),
                                addmod(mload(Z_OMEGA_EVAL_LOC), sub(p, mload(PUBLIC_INPUT_DELTA_LOC)), p),
                                p
                            ),
                            p
                        ),
                        p
                    )

                // update alpha
                mstore(C_ALPHA_BASE_LOC, mulmod(mload(C_ALPHA_BASE_LOC), mload(C_ALPHA_LOC), p))

                // L_1(ʓ)(Z(ʓ) - 1)
                mstore(
                    PERMUTATION_IDENTITY,
                    addmod(
                        result,
                        mulmod(
                            mload(C_ALPHA_BASE_LOC),
                            mulmod(mload(L_START_LOC), addmod(mload(Z_EVAL_LOC), sub(p, 1), p), p),
                            p
                        ),
                        p
                    )
                )

                // update alpha
                mstore(C_ALPHA_BASE_LOC, mulmod(mload(C_ALPHA_BASE_LOC), mload(C_ALPHA_LOC), p))
            }

            /**
             * COMPUTE PLOOKUP WIDGET EVALUATION
             */
            {
                let result := 0
                let f := 0
                let t := 0
                let t_omega := 0
                let numerator := 0
                let denominator := 0
                let gamma_beta_constant := mulmod(mload(C_GAMMA_LOC), addmod(mload(C_BETA_LOC), 1, p), p)
                {
                    // f(z) := (w1(z) + q2.w1(zω)) + η(w2(z) + qm.w2(zω)) + η²(w3(z) + qc.w_3(zω)) + q3(z).η³
                    f := addmod(mload(W1_EVAL_LOC), mulmod(mload(Q2_EVAL_LOC), mload(W1_OMEGA_EVAL_LOC), p), p)

                    let t1 := addmod(mload(W2_EVAL_LOC), mulmod(mload(QM_EVAL_LOC), mload(W2_OMEGA_EVAL_LOC), p), p)
                    f := addmod(f, mulmod(t1, mload(C_ETA_LOC), p), p)

                    t1 := addmod(mload(W3_EVAL_LOC), mulmod(mload(QC_EVAL_LOC), mload(W3_OMEGA_EVAL_LOC), p), p)
                    f :=
                        addmod(
                            addmod(f, mulmod(t1, mload(C_ETA_SQR_LOC), p), p),
                            mulmod(mload(Q3_EVAL_LOC), mload(C_ETA_CUBE_LOC), p),
                            p
                        )
                }

                {
                    // t(z) = table4(z).η³ + table3(z).η² + table2(z).η + table1(z)
                    t :=
                        addmod(
                            addmod(
                                addmod(
                                    mulmod(mload(TABLE4_EVAL_LOC), mload(C_ETA_CUBE_LOC), p),
                                    mulmod(mload(TABLE3_EVAL_LOC), mload(C_ETA_SQR_LOC), p),
                                    p
                                ),
                                mulmod(mload(TABLE2_EVAL_LOC), mload(C_ETA_LOC), p),
                                p
                            ),
                            mload(TABLE1_EVAL_LOC),
                            p
                        )
                    // t := addmod(
                    //     t,
                    //     mulmod(
                    //         mload(TABLE3_EVAL_LOC),
                    //         mload(C_ETA_SQR_LOC),
                    //         p
                    //     ),
                    //     p
                    // )
                    // t := addmod(
                    //     t,
                    //     mulmod(
                    //         mload(TABLE2_EVAL_LOC),
                    //         mload(C_ETA_LOC),
                    //         p
                    //     ),
                    //     p
                    // )
                    // t := addmod(t, mload(TABLE1_EVAL_LOC), p)

                    // t(zw) = table4(zw).η³ + table3(zw).η² + table2(zw).η + table1(zw)
                    t_omega :=
                        addmod(
                            addmod(
                                addmod(
                                    mulmod(mload(TABLE4_OMEGA_EVAL_LOC), mload(C_ETA_CUBE_LOC), p),
                                    mulmod(mload(TABLE3_OMEGA_EVAL_LOC), mload(C_ETA_SQR_LOC), p),
                                    p
                                ),
                                mulmod(mload(TABLE2_OMEGA_EVAL_LOC), mload(C_ETA_LOC), p),
                                p
                            ),
                            mload(TABLE1_OMEGA_EVAL_LOC),
                            p
                        )
                }

                // Set numerator = (q_index*f(z) + γ) * (t(z) + βt(zω) + γ(β + 1)) * (β + 1)
                numerator :=
                    mulmod(
                        mulmod(
                            addmod(mulmod(f, mload(TABLE_TYPE_EVAL_LOC), p), mload(C_GAMMA_LOC), p),
                            addmod(mulmod(t_omega, mload(C_BETA_LOC), p), addmod(gamma_beta_constant, t, p), p),
                            p
                        ),
                        addmod(mload(C_BETA_LOC), 1, p),
                        p
                    )

                {
                    let t0 := mulmod(mload(C_ALPHA_LOC), mload(L_START_LOC), p)
                    let t1 := mulmod(mload(C_ALPHA_SQR_LOC), mload(L_END_LOC), p)

                    numerator := addmod(mulmod(addmod(numerator, t0, p), mload(Z_LOOKUP_EVAL_LOC), p), sub(p, t0), p)

                    // Set denominator = s(z) + βs(zω) + γ(β + 1)
                    // plookup delta = [γ(1 + β)]^{n-k}
                    denominator :=
                        addmod(
                            mulmod(t1, mload(PLOOKUP_DELTA_LOC), p),
                            mulmod(
                                addmod(
                                    addmod(
                                        addmod(mload(S_EVAL_LOC), mulmod(mload(S_OMEGA_EVAL_LOC), mload(C_BETA_LOC), p), p),
                                        gamma_beta_constant,
                                        p
                                    ),
                                    sub(p, t1),
                                    p
                                ),
                                mload(Z_LOOKUP_OMEGA_EVAL_LOC),
                                p
                            ),
                            p
                        )

                    mstore(
                        PLOOKUP_IDENTITY, mulmod(addmod(numerator, sub(p, denominator), p), mload(C_ALPHA_BASE_LOC), p)
                    )

                    // update alpha
                    mstore(C_ALPHA_BASE_LOC, mulmod(mload(C_ALPHA_BASE_LOC), mload(C_ALPHA_CUBE_LOC), p))
                }
            }

            /**
             * COMPUTE ARITHMETIC WIDGET EVALUATION
             */
            {
                // basic arithmetic gate identity
                // (w_1 . w_2 . q_m) + (w_1 . q_1) + (w_2 . q_2) + (w_3 . q_3) + (w_4 . q_4) + q_c = 0
                // q_m is turned off if q_arith == 3

                let identity :=
                    addmod(
                        mload(QC_EVAL_LOC),
                        addmod(
                            mulmod(mload(W4_EVAL_LOC), mload(Q4_EVAL_LOC), p),
                            addmod(
                                mulmod(mload(W3_EVAL_LOC), mload(Q3_EVAL_LOC), p),
                                addmod(
                                    mulmod(mload(W2_EVAL_LOC), mload(Q2_EVAL_LOC), p),
                                    mulmod(
                                        addmod(
                                            mulmod(
                                                mulmod(
                                                    mulmod(mload(W2_EVAL_LOC), mload(QM_EVAL_LOC), p),
                                                    addmod(mload(QARITH_EVAL_LOC), sub(p, 3), p),
                                                    p
                                                ),
                                                NEGATIVE_INVERSE_OF_2_MODULO_P,
                                                p
                                            ),
                                            mload(Q1_EVAL_LOC),
                                            p
                                        ),
                                        mload(W1_EVAL_LOC),
                                        p
                                    ),
                                    p
                                ),
                                p
                            ),
                            p
                        ),
                        p
                    )

                // if q_arith == 3 we evaluate an additional mini addition gate (on top of the regular one), where:
                //   w_1 + w_4 - w_1_omega + q_m = 0
                // we use this gate to save an addition gate when adding or subtracting non-native field elements
                let extra_small_addition_gate_identity :=
                    mulmod(
                        addmod(mload(QARITH_EVAL_LOC), sub(p, 2), p),
                        mulmod(
                            mload(C_ALPHA_LOC),
                            addmod(
                                mload(QM_EVAL_LOC),
                                addmod(
                                    sub(p, mload(W1_OMEGA_EVAL_LOC)), addmod(mload(W1_EVAL_LOC), mload(W4_EVAL_LOC), p), p
                                ),
                                p
                            ),
                            p
                        ),
                        p
                    )

                // if q_arith == 2 OR q_arith == 3 we add the 4th wire of the NEXT gate into the arithmetic identity
                // N.B. if q_arith > 2, this wire value will be scaled by (q_arith - 1) relative to the other gate wires!
                mstore(
                    ARITHMETIC_IDENTITY,
                    mulmod(
                        mload(C_ALPHA_BASE_LOC),
                        mulmod(
                            mload(QARITH_EVAL_LOC),
                            addmod(
                                identity,
                                mulmod(
                                    addmod(mload(QARITH_EVAL_LOC), sub(p, 1), p),
                                    addmod(mload(W4_OMEGA_EVAL_LOC), extra_small_addition_gate_identity, p),
                                    p
                                ),
                                p
                            ),
                            p
                        ),
                        p
                    )
                )

                // update alpha
                mstore(C_ALPHA_BASE_LOC, mulmod(mload(C_ALPHA_BASE_LOC), mload(C_ALPHA_SQR_LOC), p))
            }

            /**
             * COMPUTE GENPERMSORT WIDGET EVALUATION
             */
            {
                /**
                 * D1 = (w2 - w1)
                 * D2 = (w3 - w2)
                 * D3 = (w4 - w3)
                 * D4 = (w1_omega - w4)
                 * (
                 * D1(D1 - 1)(D1 - 2)(D1 - 3).α +
                 * D1(D1 - 1)(D1 - 2)(D1 - 3).α^2 +
                 * D1(D1 - 1)(D1 - 2)(D1 - 3).α^3 +
                 * D1(D1 - 1)(D1 - 2)(D1 - 3).α^4 +
                 * ) . q_sort
                 */
                let d1 := addmod(mload(W1_OMEGA_EVAL_LOC), sub(p, mload(W4_EVAL_LOC)), p)
                let d2 := addmod(mload(W4_EVAL_LOC), sub(p, mload(W3_EVAL_LOC)), p)
                let d3 := addmod(mload(W3_EVAL_LOC), sub(p, mload(W2_EVAL_LOC)), p)
                let d4 := addmod(mload(W2_EVAL_LOC), sub(p, mload(W1_EVAL_LOC)), p)
                let minus_two := sub(p, 2)
                let minus_three := sub(p, 3)
                // t0 = D(D - 1)
                let range_accumulator :=
                    mulmod(
                        mulmod(
                            mulmod(addmod(mulmod(d1, d1, p), sub(p, d1), p), addmod(d1, minus_two, p), p),
                            addmod(d1, minus_three, p),
                            p
                        ),
                        mulmod(mload(C_ALPHA_BASE_LOC), mload(C_ALPHA_CUBE_LOC), p),
                        p
                    )

                // t0 = D(D - 1)
                range_accumulator :=
                    addmod(
                        range_accumulator,
                        mulmod(
                            mulmod(
                                mulmod(addmod(mulmod(d2, d2, p), sub(p, d2), p), addmod(d2, minus_two, p), p),
                                addmod(d2, minus_three, p),
                                p
                            ),
                            mulmod(mload(C_ALPHA_BASE_LOC), mload(C_ALPHA_SQR_LOC), p),
                            p
                        ),
                        p
                    )

                // t0 = D(D - 1)
                range_accumulator :=
                    addmod(
                        range_accumulator,
                        mulmod(
                            mulmod(
                                mulmod(addmod(mulmod(d3, d3, p), sub(p, d3), p), addmod(d3, minus_two, p), p),
                                addmod(d3, minus_three, p),
                                p
                            ),
                            mulmod(mload(C_ALPHA_BASE_LOC), mload(C_ALPHA_LOC), p),
                            p
                        ),
                        p
                    )

                range_accumulator :=
                    addmod(
                        range_accumulator,
                        mulmod(
                            mulmod(
                                mulmod(addmod(mulmod(d4, d4, p), sub(p, d4), p), addmod(d4, minus_two, p), p),
                                addmod(d4, minus_three, p),
                                p
                            ),
                            mload(C_ALPHA_BASE_LOC),
                            p
                        ),
                        p
                    )

                range_accumulator := mulmod(range_accumulator, mload(QSORT_EVAL_LOC), p)

                mstore(SORT_IDENTITY, range_accumulator)

                // update alpha
                mstore(C_ALPHA_BASE_LOC, mulmod(mload(C_ALPHA_BASE_LOC), mload(C_ALPHA_QUAD_LOC), p))
            }

            /**
             * COMPUTE ELLIPTIC WIDGET EVALUATION
             */
            {
                let endo_term := mulmod(sub(p, mload(X2_EVAL_LOC)), mload(X1_EVAL_LOC), p)
                endo_term :=
                    mulmod(
                        mulmod(
                            endo_term, addmod(addmod(mload(X3_EVAL_LOC), mload(X3_EVAL_LOC), p), mload(X1_EVAL_LOC), p), p
                        ),
                        mload(QBETA_LOC),
                        p
                    )

                let endo_sqr_term := mulmod(mload(X2_EVAL_LOC), mload(X2_EVAL_LOC), p)

                let leftovers := endo_sqr_term

                endo_sqr_term :=
                    mulmod(
                        mulmod(endo_sqr_term, addmod(mload(X3_EVAL_LOC), sub(p, mload(X1_EVAL_LOC)), p), p),
                        mload(QBETA_SQR_LOC),
                        p
                    )

                let sign_term := mulmod(mulmod(mload(Y2_EVAL_LOC), mload(Y1_EVAL_LOC), p), mload(QSIGN_LOC), p)

                leftovers :=
                    addmod(
                        addmod(
                            mulmod(leftovers, mload(X2_EVAL_LOC), p),
                            mulmod(
                                mulmod(mload(X1_EVAL_LOC), mload(X1_EVAL_LOC), p),
                                addmod(mload(X3_EVAL_LOC), mload(X1_EVAL_LOC), p),
                                p
                            ),
                            p
                        ),
                        sub(
                            p,
                            addmod(
                                mulmod(mload(Y2_EVAL_LOC), mload(Y2_EVAL_LOC), p),
                                mulmod(mload(Y1_EVAL_LOC), mload(Y1_EVAL_LOC), p),
                                p
                            )
                        ),
                        p
                    )

                let x_identity :=
                    mulmod(
                        addmod(
                            addmod(endo_term, endo_sqr_term, p), addmod(addmod(sign_term, sign_term, p), leftovers, p), p
                        ),
                        mload(C_ALPHA_BASE_LOC),
                        p
                    )

                endo_term :=
                    mulmod(
                        mulmod(mload(X2_EVAL_LOC), mload(QBETA_LOC), p),
                        addmod(mload(Y3_EVAL_LOC), mload(Y1_EVAL_LOC), p),
                        p
                    )

                sign_term :=
                    sub(
                        p,
                        mulmod(
                            mulmod(mload(Y2_EVAL_LOC), mload(QSIGN_LOC), p),
                            addmod(mload(X1_EVAL_LOC), sub(p, mload(X3_EVAL_LOC)), p),
                            p
                        )
                    )

                leftovers :=
                    addmod(
                        sub(p, mulmod(mload(X1_EVAL_LOC), addmod(mload(Y3_EVAL_LOC), mload(Y1_EVAL_LOC), p), p)),
                        mulmod(mload(Y1_EVAL_LOC), addmod(mload(X1_EVAL_LOC), sub(p, mload(X3_EVAL_LOC)), p), p),
                        p
                    )

                let y_identity :=
                    mulmod(
                        addmod(addmod(endo_term, sign_term, p), leftovers, p),
                        mulmod(mload(C_ALPHA_BASE_LOC), mload(C_ALPHA_LOC), p),
                        p
                    )

                mstore(ELLIPTIC_IDENTITY, mulmod(addmod(x_identity, y_identity, p), mload(QELLIPTIC_EVAL_LOC), p))

                // update alpha
                // The paper says to use ALPHA^2, we use ALPHA^4 this is a small oversight in the prover protocol
                mstore(C_ALPHA_BASE_LOC, mulmod(mload(C_ALPHA_BASE_LOC), mload(C_ALPHA_QUAD_LOC), p))
            }

            /**
             * COMPUTE AUXILIARY WIDGET EVALUATION
             */
            {
                {
                    // non native field arithmetic gate 2
                    let limb_subproduct :=
                        addmod(
                            mulmod(mload(W1_EVAL_LOC), mload(W2_OMEGA_EVAL_LOC), p),
                            mulmod(mload(W1_OMEGA_EVAL_LOC), mload(W2_EVAL_LOC), p),
                            p
                        )

                    let non_native_field_gate_2 :=
                        addmod(
                            addmod(
                                mulmod(mload(W1_EVAL_LOC), mload(W4_EVAL_LOC), p),
                                mulmod(mload(W2_EVAL_LOC), mload(W3_EVAL_LOC), p),
                                p
                            ),
                            sub(p, mload(W3_OMEGA_EVAL_LOC)),
                            p
                        )
                    non_native_field_gate_2 :=
                        mulmod(
                            addmod(
                                addmod(mulmod(non_native_field_gate_2, LIMB_SIZE, p), sub(p, mload(W4_OMEGA_EVAL_LOC)), p),
                                limb_subproduct,
                                p
                            ),
                            mload(Q4_EVAL_LOC),
                            p
                        )

                    limb_subproduct :=
                        addmod(
                            mulmod(limb_subproduct, LIMB_SIZE, p),
                            mulmod(mload(W1_OMEGA_EVAL_LOC), mload(W2_OMEGA_EVAL_LOC), p),
                            p
                        )

                    let non_native_field_gate_1 :=
                        mulmod(
                            addmod(limb_subproduct, sub(p, addmod(mload(W3_EVAL_LOC), mload(W4_EVAL_LOC), p)), p),
                            mload(Q3_EVAL_LOC),
                            p
                        )

                    let non_native_field_gate_3 :=
                        mulmod(
                            addmod(
                                addmod(limb_subproduct, mload(W4_EVAL_LOC), p),
                                sub(p, addmod(mload(W3_OMEGA_EVAL_LOC), mload(W4_OMEGA_EVAL_LOC), p)),
                                p
                            ),
                            mload(QM_EVAL_LOC),
                            p
                        )

                    let non_native_field_identity :=
                        mulmod(
                            addmod(addmod(non_native_field_gate_1, non_native_field_gate_2, p), non_native_field_gate_3, p),
                            mload(Q2_EVAL_LOC),
                            p
                        )

                    mstore(AUX_NON_NATIVE_FIELD_EVALUATION, non_native_field_identity)
                }

                {
                    let limb_accumulator_1 :=
                        addmod(
                            mulmod(
                                addmod(
                                    mulmod(
                                        addmod(
                                            mulmod(
                                                addmod(
                                                    mulmod(mload(W2_OMEGA_EVAL_LOC), SUBLIMB_SHIFT, p),
                                                    mload(W1_OMEGA_EVAL_LOC),
                                                    p
                                                ),
                                                SUBLIMB_SHIFT,
                                                p
                                            ),
                                            mload(W3_EVAL_LOC),
                                            p
                                        ),
                                        SUBLIMB_SHIFT,
                                        p
                                    ),
                                    mload(W2_EVAL_LOC),
                                    p
                                ),
                                SUBLIMB_SHIFT,
                                p
                            ),
                            mload(W1_EVAL_LOC),
                            p
                        )

                    limb_accumulator_1 :=
                        mulmod(addmod(limb_accumulator_1, sub(p, mload(W4_EVAL_LOC)), p), mload(Q4_EVAL_LOC), p)

                    let limb_accumulator_2 :=
                        addmod(
                            mulmod(
                                addmod(
                                    mulmod(
                                        addmod(
                                            mulmod(
                                                addmod(
                                                    mulmod(mload(W3_OMEGA_EVAL_LOC), SUBLIMB_SHIFT, p),
                                                    mload(W2_OMEGA_EVAL_LOC),
                                                    p
                                                ),
                                                SUBLIMB_SHIFT,
                                                p
                                            ),
                                            mload(W1_OMEGA_EVAL_LOC),
                                            p
                                        ),
                                        SUBLIMB_SHIFT,
                                        p
                                    ),
                                    mload(W4_EVAL_LOC),
                                    p
                                ),
                                SUBLIMB_SHIFT,
                                p
                            ),
                            mload(W3_EVAL_LOC),
                            p
                        )

                    limb_accumulator_2 :=
                        mulmod(addmod(limb_accumulator_2, sub(p, mload(W4_OMEGA_EVAL_LOC)), p), mload(QM_EVAL_LOC), p)

                    mstore(
                        AUX_LIMB_ACCUMULATOR_EVALUATION,
                        mulmod(addmod(limb_accumulator_1, limb_accumulator_2, p), mload(Q3_EVAL_LOC), p)
                    )
                }

                {
                    let memory_record_check :=
                        addmod(
                            mulmod(
                                addmod(
                                    mulmod(
                                        addmod(mulmod(mload(W3_EVAL_LOC), mload(C_ETA_LOC), p), mload(W2_EVAL_LOC), p),
                                        mload(C_ETA_LOC),
                                        p
                                    ),
                                    mload(W1_EVAL_LOC),
                                    p
                                ),
                                mload(C_ETA_LOC),
                                p
                            ),
                            mload(QC_EVAL_LOC),
                            p
                        )

                    let partial_record_check := memory_record_check

                    memory_record_check := addmod(memory_record_check, sub(p, mload(W4_EVAL_LOC)), p)

                    mstore(AUX_MEMORY_EVALUATION, memory_record_check)

                    let index_delta := addmod(mload(W1_OMEGA_EVAL_LOC), sub(p, mload(W1_EVAL_LOC)), p)

                    let record_delta := addmod(mload(W4_OMEGA_EVAL_LOC), sub(p, mload(W4_EVAL_LOC)), p)

                    let index_is_monotonically_increasing := mulmod(index_delta, addmod(index_delta, sub(p, 1), p), p)

                    let adjacent_values_match_if_adjacent_indices_match :=
                        mulmod(record_delta, addmod(1, sub(p, index_delta), p), p)

                    mstore(
                        AUX_ROM_CONSISTENCY_EVALUATION,
                        addmod(
                            mulmod(
                                addmod(
                                    mulmod(adjacent_values_match_if_adjacent_indices_match, mload(C_ALPHA_LOC), p),
                                    index_is_monotonically_increasing,
                                    p
                                ),
                                mload(C_ALPHA_LOC),
                                p
                            ),
                            memory_record_check,
                            p
                        )
                    )

                    {
                        let access_type := addmod(mload(W4_EVAL_LOC), sub(p, partial_record_check), p)

                        let next_gate_access_type :=
                            addmod(
                                sub(
                                    p,
                                    mulmod(
                                        addmod(
                                            mulmod(
                                                addmod(
                                                    mulmod(mload(W3_OMEGA_EVAL_LOC), mload(C_ETA_LOC), p),
                                                    mload(W2_OMEGA_EVAL_LOC),
                                                    p
                                                ),
                                                mload(C_ETA_LOC),
                                                p
                                            ),
                                            mload(W1_OMEGA_EVAL_LOC),
                                            p
                                        ),
                                        mload(C_ETA_LOC),
                                        p
                                    )
                                ),
                                mload(W4_OMEGA_EVAL_LOC),
                                p
                            )

                        let adjacent_values_match_if_adjacent_indices_match_and_next_access_is_a_read_operation :=
                            mulmod(
                                addmod(mload(W3_OMEGA_EVAL_LOC), sub(p, mload(W3_EVAL_LOC)), p),
                                mulmod(addmod(1, sub(p, index_delta), p), addmod(1, sub(p, next_gate_access_type), p), p),
                                p
                            )

                        mstore(
                            AUX_RAM_CONSISTENCY_EVALUATION,
                            addmod(
                                mulmod(access_type, addmod(access_type, sub(p, 1), p), p),
                                mulmod(
                                    addmod(
                                        mulmod(
                                            addmod(
                                                mulmod(
                                                    adjacent_values_match_if_adjacent_indices_match_and_next_access_is_a_read_operation,
                                                    mload(C_ALPHA_LOC),
                                                    p
                                                ),
                                                index_is_monotonically_increasing,
                                                p
                                            ),
                                            mload(C_ALPHA_LOC),
                                            p
                                        ),
                                        mulmod(next_gate_access_type, addmod(next_gate_access_type, sub(p, 1), p), p),
                                        p
                                    ),
                                    mload(C_ALPHA_LOC),
                                    p
                                ),
                                p
                            )
                        )
                    }

                    {
                        let timestamp_delta := addmod(mload(W2_OMEGA_EVAL_LOC), sub(p, mload(W2_EVAL_LOC)), p)

                        let RAM_timestamp_check_identity :=
                            addmod(
                                mulmod(timestamp_delta, addmod(1, sub(p, index_delta), p), p), sub(p, mload(W3_EVAL_LOC)), p
                            )

                        mstore(
                            AUX_IDENTITY,
                            mulmod(
                                mload(C_ALPHA_BASE_LOC),
                                mulmod(
                                    mload(QAUX_EVAL_LOC),
                                    addmod(
                                        addmod(
                                            mulmod(
                                                addmod(
                                                    addmod(
                                                        mulmod(
                                                            mload(AUX_ROM_CONSISTENCY_EVALUATION), mload(Q2_EVAL_LOC), p
                                                        ),
                                                        mulmod(RAM_timestamp_check_identity, mload(Q4_EVAL_LOC), p),
                                                        p
                                                    ),
                                                    mulmod(mload(AUX_MEMORY_EVALUATION), mload(QM_EVAL_LOC), p),
                                                    p
                                                ),
                                                mload(Q1_EVAL_LOC),
                                                p
                                            ),
                                            mulmod(mload(AUX_RAM_CONSISTENCY_EVALUATION), mload(QARITH_EVAL_LOC), p),
                                            p
                                        ),
                                        addmod(
                                            mload(AUX_NON_NATIVE_FIELD_EVALUATION),
                                            mload(AUX_LIMB_ACCUMULATOR_EVALUATION),
                                            p
                                        ),
                                        p
                                    ),
                                    p
                                ),
                                p
                            )
                        )

                        // update alpha
                        mstore(C_ALPHA_BASE_LOC, mulmod(mload(C_ALPHA_BASE_LOC), mload(C_ALPHA_CUBE_LOC), p))
                    }
                }
            }

            {
                mstore(
                    QUOTIENT_EVAL_LOC,
                    mulmod(
                        addmod(
                            addmod(
                                addmod(
                                    addmod(
                                        addmod(mload(PERMUTATION_IDENTITY), mload(PLOOKUP_IDENTITY), p),
                                        mload(ARITHMETIC_IDENTITY),
                                        p
                                    ),
                                    mload(SORT_IDENTITY),
                                    p
                                ),
                                mload(ELLIPTIC_IDENTITY),
                                p
                            ),
                            mload(AUX_IDENTITY),
                            p
                        ),
                        mload(ZERO_POLY_INVERSE_LOC),
                        p
                    )
                )
            }

            /**
             * GENERATE NU AND SEPARATOR CHALLENGES
             */
            {
                let current_challenge := mload(C_CURRENT_LOC)
                // get a calldata pointer that points to the start of the data we want to copy
                let calldata_ptr := add(calldataload(0x04), 0x24)

                calldata_ptr := add(calldata_ptr, NU_CALLDATA_SKIP_LENGTH)

                mstore(NU_CHALLENGE_INPUT_LOC_A, current_challenge)
                mstore(NU_CHALLENGE_INPUT_LOC_B, mload(QUOTIENT_EVAL_LOC))
                calldatacopy(NU_CHALLENGE_INPUT_LOC_C, calldata_ptr, NU_INPUT_LENGTH)

                // hash length = (0x20 + num field elements), we include the previous challenge in the hash
                let challenge := keccak256(NU_CHALLENGE_INPUT_LOC_A, add(NU_INPUT_LENGTH, 0x40))

                mstore(C_V0_LOC, mod(challenge, p))
                // We need THIRTY-ONE independent nu challenges!
                mstore(0x00, challenge)
                mstore8(0x20, 0x01)
                mstore(C_V1_LOC, mod(keccak256(0x00, 0x21), p))
                mstore8(0x20, 0x02)
                mstore(C_V2_LOC, mod(keccak256(0x00, 0x21), p))
                mstore8(0x20, 0x03)
                mstore(C_V3_LOC, mod(keccak256(0x00, 0x21), p))
                mstore8(0x20, 0x04)
                mstore(C_V4_LOC, mod(keccak256(0x00, 0x21), p))
                mstore8(0x20, 0x05)
                mstore(C_V5_LOC, mod(keccak256(0x00, 0x21), p))
                mstore8(0x20, 0x06)
                mstore(C_V6_LOC, mod(keccak256(0x00, 0x21), p))
                mstore8(0x20, 0x07)
                mstore(C_V7_LOC, mod(keccak256(0x00, 0x21), p))
                mstore8(0x20, 0x08)
                mstore(C_V8_LOC, mod(keccak256(0x00, 0x21), p))
                mstore8(0x20, 0x09)
                mstore(C_V9_LOC, mod(keccak256(0x00, 0x21), p))
                mstore8(0x20, 0x0a)
                mstore(C_V10_LOC, mod(keccak256(0x00, 0x21), p))
                mstore8(0x20, 0x0b)
                mstore(C_V11_LOC, mod(keccak256(0x00, 0x21), p))
                mstore8(0x20, 0x0c)
                mstore(C_V12_LOC, mod(keccak256(0x00, 0x21), p))
                mstore8(0x20, 0x0d)
                mstore(C_V13_LOC, mod(keccak256(0x00, 0x21), p))
                mstore8(0x20, 0x0e)
                mstore(C_V14_LOC, mod(keccak256(0x00, 0x21), p))
                mstore8(0x20, 0x0f)
                mstore(C_V15_LOC, mod(keccak256(0x00, 0x21), p))
                mstore8(0x20, 0x10)
                mstore(C_V16_LOC, mod(keccak256(0x00, 0x21), p))
                mstore8(0x20, 0x11)
                mstore(C_V17_LOC, mod(keccak256(0x00, 0x21), p))
                mstore8(0x20, 0x12)
                mstore(C_V18_LOC, mod(keccak256(0x00, 0x21), p))
                mstore8(0x20, 0x13)
                mstore(C_V19_LOC, mod(keccak256(0x00, 0x21), p))
                mstore8(0x20, 0x14)
                mstore(C_V20_LOC, mod(keccak256(0x00, 0x21), p))
                mstore8(0x20, 0x15)
                mstore(C_V21_LOC, mod(keccak256(0x00, 0x21), p))
                mstore8(0x20, 0x16)
                mstore(C_V22_LOC, mod(keccak256(0x00, 0x21), p))
                mstore8(0x20, 0x17)
                mstore(C_V23_LOC, mod(keccak256(0x00, 0x21), p))
                mstore8(0x20, 0x18)
                mstore(C_V24_LOC, mod(keccak256(0x00, 0x21), p))
                mstore8(0x20, 0x19)
                mstore(C_V25_LOC, mod(keccak256(0x00, 0x21), p))
                mstore8(0x20, 0x1a)
                mstore(C_V26_LOC, mod(keccak256(0x00, 0x21), p))
                mstore8(0x20, 0x1b)
                mstore(C_V27_LOC, mod(keccak256(0x00, 0x21), p))
                mstore8(0x20, 0x1c)
                mstore(C_V28_LOC, mod(keccak256(0x00, 0x21), p))
                mstore8(0x20, 0x1d)
                mstore(C_V29_LOC, mod(keccak256(0x00, 0x21), p))

                mstore8(0x20, 0x1d)
                challenge := keccak256(0x00, 0x21)
                mstore(C_V30_LOC, mod(challenge, p))

                // separator
                mstore(0x00, challenge)
                mstore(0x20, mload(PI_Z_Y_LOC))
                mstore(0x40, mload(PI_Z_X_LOC))
                mstore(0x60, mload(PI_Z_OMEGA_Y_LOC))
                mstore(0x80, mload(PI_Z_OMEGA_X_LOC))

                mstore(C_U_LOC, mod(keccak256(0x00, 0xa0), p))
            }

            let success := 0
            // VALIDATE T1
            {
                let x := mload(T1_X_LOC)
                let y := mload(T1_Y_LOC)
                let xx := mulmod(x, x, q)
                success := eq(mulmod(y, y, q), addmod(mulmod(x, xx, q), 3, q))
                mstore(ACCUMULATOR_X_LOC, x)
                mstore(add(ACCUMULATOR_X_LOC, 0x20), y)
            }
            // VALIDATE T2
            {
                let x := mload(T2_X_LOC)
                let y := mload(T2_Y_LOC)
                let xx := mulmod(x, x, q)
                success := and(success, eq(mulmod(y, y, q), addmod(mulmod(x, xx, q), 3, q)))
                mstore(0x00, x)
                mstore(0x20, y)
            }
            mstore(0x40, mload(ZETA_POW_N_LOC))

            success :=
                and(
                    staticcall(gas(), 6, ACCUMULATOR_X_LOC, 0x80, ACCUMULATOR_X_LOC, 0x40),
                    and(success, staticcall(gas(), 7, 0x00, 0x60, ACCUMULATOR2_X_LOC, 0x40))
                )

            // VALIDATE T3
            {
                let x := mload(T3_X_LOC)
                let y := mload(T3_Y_LOC)
                let xx := mulmod(x, x, q)
                success := and(success, eq(mulmod(y, y, q), addmod(mulmod(x, xx, q), 3, q)))
                mstore(0x00, x)
                mstore(0x20, y)
            }
            mstore(0x40, mulmod(mload(ZETA_POW_N_LOC), mload(ZETA_POW_N_LOC), p))

            success :=
                and(
                    staticcall(gas(), 6, ACCUMULATOR_X_LOC, 0x80, ACCUMULATOR_X_LOC, 0x40),
                    and(success, staticcall(gas(), 7, 0x00, 0x60, ACCUMULATOR2_X_LOC, 0x40))
                )

            // VALIDATE T4
            {
                let x := mload(T4_X_LOC)
                let y := mload(T4_Y_LOC)
                let xx := mulmod(x, x, q)
                success := and(success, eq(mulmod(y, y, q), addmod(mulmod(x, xx, q), 3, q)))
                mstore(0x00, x)
                mstore(0x20, y)
            }
            mstore(0x40, mulmod(mulmod(mload(ZETA_POW_N_LOC), mload(ZETA_POW_N_LOC), p), mload(ZETA_POW_N_LOC), p))

            success :=
                and(
                    staticcall(gas(), 6, ACCUMULATOR_X_LOC, 0x80, ACCUMULATOR_X_LOC, 0x40),
                    and(success, staticcall(gas(), 7, 0x00, 0x60, ACCUMULATOR2_X_LOC, 0x40))
                )

            // VALIDATE W1
            {
                let x := mload(W1_X_LOC)
                let y := mload(W1_Y_LOC)
                let xx := mulmod(x, x, q)
                success := and(success, eq(mulmod(y, y, q), addmod(mulmod(x, xx, q), 3, q)))
                mstore(0x00, x)
                mstore(0x20, y)
            }
            mstore(0x40, mulmod(addmod(mload(C_U_LOC), 0x1, p), mload(C_V0_LOC), p))
            success :=
                and(
                    staticcall(gas(), 6, ACCUMULATOR_X_LOC, 0x80, ACCUMULATOR_X_LOC, 0x40),
                    and(success, staticcall(gas(), 7, 0x00, 0x60, ACCUMULATOR2_X_LOC, 0x40))
                )

            // VALIDATE W2
            {
                let x := mload(W2_X_LOC)
                let y := mload(W2_Y_LOC)
                let xx := mulmod(x, x, q)
                success := and(success, eq(mulmod(y, y, q), addmod(mulmod(x, xx, q), 3, q)))
                mstore(0x00, x)
                mstore(0x20, y)
            }
            mstore(0x40, mulmod(addmod(mload(C_U_LOC), 0x1, p), mload(C_V1_LOC), p))
            success :=
                and(
                    staticcall(gas(), 6, ACCUMULATOR_X_LOC, 0x80, ACCUMULATOR_X_LOC, 0x40),
                    and(success, staticcall(gas(), 7, 0x00, 0x60, ACCUMULATOR2_X_LOC, 0x40))
                )

            // VALIDATE W3
            {
                let x := mload(W3_X_LOC)
                let y := mload(W3_Y_LOC)
                let xx := mulmod(x, x, q)
                success := and(success, eq(mulmod(y, y, q), addmod(mulmod(x, xx, q), 3, q)))
                mstore(0x00, x)
                mstore(0x20, y)
            }
            mstore(0x40, mulmod(addmod(mload(C_U_LOC), 0x1, p), mload(C_V2_LOC), p))
            success :=
                and(
                    staticcall(gas(), 6, ACCUMULATOR_X_LOC, 0x80, ACCUMULATOR_X_LOC, 0x40),
                    and(success, staticcall(gas(), 7, 0x00, 0x60, ACCUMULATOR2_X_LOC, 0x40))
                )

            // VALIDATE W4
            {
                let x := mload(W4_X_LOC)
                let y := mload(W4_Y_LOC)
                let xx := mulmod(x, x, q)
                success := and(success, eq(mulmod(y, y, q), addmod(mulmod(x, xx, q), 3, q)))
                mstore(0x00, x)
                mstore(0x20, y)
            }
            mstore(0x40, mulmod(addmod(mload(C_U_LOC), 0x1, p), mload(C_V3_LOC), p))
            success :=
                and(
                    staticcall(gas(), 6, ACCUMULATOR_X_LOC, 0x80, ACCUMULATOR_X_LOC, 0x40),
                    and(success, staticcall(gas(), 7, 0x00, 0x60, ACCUMULATOR2_X_LOC, 0x40))
                )

            // VALIDATE S
            {
                let x := mload(S_X_LOC)
                let y := mload(S_Y_LOC)
                let xx := mulmod(x, x, q)
                success := and(success, eq(mulmod(y, y, q), addmod(mulmod(x, xx, q), 3, q)))
                mstore(0x00, x)
                mstore(0x20, y)
            }
            mstore(0x40, mulmod(addmod(mload(C_U_LOC), 0x1, p), mload(C_V4_LOC), p))
            success :=
                and(
                    staticcall(gas(), 6, ACCUMULATOR_X_LOC, 0x80, ACCUMULATOR_X_LOC, 0x40),
                    and(success, staticcall(gas(), 7, 0x00, 0x60, ACCUMULATOR2_X_LOC, 0x40))
                )

            // VALIDATE Z
            {
                let x := mload(Z_X_LOC)
                let y := mload(Z_Y_LOC)
                let xx := mulmod(x, x, q)
                success := and(success, eq(mulmod(y, y, q), addmod(mulmod(x, xx, q), 3, q)))
                mstore(0x00, x)
                mstore(0x20, y)
            }
            mstore(0x40, mulmod(addmod(mload(C_U_LOC), 0x1, p), mload(C_V5_LOC), p))
            success :=
                and(
                    staticcall(gas(), 6, ACCUMULATOR_X_LOC, 0x80, ACCUMULATOR_X_LOC, 0x40),
                    and(success, staticcall(gas(), 7, 0x00, 0x60, ACCUMULATOR2_X_LOC, 0x40))
                )

            // VALIDATE Z_LOOKUP
            {
                let x := mload(Z_LOOKUP_X_LOC)
                let y := mload(Z_LOOKUP_Y_LOC)
                let xx := mulmod(x, x, q)
                success := and(success, eq(mulmod(y, y, q), addmod(mulmod(x, xx, q), 3, q)))
                mstore(0x00, x)
                mstore(0x20, y)
            }
            mstore(0x40, mulmod(addmod(mload(C_U_LOC), 0x1, p), mload(C_V6_LOC), p))
            success :=
                and(
                    staticcall(gas(), 6, ACCUMULATOR_X_LOC, 0x80, ACCUMULATOR_X_LOC, 0x40),
                    and(success, staticcall(gas(), 7, 0x00, 0x60, ACCUMULATOR2_X_LOC, 0x40))
                )

            // VALIDATE Q1
            {
                let x := mload(Q1_X_LOC)
                let y := mload(Q1_Y_LOC)
                let xx := mulmod(x, x, q)
                success := and(success, eq(mulmod(y, y, q), addmod(mulmod(x, xx, q), 3, q)))
                mstore(0x00, x)
                mstore(0x20, y)
            }
            mstore(0x40, mload(C_V7_LOC))
            success :=
                and(
                    staticcall(gas(), 6, ACCUMULATOR_X_LOC, 0x80, ACCUMULATOR_X_LOC, 0x40),
                    and(success, staticcall(gas(), 7, 0x00, 0x60, ACCUMULATOR2_X_LOC, 0x40))
                )

            // VALIDATE Q2
            {
                let x := mload(Q2_X_LOC)
                let y := mload(Q2_Y_LOC)
                let xx := mulmod(x, x, q)
                success := and(success, eq(mulmod(y, y, q), addmod(mulmod(x, xx, q), 3, q)))
                mstore(0x00, x)
                mstore(0x20, y)
            }
            mstore(0x40, mload(C_V8_LOC))
            success :=
                and(
                    staticcall(gas(), 6, ACCUMULATOR_X_LOC, 0x80, ACCUMULATOR_X_LOC, 0x40),
                    and(success, staticcall(gas(), 7, 0x00, 0x60, ACCUMULATOR2_X_LOC, 0x40))
                )

            // VALIDATE Q3
            {
                let x := mload(Q3_X_LOC)
                let y := mload(Q3_Y_LOC)
                let xx := mulmod(x, x, q)
                success := and(success, eq(mulmod(y, y, q), addmod(mulmod(x, xx, q), 3, q)))
                mstore(0x00, x)
                mstore(0x20, y)
            }
            mstore(0x40, mload(C_V9_LOC))
            success :=
                and(
                    staticcall(gas(), 6, ACCUMULATOR_X_LOC, 0x80, ACCUMULATOR_X_LOC, 0x40),
                    and(success, staticcall(gas(), 7, 0x00, 0x60, ACCUMULATOR2_X_LOC, 0x40))
                )

            // VALIDATE Q4
            {
                let x := mload(Q4_X_LOC)
                let y := mload(Q4_Y_LOC)
                let xx := mulmod(x, x, q)
                success := and(success, eq(mulmod(y, y, q), addmod(mulmod(x, xx, q), 3, q)))
                mstore(0x00, x)
                mstore(0x20, y)
            }
            mstore(0x40, mload(C_V10_LOC))
            success :=
                and(
                    staticcall(gas(), 6, ACCUMULATOR_X_LOC, 0x80, ACCUMULATOR_X_LOC, 0x40),
                    and(success, staticcall(gas(), 7, 0x00, 0x60, ACCUMULATOR2_X_LOC, 0x40))
                )

            // VALIDATE QM
            {
                let x := mload(QM_X_LOC)
                let y := mload(QM_Y_LOC)
                let xx := mulmod(x, x, q)
                success := and(success, eq(mulmod(y, y, q), addmod(mulmod(x, xx, q), 3, q)))
                mstore(0x00, x)
                mstore(0x20, y)
            }
            mstore(0x40, mload(C_V11_LOC))
            success :=
                and(
                    staticcall(gas(), 6, ACCUMULATOR_X_LOC, 0x80, ACCUMULATOR_X_LOC, 0x40),
                    and(success, staticcall(gas(), 7, 0x00, 0x60, ACCUMULATOR2_X_LOC, 0x40))
                )

            // VALIDATE QC
            {
                let x := mload(QC_X_LOC)
                let y := mload(QC_Y_LOC)
                let xx := mulmod(x, x, q)
                success := and(success, eq(mulmod(y, y, q), addmod(mulmod(x, xx, q), 3, q)))
                mstore(0x00, x)
                mstore(0x20, y)
            }
            mstore(0x40, mload(C_V12_LOC))
            success :=
                and(
                    staticcall(gas(), 6, ACCUMULATOR_X_LOC, 0x80, ACCUMULATOR_X_LOC, 0x40),
                    and(success, staticcall(gas(), 7, 0x00, 0x60, ACCUMULATOR2_X_LOC, 0x40))
                )

            // VALIDATE QARITH
            {
                let x := mload(QARITH_X_LOC)
                let y := mload(QARITH_Y_LOC)
                let xx := mulmod(x, x, q)
                success := and(success, eq(mulmod(y, y, q), addmod(mulmod(x, xx, q), 3, q)))
                mstore(0x00, x)
                mstore(0x20, y)
            }
            mstore(0x40, mload(C_V13_LOC))
            success :=
                and(
                    staticcall(gas(), 6, ACCUMULATOR_X_LOC, 0x80, ACCUMULATOR_X_LOC, 0x40),
                    and(success, staticcall(gas(), 7, 0x00, 0x60, ACCUMULATOR2_X_LOC, 0x40))
                )

            // VALIDATE QSORT
            {
                let x := mload(QSORT_X_LOC)
                let y := mload(QSORT_Y_LOC)
                let xx := mulmod(x, x, q)
                success := and(success, eq(mulmod(y, y, q), addmod(mulmod(x, xx, q), 3, q)))
                mstore(0x00, x)
                mstore(0x20, y)
            }
            mstore(0x40, mload(C_V14_LOC))
            success :=
                and(
                    staticcall(gas(), 6, ACCUMULATOR_X_LOC, 0x80, ACCUMULATOR_X_LOC, 0x40),
                    and(success, staticcall(gas(), 7, 0x00, 0x60, ACCUMULATOR2_X_LOC, 0x40))
                )

            // VALIDATE QELLIPTIC
            {
                let x := mload(QELLIPTIC_X_LOC)
                let y := mload(QELLIPTIC_Y_LOC)
                let xx := mulmod(x, x, q)
                success := and(success, eq(mulmod(y, y, q), addmod(mulmod(x, xx, q), 3, q)))
                mstore(0x00, x)
                mstore(0x20, y)
            }
            mstore(0x40, mload(C_V15_LOC))
            success :=
                and(
                    staticcall(gas(), 6, ACCUMULATOR_X_LOC, 0x80, ACCUMULATOR_X_LOC, 0x40),
                    and(success, staticcall(gas(), 7, 0x00, 0x60, ACCUMULATOR2_X_LOC, 0x40))
                )

            // VALIDATE QAUX
            {
                let x := mload(QAUX_X_LOC)
                let y := mload(QAUX_Y_LOC)
                let xx := mulmod(x, x, q)
                success := and(success, eq(mulmod(y, y, q), addmod(mulmod(x, xx, q), 3, q)))
                mstore(0x00, x)
                mstore(0x20, y)
            }
            mstore(0x40, mload(C_V16_LOC))
            success :=
                and(
                    staticcall(gas(), 6, ACCUMULATOR_X_LOC, 0x80, ACCUMULATOR_X_LOC, 0x40),
                    and(success, staticcall(gas(), 7, 0x00, 0x60, ACCUMULATOR2_X_LOC, 0x40))
                )

            // VALIDATE SIGMA1
            {
                let x := mload(SIGMA1_X_LOC)
                let y := mload(SIGMA1_Y_LOC)
                let xx := mulmod(x, x, q)
                success := and(success, eq(mulmod(y, y, q), addmod(mulmod(x, xx, q), 3, q)))
                mstore(0x00, x)
                mstore(0x20, y)
            }
            mstore(0x40, mload(C_V17_LOC))
            success :=
                and(
                    staticcall(gas(), 6, ACCUMULATOR_X_LOC, 0x80, ACCUMULATOR_X_LOC, 0x40),
                    and(success, staticcall(gas(), 7, 0x00, 0x60, ACCUMULATOR2_X_LOC, 0x40))
                )

            // VALIDATE SIGMA2
            {
                let x := mload(SIGMA2_X_LOC)
                let y := mload(SIGMA2_Y_LOC)
                let xx := mulmod(x, x, q)
                success := and(success, eq(mulmod(y, y, q), addmod(mulmod(x, xx, q), 3, q)))
                mstore(0x00, x)
                mstore(0x20, y)
            }
            mstore(0x40, mload(C_V18_LOC))
            success :=
                and(
                    staticcall(gas(), 6, ACCUMULATOR_X_LOC, 0x80, ACCUMULATOR_X_LOC, 0x40),
                    and(success, staticcall(gas(), 7, 0x00, 0x60, ACCUMULATOR2_X_LOC, 0x40))
                )

            // VALIDATE SIGMA3
            {
                let x := mload(SIGMA3_X_LOC)
                let y := mload(SIGMA3_Y_LOC)
                let xx := mulmod(x, x, q)
                success := and(success, eq(mulmod(y, y, q), addmod(mulmod(x, xx, q), 3, q)))
                mstore(0x00, x)
                mstore(0x20, y)
            }
            mstore(0x40, mload(C_V19_LOC))
            success :=
                and(
                    staticcall(gas(), 6, ACCUMULATOR_X_LOC, 0x80, ACCUMULATOR_X_LOC, 0x40),
                    and(success, staticcall(gas(), 7, 0x00, 0x60, ACCUMULATOR2_X_LOC, 0x40))
                )

            // VALIDATE SIGMA4
            {
                let x := mload(SIGMA4_X_LOC)
                let y := mload(SIGMA4_Y_LOC)
                let xx := mulmod(x, x, q)
                success := and(success, eq(mulmod(y, y, q), addmod(mulmod(x, xx, q), 3, q)))
                mstore(0x00, x)
                mstore(0x20, y)
            }
            mstore(0x40, mload(C_V20_LOC))
            success :=
                and(
                    staticcall(gas(), 6, ACCUMULATOR_X_LOC, 0x80, ACCUMULATOR_X_LOC, 0x40),
                    and(success, staticcall(gas(), 7, 0x00, 0x60, ACCUMULATOR2_X_LOC, 0x40))
                )

            // VALIDATE TABLE1
            {
                let x := mload(TABLE1_X_LOC)
                let y := mload(TABLE1_Y_LOC)
                let xx := mulmod(x, x, q)
                success := and(success, eq(mulmod(y, y, q), addmod(mulmod(x, xx, q), 3, q)))
                mstore(0x00, x)
                mstore(0x20, y)
            }
            mstore(0x40, mulmod(addmod(mload(C_U_LOC), 0x1, p), mload(C_V21_LOC), p))
            success :=
                and(
                    staticcall(gas(), 6, ACCUMULATOR_X_LOC, 0x80, ACCUMULATOR_X_LOC, 0x40),
                    and(success, staticcall(gas(), 7, 0x00, 0x60, ACCUMULATOR2_X_LOC, 0x40))
                )

            // VALIDATE TABLE2
            {
                let x := mload(TABLE2_X_LOC)
                let y := mload(TABLE2_Y_LOC)
                let xx := mulmod(x, x, q)
                success := and(success, eq(mulmod(y, y, q), addmod(mulmod(x, xx, q), 3, q)))
                mstore(0x00, x)
                mstore(0x20, y)
            }
            mstore(0x40, mulmod(addmod(mload(C_U_LOC), 0x1, p), mload(C_V22_LOC), p))
            success :=
                and(
                    staticcall(gas(), 6, ACCUMULATOR_X_LOC, 0x80, ACCUMULATOR_X_LOC, 0x40),
                    and(success, staticcall(gas(), 7, 0x00, 0x60, ACCUMULATOR2_X_LOC, 0x40))
                )

            // VALIDATE TABLE3
            {
                let x := mload(TABLE3_X_LOC)
                let y := mload(TABLE3_Y_LOC)
                let xx := mulmod(x, x, q)
                success := and(success, eq(mulmod(y, y, q), addmod(mulmod(x, xx, q), 3, q)))
                mstore(0x00, x)
                mstore(0x20, y)
            }
            mstore(0x40, mulmod(addmod(mload(C_U_LOC), 0x1, p), mload(C_V23_LOC), p))
            success :=
                and(
                    staticcall(gas(), 6, ACCUMULATOR_X_LOC, 0x80, ACCUMULATOR_X_LOC, 0x40),
                    and(success, staticcall(gas(), 7, 0x00, 0x60, ACCUMULATOR2_X_LOC, 0x40))
                )

            // VALIDATE TABLE4
            {
                let x := mload(TABLE4_X_LOC)
                let y := mload(TABLE4_Y_LOC)
                let xx := mulmod(x, x, q)
                success := and(success, eq(mulmod(y, y, q), addmod(mulmod(x, xx, q), 3, q)))
                mstore(0x00, x)
                mstore(0x20, y)
            }
            mstore(0x40, mulmod(addmod(mload(C_U_LOC), 0x1, p), mload(C_V24_LOC), p))
            success :=
                and(
                    staticcall(gas(), 6, ACCUMULATOR_X_LOC, 0x80, ACCUMULATOR_X_LOC, 0x40),
                    and(success, staticcall(gas(), 7, 0x00, 0x60, ACCUMULATOR2_X_LOC, 0x40))
                )

            // VALIDATE TABLE_TYPE
            {
                let x := mload(TABLE_TYPE_X_LOC)
                let y := mload(TABLE_TYPE_Y_LOC)
                let xx := mulmod(x, x, q)
                success := and(success, eq(mulmod(y, y, q), addmod(mulmod(x, xx, q), 3, q)))
                mstore(0x00, x)
                mstore(0x20, y)
            }
            mstore(0x40, mload(C_V25_LOC))
            success :=
                and(
                    staticcall(gas(), 6, ACCUMULATOR_X_LOC, 0x80, ACCUMULATOR_X_LOC, 0x40),
                    and(success, staticcall(gas(), 7, 0x00, 0x60, ACCUMULATOR2_X_LOC, 0x40))
                )

            // VALIDATE ID1
            {
                let x := mload(ID1_X_LOC)
                let y := mload(ID1_Y_LOC)
                let xx := mulmod(x, x, q)
                success := and(success, eq(mulmod(y, y, q), addmod(mulmod(x, xx, q), 3, q)))
                mstore(0x00, x)
                mstore(0x20, y)
            }
            mstore(0x40, mload(C_V26_LOC))
            success :=
                and(
                    staticcall(gas(), 6, ACCUMULATOR_X_LOC, 0x80, ACCUMULATOR_X_LOC, 0x40),
                    and(success, staticcall(gas(), 7, 0x00, 0x60, ACCUMULATOR2_X_LOC, 0x40))
                )

            // VALIDATE ID2
            {
                let x := mload(ID2_X_LOC)
                let y := mload(ID2_Y_LOC)
                let xx := mulmod(x, x, q)
                success := and(success, eq(mulmod(y, y, q), addmod(mulmod(x, xx, q), 3, q)))
                mstore(0x00, x)
                mstore(0x20, y)
            }
            mstore(0x40, mload(C_V27_LOC))
            success :=
                and(
                    staticcall(gas(), 6, ACCUMULATOR_X_LOC, 0x80, ACCUMULATOR_X_LOC, 0x40),
                    and(success, staticcall(gas(), 7, 0x00, 0x60, ACCUMULATOR2_X_LOC, 0x40))
                )

            // VALIDATE ID3
            {
                let x := mload(ID3_X_LOC)
                let y := mload(ID3_Y_LOC)
                let xx := mulmod(x, x, q)
                success := and(success, eq(mulmod(y, y, q), addmod(mulmod(x, xx, q), 3, q)))
                mstore(0x00, x)
                mstore(0x20, y)
            }
            mstore(0x40, mload(C_V28_LOC))
            success :=
                and(
                    staticcall(gas(), 6, ACCUMULATOR_X_LOC, 0x80, ACCUMULATOR_X_LOC, 0x40),
                    and(success, staticcall(gas(), 7, 0x00, 0x60, ACCUMULATOR2_X_LOC, 0x40))
                )

            // VALIDATE ID4
            {
                let x := mload(ID4_X_LOC)
                let y := mload(ID4_Y_LOC)
                let xx := mulmod(x, x, q)
                success := and(success, eq(mulmod(y, y, q), addmod(mulmod(x, xx, q), 3, q)))
                mstore(0x00, x)
                mstore(0x20, y)
            }
            mstore(0x40, mload(C_V29_LOC))
            success :=
                and(
                    staticcall(gas(), 6, ACCUMULATOR_X_LOC, 0x80, ACCUMULATOR_X_LOC, 0x40),
                    and(success, staticcall(gas(), 7, 0x00, 0x60, ACCUMULATOR2_X_LOC, 0x40))
                )

            /**
             * COMPUTE BATCH EVALUATION SCALAR MULTIPLIER
             */
            {
                let batch_evaluation :=
                    addmod(
                        0, // mload(QUOTIENT_EVAL_LOC),
                        mulmod(
                            mload(C_V0_LOC),
                            addmod(mulmod(mload(W1_OMEGA_EVAL_LOC), mload(C_U_LOC), p), mload(W1_EVAL_LOC), p),
                            p
                        ),
                        p
                    )

                batch_evaluation :=
                    addmod(
                        batch_evaluation,
                        mulmod(
                            mload(C_V1_LOC),
                            addmod(mulmod(mload(W2_OMEGA_EVAL_LOC), mload(C_U_LOC), p), mload(W2_EVAL_LOC), p),
                            p
                        ),
                        p
                    )

                batch_evaluation :=
                    addmod(
                        batch_evaluation,
                        mulmod(
                            mload(C_V2_LOC),
                            addmod(mulmod(mload(W3_OMEGA_EVAL_LOC), mload(C_U_LOC), p), mload(W3_EVAL_LOC), p),
                            p
                        ),
                        p
                    )

                batch_evaluation :=
                    addmod(
                        batch_evaluation,
                        mulmod(
                            mload(C_V3_LOC),
                            addmod(mulmod(mload(W4_OMEGA_EVAL_LOC), mload(C_U_LOC), p), mload(W4_EVAL_LOC), p),
                            p
                        ),
                        p
                    )

                batch_evaluation :=
                    addmod(
                        batch_evaluation,
                        mulmod(
                            mload(C_V4_LOC),
                            addmod(mulmod(mload(S_OMEGA_EVAL_LOC), mload(C_U_LOC), p), mload(S_EVAL_LOC), p),
                            p
                        ),
                        p
                    )

                batch_evaluation :=
                    addmod(
                        batch_evaluation,
                        mulmod(
                            mload(C_V5_LOC),
                            addmod(mulmod(mload(Z_OMEGA_EVAL_LOC), mload(C_U_LOC), p), mload(Z_EVAL_LOC), p),
                            p
                        ),
                        p
                    )

                batch_evaluation :=
                    addmod(
                        batch_evaluation,
                        mulmod(
                            mload(C_V6_LOC),
                            addmod(mulmod(mload(Z_LOOKUP_OMEGA_EVAL_LOC), mload(C_U_LOC), p), mload(Z_LOOKUP_EVAL_LOC), p),
                            p
                        ),
                        p
                    )

                batch_evaluation := addmod(batch_evaluation, mulmod(mload(C_V7_LOC), mload(Q1_EVAL_LOC), p), p)

                batch_evaluation := addmod(batch_evaluation, mulmod(mload(C_V8_LOC), mload(Q2_EVAL_LOC), p), p)

                batch_evaluation := addmod(batch_evaluation, mulmod(mload(C_V9_LOC), mload(Q3_EVAL_LOC), p), p)

                batch_evaluation := addmod(batch_evaluation, mulmod(mload(C_V10_LOC), mload(Q4_EVAL_LOC), p), p)

                batch_evaluation := addmod(batch_evaluation, mulmod(mload(C_V11_LOC), mload(QM_EVAL_LOC), p), p)

                batch_evaluation := addmod(batch_evaluation, mulmod(mload(C_V12_LOC), mload(QC_EVAL_LOC), p), p)

                batch_evaluation := addmod(batch_evaluation, mulmod(mload(C_V13_LOC), mload(QARITH_EVAL_LOC), p), p)

                batch_evaluation := addmod(batch_evaluation, mulmod(mload(C_V14_LOC), mload(QSORT_EVAL_LOC), p), p)

                batch_evaluation := addmod(batch_evaluation, mulmod(mload(C_V15_LOC), mload(QELLIPTIC_EVAL_LOC), p), p)

                batch_evaluation := addmod(batch_evaluation, mulmod(mload(C_V16_LOC), mload(QAUX_EVAL_LOC), p), p)

                batch_evaluation := addmod(batch_evaluation, mulmod(mload(C_V17_LOC), mload(SIGMA1_EVAL_LOC), p), p)

                batch_evaluation := addmod(batch_evaluation, mulmod(mload(C_V18_LOC), mload(SIGMA2_EVAL_LOC), p), p)

                batch_evaluation := addmod(batch_evaluation, mulmod(mload(C_V19_LOC), mload(SIGMA3_EVAL_LOC), p), p)

                batch_evaluation := addmod(batch_evaluation, mulmod(mload(C_V20_LOC), mload(SIGMA4_EVAL_LOC), p), p)

                batch_evaluation :=
                    addmod(
                        batch_evaluation,
                        mulmod(
                            mload(C_V21_LOC),
                            addmod(mulmod(mload(TABLE1_OMEGA_EVAL_LOC), mload(C_U_LOC), p), mload(TABLE1_EVAL_LOC), p),
                            p
                        ),
                        p
                    )

                batch_evaluation :=
                    addmod(
                        batch_evaluation,
                        mulmod(
                            mload(C_V22_LOC),
                            addmod(mulmod(mload(TABLE2_OMEGA_EVAL_LOC), mload(C_U_LOC), p), mload(TABLE2_EVAL_LOC), p),
                            p
                        ),
                        p
                    )

                batch_evaluation :=
                    addmod(
                        batch_evaluation,
                        mulmod(
                            mload(C_V23_LOC),
                            addmod(mulmod(mload(TABLE3_OMEGA_EVAL_LOC), mload(C_U_LOC), p), mload(TABLE3_EVAL_LOC), p),
                            p
                        ),
                        p
                    )

                batch_evaluation :=
                    addmod(
                        batch_evaluation,
                        mulmod(
                            mload(C_V24_LOC),
                            addmod(mulmod(mload(TABLE4_OMEGA_EVAL_LOC), mload(C_U_LOC), p), mload(TABLE4_EVAL_LOC), p),
                            p
                        ),
                        p
                    )

                batch_evaluation := addmod(batch_evaluation, mulmod(mload(C_V25_LOC), mload(TABLE_TYPE_EVAL_LOC), p), p)

                batch_evaluation := addmod(batch_evaluation, mulmod(mload(C_V26_LOC), mload(ID1_EVAL_LOC), p), p)

                batch_evaluation := addmod(batch_evaluation, mulmod(mload(C_V27_LOC), mload(ID2_EVAL_LOC), p), p)

                batch_evaluation := addmod(batch_evaluation, mulmod(mload(C_V28_LOC), mload(ID3_EVAL_LOC), p), p)

                batch_evaluation := addmod(batch_evaluation, mulmod(mload(C_V29_LOC), mload(ID4_EVAL_LOC), p), p)

                batch_evaluation := addmod(batch_evaluation, mload(QUOTIENT_EVAL_LOC), p)

                mstore(0x00, 0x01) // [1].x
                mstore(0x20, 0x02) // [1].y
                mstore(0x40, sub(p, batch_evaluation))
                success :=
                    and(
                        staticcall(gas(), 6, ACCUMULATOR_X_LOC, 0x80, ACCUMULATOR_X_LOC, 0x40),
                        staticcall(gas(), 7, 0x00, 0x60, ACCUMULATOR2_X_LOC, 0x40)
                    )
                mstore(OPENING_COMMITMENT_SUCCESS_FLAG, success)
            }

            /**
             * PERFORM PAIRING PREAMBLE
             */
            {
                let u := mload(C_U_LOC)
                let zeta := mload(C_ZETA_LOC)
                // VALIDATE PI_Z
                {
                    let x := mload(PI_Z_X_LOC)
                    let y := mload(PI_Z_Y_LOC)
                    let xx := mulmod(x, x, q)
                    success := eq(mulmod(y, y, q), addmod(mulmod(x, xx, q), 3, q))
                    mstore(0x00, x)
                    mstore(0x20, y)
                }
                // compute zeta.[PI_Z] and add into accumulator
                mstore(0x40, zeta)
                success :=
                    and(
                        success,
                        and(
                            staticcall(gas(), 6, ACCUMULATOR_X_LOC, 0x80, ACCUMULATOR_X_LOC, 0x40),
                            staticcall(gas(), 7, 0x00, 0x60, ACCUMULATOR2_X_LOC, 0x40)
                        )
                    )

                // VALIDATE PI_Z_OMEGA
                {
                    let x := mload(PI_Z_OMEGA_X_LOC)
                    let y := mload(PI_Z_OMEGA_Y_LOC)
                    let xx := mulmod(x, x, q)
                    success := and(success, eq(mulmod(y, y, q), addmod(mulmod(x, xx, q), 3, q)))
                    mstore(0x00, x)
                    mstore(0x20, y)
                }
                // compute u.zeta.omega.[PI_Z_OMEGA] and add into accumulator
                mstore(0x40, mulmod(mulmod(u, zeta, p), mload(OMEGA_LOC), p))
                success :=
                    and(
                        staticcall(gas(), 6, ACCUMULATOR_X_LOC, 0x80, PAIRING_RHS_X_LOC, 0x40),
                        and(success, staticcall(gas(), 7, 0x00, 0x60, ACCUMULATOR2_X_LOC, 0x40))
                    )

                mstore(0x00, mload(PI_Z_X_LOC))
                mstore(0x20, mload(PI_Z_Y_LOC))
                mstore(0x40, mload(PI_Z_OMEGA_X_LOC))
                mstore(0x60, mload(PI_Z_OMEGA_Y_LOC))
                mstore(0x80, u)
                success :=
                    and(
                        staticcall(gas(), 6, 0x00, 0x80, PAIRING_LHS_X_LOC, 0x40),
                        and(success, staticcall(gas(), 7, 0x40, 0x60, 0x40, 0x40))
                    )
                // negate lhs y-coordinate
                mstore(PAIRING_LHS_Y_LOC, sub(q, mload(PAIRING_LHS_Y_LOC)))

                if mload(CONTAINS_RECURSIVE_PROOF_LOC) {
                    // VALIDATE RECURSIVE P1
                    {
                        let x := mload(RECURSIVE_P1_X_LOC)
                        let y := mload(RECURSIVE_P1_Y_LOC)
                        let xx := mulmod(x, x, q)
                        success := and(success, eq(mulmod(y, y, q), addmod(mulmod(x, xx, q), 3, q)))
                        mstore(0x00, x)
                        mstore(0x20, y)
                    }

                    // compute u.u.[recursive_p1] and write into 0x60
                    mstore(0x40, mulmod(u, u, p))
                    success := and(success, staticcall(gas(), 7, 0x00, 0x60, 0x60, 0x40))
                    // VALIDATE RECURSIVE P2
                    {
                        let x := mload(RECURSIVE_P2_X_LOC)
                        let y := mload(RECURSIVE_P2_Y_LOC)
                        let xx := mulmod(x, x, q)
                        success := and(success, eq(mulmod(y, y, q), addmod(mulmod(x, xx, q), 3, q)))
                        mstore(0x00, x)
                        mstore(0x20, y)
                    }
                    // compute u.u.[recursive_p2] and write into 0x00
                    // 0x40 still contains u*u
                    success := and(success, staticcall(gas(), 7, 0x00, 0x60, 0x00, 0x40))

                    // compute u.u.[recursiveP1] + rhs and write into rhs
                    mstore(0xa0, mload(PAIRING_RHS_X_LOC))
                    mstore(0xc0, mload(PAIRING_RHS_Y_LOC))
                    success := and(success, staticcall(gas(), 6, 0x60, 0x80, PAIRING_RHS_X_LOC, 0x40))

                    // compute u.u.[recursiveP2] + lhs and write into lhs
                    mstore(0x40, mload(PAIRING_LHS_X_LOC))
                    mstore(0x60, mload(PAIRING_LHS_Y_LOC))
                    success := and(success, staticcall(gas(), 6, 0x00, 0x80, PAIRING_LHS_X_LOC, 0x40))
                }

                if iszero(success) {
                    mstore(0x0, EC_SCALAR_MUL_FAILURE_SELECTOR)
                    revert(0x00, 0x04)
                }
                mstore(PAIRING_PREAMBLE_SUCCESS_FLAG, success)
            }

            /**
             * PERFORM PAIRING
             */
            {
                // rhs paired with [1]_2
                // lhs paired with [x]_2

                mstore(0x00, mload(PAIRING_RHS_X_LOC))
                mstore(0x20, mload(PAIRING_RHS_Y_LOC))
                mstore(0x40, 0x198e9393920d483a7260bfb731fb5d25f1aa493335a9e71297e485b7aef312c2) // this is [1]_2
                mstore(0x60, 0x1800deef121f1e76426a00665e5c4479674322d4f75edadd46debd5cd992f6ed)
                mstore(0x80, 0x090689d0585ff075ec9e99ad690c3395bc4b313370b38ef355acdadcd122975b)
                mstore(0xa0, 0x12c85ea5db8c6deb4aab71808dcb408fe3d1e7690c43d37b4ce6cc0166fa7daa)

                mstore(0xc0, mload(PAIRING_LHS_X_LOC))
                mstore(0xe0, mload(PAIRING_LHS_Y_LOC))
                mstore(0x100, mload(G2X_X0_LOC))
                mstore(0x120, mload(G2X_X1_LOC))
                mstore(0x140, mload(G2X_Y0_LOC))
                mstore(0x160, mload(G2X_Y1_LOC))

                success := staticcall(gas(), 8, 0x00, 0x180, 0x00, 0x20)
                mstore(PAIRING_SUCCESS_FLAG, success)
                mstore(RESULT_FLAG, mload(0x00))
            }
            if iszero(
                and(
                    and(and(mload(PAIRING_SUCCESS_FLAG), mload(RESULT_FLAG)), mload(PAIRING_PREAMBLE_SUCCESS_FLAG)),
                    mload(OPENING_COMMITMENT_SUCCESS_FLAG)
                )
            ) {
                mstore(0x0, PROOF_FAILURE_SELECTOR)
                revert(0x00, 0x04)
            }
            {
                mstore(0x00, 0x01)
                return(0x00, 0x20) // Proof succeeded!
            }
        }
    }
}

contract UltraVerifier is BaseUltraVerifier {
    function getVerificationKeyHash() public pure override(BASE) returns (bytes32) {
        return UltraVerificationKey.verificationKeyHash();
    }

    function loadVerificationKey(uint256 vk, uint256 _omegaInverseLoc) internal pure virtual override(BASE) {
        UltraVerificationKey.loadVerificationKey(vk, _omegaInverseLoc);
    }
}
