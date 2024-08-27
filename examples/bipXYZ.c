#include <stdio.h>
#include <assert.h>
#include <string.h>

#include "examples_util.h"

#include <secp256k1.h>
#include <secp256k1_extrakeys.h>
#include <secp256k1_schnorrsig.h>


static const unsigned char bipXYZ_tag[] = {'B', 'I', 'P', '0', 'X', 'Y', 'Z', '/', 'n', 'o', 'n', 'c', 'e'};
static const unsigned char bipXYZ_aux[] = {'B', 'I', 'P', '0', 'X', 'Y', 'Z', '/', 'a', 'u', 'x'};


static int schnorrsig_noncefp_bipXYZ(const secp256k1_context* ctx, unsigned char *nonce32, unsigned char *Q_ser, const unsigned char *msg32, unsigned char *seckey, unsigned char *nonce_commit) {
    secp256k1_keypair keypair;
    secp256k1_keypair kp;
    secp256k1_xonly_pubkey Q;
    secp256k1_xonly_pubkey X;
    unsigned char masked_key[32];
    unsigned char tweak[32];

    unsigned char tweak_ser[96];
    unsigned char q_ser[96];
    int rv, pk_parity, i;

    rv = secp256k1_keypair_create(ctx, &keypair, seckey);
    assert(rv);
    rv = secp256k1_keypair_xonly_pub(ctx, &X, &pk_parity, &keypair);
    assert(rv);
    if (pk_parity == 1) {
        rv = secp256k1_ec_seckey_negate(ctx, seckey);
        assert(rv);
    }
    /* Let t be the byte-wise xor of bytes(seckey) and hashBIP0XYZ/aux(nonce_commit) */
    rv = secp256k1_tagged_sha256(ctx, masked_key, bipXYZ_aux, sizeof(bipXYZ_aux), nonce_commit, 32);
    assert(rv);

    for (i = 0; i < 32; i++) {
        masked_key[i] ^= seckey[i];
    }

    /* q = H(t,m,n) */
    memcpy(q_ser, masked_key, 32);
    memcpy(q_ser + 32, msg32, 32);
    memcpy(q_ser + 64, nonce_commit, 32);

    rv = secp256k1_tagged_sha256(ctx, nonce32, bipXYZ_tag, sizeof(bipXYZ_tag), q_ser, sizeof(q_ser));
    assert(rv);
    printf("\tq ");
    print_hex(nonce32, 32);

    /* Q = q·G */
    rv = secp256k1_keypair_create(ctx, &kp, nonce32);
    assert(rv);
    rv = secp256k1_keypair_xonly_pub(ctx, &Q, &pk_parity, &kp);
    assert(rv);
    rv = secp256k1_xonly_pubkey_serialize(ctx, Q_ser, &Q);
    assert(rv);
    if (pk_parity == 1) {
        rv = secp256k1_ec_seckey_negate(ctx, nonce32);
        assert(rv);
    }

    /* tweak = H(Q, m, n) */

    memcpy(tweak_ser, Q_ser, 32);
    memcpy(tweak_ser + 32, msg32, 32);
    memcpy(tweak_ser + 64, nonce_commit, 32);
    rv = secp256k1_tagged_sha256(ctx, tweak, bipXYZ_tag, sizeof(bipXYZ_tag), tweak_ser, sizeof(tweak_ser));
    assert(rv);

    /* k = q + H(Q, m, n) */
    rv = secp256k1_ec_seckey_tweak_add(ctx, nonce32, tweak);
    printf("\tk ");
    print_hex(nonce32, 32);
    assert(rv);
    return 1;
}

static int ecdsa_noncefp_bipXYZ(const secp256k1_context* ctx, unsigned char *nonce32, unsigned char *Q_ser, const unsigned char *msg32, unsigned char *seckey, unsigned char *nonce_commit, unsigned int counter) {
    secp256k1_keypair kp;
    secp256k1_pubkey Q;
    unsigned char masked_key[32];
    unsigned char tweak[32];

    unsigned char tweak_ser[97];
    unsigned char q_ser[97];
    int rv, i;
    char c = (unsigned char)counter;
    size_t compressed = 33;

    /* Let t be the byte-wise xor of bytes(seckey) and hashBIP0XYZ/aux(nonce_commit) */
    rv = secp256k1_tagged_sha256(ctx, masked_key, bipXYZ_aux, sizeof(bipXYZ_aux), nonce_commit, 32);
    assert(rv);

    for (i = 0; i < 32; i++) {
        masked_key[i] ^= seckey[i];
    }

    /* q = H(t,m,n) */
    memcpy(q_ser, masked_key, 32);
    memcpy(q_ser + 32, msg32, 32);
    memcpy(q_ser + 64, nonce_commit, 32);
    memcpy(q_ser + 96, &c, 1);

    rv = secp256k1_tagged_sha256(ctx, nonce32, bipXYZ_tag, sizeof(bipXYZ_tag), q_ser, sizeof(q_ser));
    assert(rv);
    printf("\tq ");
    print_hex(nonce32, 32);

    /* Q = q·G */
    rv = secp256k1_keypair_create(ctx, &kp, nonce32);
    assert(rv);
    rv = secp256k1_keypair_pub(ctx, &Q, &kp);
    assert(rv);
    rv = secp256k1_ec_pubkey_serialize(ctx, Q_ser, &compressed, &Q, SECP256K1_EC_COMPRESSED);
    assert(rv);

    /* tweak = H(Q, m, n) */

    memcpy(tweak_ser, Q_ser, 33);
    memcpy(tweak_ser + 33, msg32, 32);
    memcpy(tweak_ser + 65, nonce_commit, 32);
    rv = secp256k1_tagged_sha256(ctx, tweak, bipXYZ_tag, sizeof(bipXYZ_tag), tweak_ser, sizeof(tweak_ser));
    assert(rv);

    /* k = q + H(Q, m, n) */
    rv = secp256k1_ec_seckey_tweak_add(ctx, nonce32, tweak);
    printf("\tk ");
    print_hex(nonce32, 32);
    assert(rv);
    return 1;
}

static int schnorrsig_nonce_function_bipXYZ(unsigned char *nonce32, const unsigned char *msg, size_t msglen, const unsigned char *key32, const unsigned char *xonly_pk32, const unsigned char *algo, size_t algolen, void *data) {
    /* schnorrsig dummy passover */
    memcpy(nonce32, (unsigned char*)data, 32);
    return 1;
}

static int ecdsa_nonce_function_bipXYZ(unsigned char *nonce32, const unsigned char *msg32, const unsigned char *key32, const unsigned char *algo16, void *data, unsigned int counter) {
    /* ecdsa dummy passover */
    memcpy(nonce32, (unsigned char*)data, 32);
    return 1;
}

int schnorrsig_sign_bipXYZ(const secp256k1_context* ctx, unsigned char *sig64, unsigned char *Q_ser, unsigned char *msg32, const secp256k1_keypair *keypair, unsigned char *nonce_commit) {
    secp256k1_nonce_function_hardened nonce_fp_bipXYZ = schnorrsig_nonce_function_bipXYZ;
    secp256k1_schnorrsig_extraparams extraparams = SECP256K1_SCHNORRSIG_EXTRAPARAMS_INIT;
    int rv;
    unsigned char k[32];
    unsigned char seckey[32];

    rv = secp256k1_keypair_sec(ctx, seckey, keypair);
    assert(rv);
    rv = schnorrsig_noncefp_bipXYZ(ctx, k, Q_ser, msg32, seckey, nonce_commit);

    extraparams.noncefp = nonce_fp_bipXYZ;
    extraparams.ndata = &k;
    rv = secp256k1_schnorrsig_sign_custom(ctx, sig64, msg32, 32, keypair, &extraparams);
    assert(rv);
    printf("\tsig ");
    print_hex(sig64, 64);
    printf("\tQ ");
    print_hex(Q_ser, 32);
    return 1;
}

int ecdsa_sign_bipXYZ(const secp256k1_context* ctx, const secp256k1_ecdsa_signature *signature, unsigned char *Q_ser, unsigned char *msg32, const secp256k1_keypair *keypair, unsigned char *nonce_commit) {
    int rv;
    int c = 0;
    size_t siglen = 74;
    unsigned char k[32];
    unsigned char seckey[32];
    unsigned int ider[74];

    const secp256k1_nonce_function nonce_fp_bipXYZ = ecdsa_nonce_function_bipXYZ;

    rv = secp256k1_keypair_sec(ctx, seckey, keypair);
    assert(rv);

    while (1){
        rv = ecdsa_noncefp_bipXYZ(ctx, k, Q_ser, msg32, seckey, nonce_commit, c);
        assert(rv);
        if (secp256k1_ec_seckey_verify(ctx, k)) {
            break;
        }
        c += 1;
    }

    rv = secp256k1_ecdsa_sign(ctx, signature, msg32, seckey, nonce_fp_bipXYZ, (void*)k);
    assert(rv);
    rv = secp256k1_ecdsa_signature_serialize_der(ctx, ider, &siglen, signature);
    assert(rv);

    unsigned char der_sig[siglen];
    memcpy(der_sig, ider, siglen);
    printf("\tder ");
    print_hex(der_sig, siglen);
    printf("\tQ ");
    print_hex(Q_ser, 32);
    return 1;
}

int schnorrsig_verify_bipXYZ(const secp256k1_context* ctx, unsigned char *sig64, unsigned char *Q_ser, unsigned char *msg32, const secp256k1_xonly_pubkey *pubkey, unsigned char *nonce_commit) {
    secp256k1_xonly_pubkey Q;
    secp256k1_xonly_pubkey R;
    secp256k1_xonly_pubkey tweak_xo;
    secp256k1_keypair kp;
    int pk_parity, rv;
    unsigned char tweak_ser[96];
    unsigned char tweak[32];
    const secp256k1_xonly_pubkey *pubkeys[2];
    unsigned char R_ser[32];

    rv = secp256k1_xonly_pubkey_parse(ctx, &Q, Q_ser);
    assert(rv);

    /* H(Q,m,n) */
    memcpy(tweak_ser, Q_ser, 32);
    memcpy(tweak_ser + 32, msg32, 32);
    memcpy(tweak_ser + 64, nonce_commit, 32);
    rv = secp256k1_tagged_sha256(ctx, tweak, bipXYZ_tag, sizeof(bipXYZ_tag), tweak_ser, sizeof(tweak_ser));
    assert(rv);

    /* H(Q,m,n)·G */
    rv = secp256k1_keypair_create(ctx, &kp, tweak);
    assert(rv);
    rv = secp256k1_keypair_xonly_pub(ctx, &tweak_xo, &pk_parity, &kp);
    assert(rv);

    assert(rv);
    if (pk_parity == 1) {
        rv = secp256k1_ec_pubkey_negate(ctx, &tweak_xo);
        assert(rv);
    }
    pubkeys[0] = &tweak_xo;
    pubkeys[1] = &Q;
    /* R = Q + H(Q,m,n)·G */
    rv = secp256k1_ec_pubkey_combine(ctx, &R, pubkeys, 2);
    assert(rv);
    rv = secp256k1_xonly_pubkey_serialize(ctx, R_ser, &R);
    assert(rv);
    printf("\tR ");
    print_hex(R_ser, 32);
    if (memcmp(R_ser, sig64, sizeof(R_ser)) == 0) {
        printf("\tantiexfill: OK\n");
        rv = secp256k1_schnorrsig_verify(ctx, sig64, msg32, 32, pubkey);
        assert(rv);
        printf("\tschnorrsig: OK\n");
        return 1;
    } else {
        printf("\tFAIL");
        return 0;
    }
}

int ecdsa_verify_bipXYZ(const secp256k1_context* ctx, secp256k1_ecdsa_signature *signature, unsigned char *Q_ser, unsigned char *msg32, const secp256k1_pubkey *pubkey, unsigned char *nonce_commit) {
    secp256k1_pubkey Q;
    secp256k1_pubkey R;
    secp256k1_xonly_pubkey tweak_point;
    secp256k1_keypair kp;
    int rv;
    unsigned char tweak_ser[97];
    unsigned char tweak[32];
    const secp256k1_xonly_pubkey *pubkeys[2];
    unsigned char R_ser[32];
    unsigned char sig[64];

    rv = secp256k1_ec_pubkey_parse(ctx, &Q, Q_ser, 33);
    assert(rv);

    /* H(Q,m,n) */
    memcpy(tweak_ser, Q_ser, 33);
    memcpy(tweak_ser + 33, msg32, 32);
    memcpy(tweak_ser + 65, nonce_commit, 32);
    rv = secp256k1_tagged_sha256(ctx, tweak, bipXYZ_tag, sizeof(bipXYZ_tag), tweak_ser, sizeof(tweak_ser));
    assert(rv);

    /* H(Q,m,n)·G */
    rv = secp256k1_keypair_create(ctx, &kp, tweak);
    assert(rv);
    rv = secp256k1_keypair_pub(ctx, &tweak_point, &kp);
    assert(rv);

    pubkeys[0] = &tweak_point;
    pubkeys[1] = &Q;
    /* R = Q + H(Q,m,n)·G */
    rv = secp256k1_ec_pubkey_combine(ctx, &R, pubkeys, 2);
    assert(rv);
    /* serialize as Xonly to get rid of the marker */
    rv = secp256k1_xonly_pubkey_serialize(ctx, R_ser, &R);
    assert(rv);
    printf("\tR ");
    print_hex(R_ser, 32);
    rv = secp256k1_ecdsa_signature_serialize_compact(ctx, sig, signature);
    assert(rv);
    printf("\tsig compact ");
    print_hex(sig, 64);
    if (memcmp(R_ser, sig, sizeof(R_ser)) == 0) {
        printf("\tantiexfill: OK\n");
        rv = secp256k1_ecdsa_verify(ctx, signature, msg32, pubkey);
        assert(rv);
        printf("\tecdsa: OK\n");
        return 1;
    } else {
        printf("\tFAIL");
        return 0;
    }
}

int main(void) {
    unsigned char msg[32];
    unsigned char seckey[32];
    unsigned char randomize[32];
    unsigned char Q_ser[32];
    unsigned char Q_ser_ecdsa[33];
    unsigned char nonce_commit[32];
    unsigned char sig[64];
    int rv;
    secp256k1_xonly_pubkey pubkey;
    secp256k1_pubkey pubkey_ecdsa;
    secp256k1_keypair keypair;
    secp256k1_ecdsa_signature esig;

    secp256k1_context* ctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
    if (!fill_random(randomize, sizeof(randomize))) {
        printf("Failed to generate randomness\n");
        return 1;
    }
    rv = secp256k1_context_randomize(ctx, randomize);
    assert(rv);

    if (!fill_random(msg, sizeof(msg))) {
        printf("Failed to generate msg\n");
        return 1;
    }
    printf("msg ");
    print_hex(msg, 32);

    if (!fill_random(nonce_commit, sizeof(nonce_commit))) {
        printf("Failed to generate nonce_commit\n");
        return 1;
    }
    printf("nonce_commit ");
    print_hex(nonce_commit, 32);
    while (1) {
        if (!fill_random(seckey, sizeof(seckey))) {
            printf("Failed to generate randomness\n");
            return 1;
        }
        if (secp256k1_keypair_create(ctx, &keypair, seckey)) {
            printf("seckey ");
            print_hex(seckey, 32);
            break;
        }
    }
    printf("\n");
    printf("=== SCHNORRSIG ===\n");
    printf("HWW:\n");
    rv = schnorrsig_sign_bipXYZ(ctx, sig, Q_ser, msg, &keypair, nonce_commit);
    assert(rv);
    printf("SW:\n");
    rv = secp256k1_keypair_xonly_pub(ctx, &pubkey, NULL, &keypair);
    assert(rv);

    rv = schnorrsig_verify_bipXYZ(ctx, sig, Q_ser, msg, &pubkey, nonce_commit);
    assert(rv);

    printf("\n");

    printf("=== ECDSA ===\n");
    printf("HWW:\n");
    rv = ecdsa_sign_bipXYZ(ctx, &esig, Q_ser_ecdsa, msg, &keypair, nonce_commit);
    assert(rv);
    printf("SW:\n");
    rv = secp256k1_keypair_pub(ctx, &pubkey_ecdsa, &keypair);
    assert(rv);

    rv = ecdsa_verify_bipXYZ(ctx, &esig, Q_ser_ecdsa, msg, &pubkey_ecdsa, nonce_commit);
    assert(rv);

    printf("\n");

    secp256k1_context_destroy(ctx);
    secure_erase(seckey, sizeof(seckey));
    return 0;
}