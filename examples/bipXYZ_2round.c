/***********************************************************************
 * Commit-reveal sign-to-contract anti-exfil example.
 *
 * Unlike the 1-round bipXYZ scheme in examples/bipXYZ.c — which is
 * mitigation-based, not cryptographic — this construction provides
 * cryptographic anti-exfil: a malicious signing device cannot leak its
 * secret key via nonce choice to an outside observer of signatures.
 *
 * Protocol
 * --------
 *   Round 0:  Host   → Device:  C = H(ρ)         (host commits)
 *   Round 1:  Device → Host:    Q = q·G          (device commits)
 *   Round 2:  Host   → Device:  ρ                (host opens C)
 *             Device → Host:    sig              (device signs)
 *
 *   Host verifier check:  sig.R == Q + H(Q, m, ρ)·G
 *
 * Security argument
 * -----------------
 *   The host commits to ρ before seeing Q, so it cannot request multiple
 *   signatures for the same Q with different ρ values. The device commits
 *   to Q before seeing ρ. Whatever q it picks (honest or adversarial), it
 *   has no information about ρ at that moment, so it cannot evaluate the
 *   resulting R and therefore cannot grind toward an R that leaks key bits.
 *   After ρ arrives, R = Q + H(Q,m,ρ)·G is fully determined.
 *
 *   Q itself is sent privately to the (trusted) host; only sig is
 *   published. A malicious host that colludes with the on-chain
 *   observer breaks anti-exfil — same threat model as classical S2C.
 *
 *   Residual covert channel: abort/timing (~1 bit per attempt,
 *   detectable). Not closed by 2 rounds either.
 *
 * Notes
 * -----
 *   The specific q-derivation used here, q = H_tag(seckey || m), is
 *   only what an HONEST device does. A malicious device may use any q
 *   it likes — the verifier cannot check (it doesn't know seckey).
 *   Security comes from the commit-then-challenge flow, not from any
 *   property of q.
 *
 * References
 * ----------
 *   https://gist.github.com/moonsettler/d4eb59c62a2b8f104c72603231b73a41
 *   https://delvingbitcoin.org/t/non-interactive-anti-exfil-airgap-compatible/1081
 *   Schnorr/ECDSA Sign-to-Contract (S2C), Andrew Poelstra et al.
 ***********************************************************************/

#include <stdio.h>
#include <assert.h>
#include <string.h>

#include "examples_util.h"

#include <secp256k1.h>
#include <secp256k1_extrakeys.h>
#include <secp256k1_schnorrsig.h>

#include "bipXYZ_impl.h"

static const unsigned char tag_commit[] = {
    'B','I','P','0','X','Y','Z','-','2','R','/','c','o','m','m','i','t'
};
static const unsigned char tag_tweak[] = {
    'B','I','P','0','X','Y','Z','-','2','R','/','t','w','e','a','k'
};
static const unsigned char tag_host_commit[] = {
    'B','I','P','0','X','Y','Z','-','2','R','/','h','o','s','t'
};

static int host_pick_challenge(unsigned char *rho) {
    return fill_random(rho, 32);
}

static int host_commit_challenge(const secp256k1_context *ctx,
                                 unsigned char *rho_commit,
                                 const unsigned char *rho) {
    return secp256k1_tagged_sha256(ctx, rho_commit, tag_host_commit, sizeof(tag_host_commit), rho, 32);
}

static int verify_challenge_commitment(const secp256k1_context *ctx,
                                       const unsigned char *rho,
                                       const unsigned char *rho_commit) {
    unsigned char expected[32];
    int rv;

    rv = host_commit_challenge(ctx, expected, rho);
    assert(rv);
    return memcmp(expected, rho_commit, sizeof(expected)) == 0;
}

/* =====================================================================
 * Round 1 (device): commit to Q = q·G with q derived from (seckey, m, C).
 *
 * The device must remember q between rounds; only Q is sent to the host.
 * Q is the device's binding "nonce commitment" — committing to it before
 * seeing ρ is what removes the device's freedom over the final R.
 * ===================================================================== */

static int schnorrsig_device_round1(const secp256k1_context *ctx,
                                    unsigned char *q,
                                    unsigned char *Q_ser,
                                    const secp256k1_keypair *keypair,
                                    const unsigned char *m32,
                                    const unsigned char *rho_commit) {
    unsigned char seckey[32];
    unsigned char input[96];
    secp256k1_xonly_pubkey X, Q_xo;
    secp256k1_pubkey Q_full;
    int pk_parity, rv;

    rv = secp256k1_keypair_sec(ctx, seckey, keypair);
    assert(rv);
    /* Canonicalize seckey to the BIP340 even-y branch so q is independent
     * of which sign of seckey the caller happened to supply. */
    rv = secp256k1_keypair_xonly_pub(ctx, &X, &pk_parity, keypair);
    assert(rv);
    if (pk_parity == 1) {
        rv = secp256k1_ec_seckey_negate(ctx, seckey);
        assert(rv);
    }

    memcpy(input, seckey, 32);
    memcpy(input + 32, m32, 32);
    memcpy(input + 64, rho_commit, 32);
    rv = secp256k1_tagged_sha256(ctx, q, tag_commit, sizeof(tag_commit), input, sizeof(input));
    assert(rv);
    secure_erase(seckey, sizeof(seckey));
    secure_erase(input,  sizeof(input));

    /* Q = q·G; force even-y so Q_ser is the canonical x-only form. */
    rv = secp256k1_ec_pubkey_create(ctx, &Q_full, q);
    assert(rv);
    rv = secp256k1_xonly_pubkey_from_pubkey(ctx, &Q_xo, &pk_parity, &Q_full);
    assert(rv);
    rv = secp256k1_xonly_pubkey_serialize(ctx, Q_ser, &Q_xo);
    assert(rv);
    if (pk_parity == 1) {
        rv = secp256k1_ec_seckey_negate(ctx, q);
        assert(rv);
    }
    return 1;
}

static int ecdsa_device_round1(const secp256k1_context *ctx,
                               unsigned char *q,
                               unsigned char *Q_ser33,
                               const secp256k1_keypair *keypair,
                               const unsigned char *m32,
                               const unsigned char *rho_commit) {
    unsigned char seckey[32];
    unsigned char input[96];
    secp256k1_pubkey Q;
    size_t compressed_len = 33;
    int rv;

    rv = secp256k1_keypair_sec(ctx, seckey, keypair);
    assert(rv);

    memcpy(input, seckey, 32);
    memcpy(input + 32, m32, 32);
    memcpy(input + 64, rho_commit, 32);
    rv = secp256k1_tagged_sha256(ctx, q, tag_commit, sizeof(tag_commit), input, sizeof(input));
    assert(rv);
    secure_erase(seckey, sizeof(seckey));
    secure_erase(input,  sizeof(input));

    /* If q is invalid (≥ n or 0; probability ~2^-128) production code
     * would loop with a counter — skipped here for clarity. */
    assert(secp256k1_ec_seckey_verify(ctx, q));

    rv = secp256k1_ec_pubkey_create(ctx, &Q, q);
    assert(rv);
    rv = secp256k1_ec_pubkey_serialize(ctx, Q_ser33, &compressed_len, &Q, SECP256K1_EC_COMPRESSED);
    assert(rv);
    return 1;
}

/* =====================================================================
 * Round 2 (device): sign with k = q + H_tag(Q, m, ρ).
 * ===================================================================== */

static int schnorrsig_device_round2(const secp256k1_context *ctx,
                                    unsigned char *sig64,
                                    const unsigned char *q,
                                    const unsigned char *Q_ser,
                                    const unsigned char *m32,
                                    const unsigned char *rho,
                                    const unsigned char *rho_commit,
                                    const secp256k1_keypair *keypair) {
    unsigned char tweak[32];
    unsigned char k[32];
    secp256k1_schnorrsig_extraparams xp = SECP256K1_SCHNORRSIG_EXTRAPARAMS_INIT;
    int rv;

    if (!verify_challenge_commitment(ctx, rho, rho_commit)) {
        return 0;
    }

    rv = bipxyz_compute_tweak_schnorr(ctx, tweak, tag_tweak, sizeof(tag_tweak), Q_ser, m32, rho);
    assert(rv);
    memcpy(k, q, 32);
    rv = secp256k1_ec_seckey_tweak_add(ctx, k, tweak);
    assert(rv);

    xp.noncefp = bipxyz_nonce_passthrough_schnorr;
    xp.ndata = k;
    rv = secp256k1_schnorrsig_sign_custom(ctx, sig64, m32, 32, keypair, &xp);
    assert(rv);

    secure_erase(k, sizeof(k));
    return 1;
}

static int ecdsa_device_round2(const secp256k1_context *ctx,
                               secp256k1_ecdsa_signature *sig_out,
                               const unsigned char *q,
                               const unsigned char *Q_ser33,
                               const unsigned char *m32,
                               const unsigned char *rho,
                               const unsigned char *rho_commit,
                               const secp256k1_keypair *keypair) {
    unsigned char tweak[32];
    unsigned char k[32];
    unsigned char seckey[32];
    int rv;

    if (!verify_challenge_commitment(ctx, rho, rho_commit)) {
        return 0;
    }

    rv = bipxyz_compute_tweak_ecdsa(ctx, tweak, tag_tweak, sizeof(tag_tweak), Q_ser33, m32, rho);
    assert(rv);
    memcpy(k, q, 32);
    rv = secp256k1_ec_seckey_tweak_add(ctx, k, tweak);
    assert(rv);

    rv = secp256k1_keypair_sec(ctx, seckey, keypair);
    assert(rv);
    rv = secp256k1_ecdsa_sign(ctx, sig_out, m32, seckey, bipxyz_nonce_passthrough_ecdsa, (void *)k);
    assert(rv);

    secure_erase(seckey, sizeof(seckey));
    secure_erase(k,      sizeof(k));
    return 1;
}

/* =====================================================================
 * Host verification: recompute R = Q + H_tag(Q,m,ρ)·G and check sig.R.
 * ===================================================================== */

static int schnorrsig_host_verify(const secp256k1_context *ctx,
                                  const unsigned char *sig64,
                                  const unsigned char *Q_ser,
                                  const unsigned char *m32,
                                  const unsigned char *rho,
                                  const secp256k1_xonly_pubkey *pubkey) {
    unsigned char R_ser[32];
    int rv;

    rv = bipxyz_reconstruct_schnorr_R(ctx, R_ser, Q_ser, tag_tweak, sizeof(tag_tweak), m32, rho);
    if (!rv) {
        printf("\tantiexfill: FAIL\n");
        return 0;
    }

    printf("\tR   ");
    print_hex(R_ser, 32);
    if (memcmp(R_ser, sig64, 32) != 0) {
        printf("\tantiexfill: FAIL\n");
        return 0;
    }
    printf("\tantiexfill: OK\n");
    rv = secp256k1_schnorrsig_verify(ctx, sig64, m32, 32, pubkey);
    if (!rv) {
        printf("\tschnorrsig: FAIL\n");
        return 0;
    }
    printf("\tschnorrsig: OK\n");
    return 1;
}

static int ecdsa_host_verify(const secp256k1_context *ctx,
                             const secp256k1_ecdsa_signature *signature,
                             const unsigned char *Q_ser33,
                             const unsigned char *m32,
                             const unsigned char *rho,
                             const secp256k1_pubkey *pubkey) {
    unsigned char R_r[32], sig_compact[64];
    int rv;

    rv = bipxyz_reconstruct_ecdsa_r(ctx, R_r, Q_ser33, tag_tweak, sizeof(tag_tweak), m32, rho);
    if (!rv) {
        printf("\tantiexfill: FAIL\n");
        return 0;
    }
    rv = secp256k1_ecdsa_signature_serialize_compact(ctx, sig_compact, signature);
    assert(rv);

    printf("\tR   ");
    print_hex(R_r, 32);
    if (memcmp(R_r, sig_compact, 32) != 0) {
        printf("\tantiexfill: FAIL\n");
        return 0;
    }
    printf("\tantiexfill: OK\n");
    rv = secp256k1_ecdsa_verify(ctx, signature, m32, pubkey);
    if (!rv) {
        printf("\tecdsa: FAIL\n");
        return 0;
    }
    printf("\tecdsa: OK\n");
    return 1;
}

/* =====================================================================
 * Demo: choreograph one round-trip per scheme.
 * ===================================================================== */

int main(void) {
    secp256k1_context *ctx;
    unsigned char randomize[32];
    unsigned char msg[32];
    unsigned char seckey[32];
    unsigned char rho[32];
    unsigned char rho_commit[32];
    unsigned char q_schnorr[32];
    unsigned char q_ecdsa[32];
    unsigned char Q_ser_schnorr[32];
    unsigned char Q_ser_ecdsa[33];
    unsigned char sig[64];
    secp256k1_keypair keypair;
    secp256k1_xonly_pubkey pubkey;
    secp256k1_pubkey pubkey_ecdsa;
    secp256k1_ecdsa_signature esig;
    int rv;

    ctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
    if (!fill_random(randomize, sizeof(randomize))) {
        printf("Failed to generate randomness\n"); return 1;
    }
    rv = secp256k1_context_randomize(ctx, randomize);
    assert(rv);

    printf("=== Setup ===\n");
    if (!fill_random(msg, sizeof(msg))) {
        printf("Failed to generate msg\n"); return 1;
    }
    printf("\tmsg    ");
    print_hex(msg, 32);

    while (1) {
        if (!fill_random(seckey, sizeof(seckey))) {
            printf("Failed to generate randomness\n"); return 1;
        }
        if (secp256k1_keypair_create(ctx, &keypair, seckey)) {
            printf("\tseckey ");
            print_hex(seckey, 32);
            break;
        }
    }

    /* ===================== SCHNORRSIG (commit-reveal) ===================== */
    printf("\n=== SCHNORRSIG (commit-reveal) ===\n");

    printf("Round 0: SW  -> HWW  (commit H(rho))\n");
    rv = host_pick_challenge(rho);
    assert(rv);
    rv = host_commit_challenge(ctx, rho_commit, rho);
    assert(rv);
    printf("\tH(rho) ");
    print_hex(rho_commit, 32);

    printf("Round 1: HWW -> SW   (commit Q)\n");
    rv = schnorrsig_device_round1(ctx, q_schnorr, Q_ser_schnorr, &keypair, msg, rho_commit);
    assert(rv);
    printf("\tQ   ");
    print_hex(Q_ser_schnorr, 32);

    printf("Round 2: SW  -> HWW  (open rho)\n");
    printf("\trho ");
    print_hex(rho, 32);

    printf("         HWW -> SW   (sign)\n");
    rv = schnorrsig_device_round2(ctx, sig, q_schnorr, Q_ser_schnorr, msg, rho, rho_commit, &keypair);
    assert(rv);
    printf("\tsig ");
    print_hex(sig, 64);

    printf("Host verify:\n");
    rv = secp256k1_keypair_xonly_pub(ctx, &pubkey, NULL, &keypair);
    assert(rv);
    rv = schnorrsig_host_verify(ctx, sig, Q_ser_schnorr, msg, rho, &pubkey);
    assert(rv);
    secure_erase(q_schnorr, sizeof(q_schnorr));

    /* ===================== ECDSA (commit-reveal) ===================== */
    printf("\n=== ECDSA (commit-reveal) ===\n");

    printf("Round 0: SW  -> HWW  (commit H(rho))\n");
    rv = host_pick_challenge(rho);
    assert(rv);
    rv = host_commit_challenge(ctx, rho_commit, rho);
    assert(rv);
    printf("\tH(rho) ");
    print_hex(rho_commit, 32);

    printf("Round 1: HWW -> SW   (commit Q)\n");
    rv = ecdsa_device_round1(ctx, q_ecdsa, Q_ser_ecdsa, &keypair, msg, rho_commit);
    assert(rv);
    printf("\tQ   ");
    print_hex(Q_ser_ecdsa, 33);

    printf("Round 2: SW  -> HWW  (open rho)\n");
    printf("\trho ");
    print_hex(rho, 32);

    printf("         HWW -> SW   (sign)\n");
    rv = ecdsa_device_round2(ctx, &esig, q_ecdsa, Q_ser_ecdsa, msg, rho, rho_commit, &keypair);
    assert(rv);

    printf("Host verify:\n");
    rv = secp256k1_keypair_pub(ctx, &pubkey_ecdsa, &keypair);
    assert(rv);
    rv = ecdsa_host_verify(ctx, &esig, Q_ser_ecdsa, msg, rho, &pubkey_ecdsa);
    assert(rv);
    secure_erase(q_ecdsa, sizeof(q_ecdsa));

    printf("\n");

    secp256k1_context_destroy(ctx);
    secure_erase(seckey, sizeof(seckey));
    return 0;
}
