#ifndef SECP256K1_EXAMPLES_BIPXYZ_IMPL_H
#define SECP256K1_EXAMPLES_BIPXYZ_IMPL_H

#include <string.h>

#include <secp256k1.h>
#include <secp256k1_extrakeys.h>

static const unsigned char bipxyz_secp256k1_order[] = {
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE,
    0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B,
    0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36, 0x41, 0x41
};

static int bipxyz_bytes32_ge(const unsigned char *a, const unsigned char *b) {
    int i;

    for (i = 0; i < 32; i++) {
        if (a[i] > b[i]) {
            return 1;
        }
        if (a[i] < b[i]) {
            return 0;
        }
    }
    return 1;
}

static void bipxyz_bytes32_sub(unsigned char *r, const unsigned char *a, const unsigned char *b) {
    int i;
    unsigned int borrow = 0;

    for (i = 31; i >= 0; i--) {
        unsigned int ai = a[i];
        unsigned int bi = b[i] + borrow;
        if (ai < bi) {
            r[i] = (unsigned char)(ai + 0x100 - bi);
            borrow = 1;
        } else {
            r[i] = (unsigned char)(ai - bi);
            borrow = 0;
        }
    }
}

static void bipxyz_ecdsa_r_from_x(unsigned char *r, const unsigned char *x) {
    if (bipxyz_bytes32_ge(x, bipxyz_secp256k1_order)) {
        bipxyz_bytes32_sub(r, x, bipxyz_secp256k1_order);
    } else {
        memcpy(r, x, 32);
    }
}

static int bipxyz_nonce_passthrough_schnorr(unsigned char *nonce32,
                                            const unsigned char *msg,
                                            size_t msglen,
                                            const unsigned char *key32,
                                            const unsigned char *xonly_pk32,
                                            const unsigned char *algo,
                                            size_t algolen,
                                            void *data) {
    (void)msg;
    (void)msglen;
    (void)key32;
    (void)xonly_pk32;
    (void)algo;
    (void)algolen;
    memcpy(nonce32, (unsigned char*)data, 32);
    return 1;
}

static int bipxyz_nonce_passthrough_ecdsa(unsigned char *nonce32,
                                          const unsigned char *msg32,
                                          const unsigned char *key32,
                                          const unsigned char *algo16,
                                          void *data,
                                          unsigned int counter) {
    (void)msg32;
    (void)key32;
    (void)algo16;
    (void)counter;
    memcpy(nonce32, (unsigned char*)data, 32);
    return 1;
}

static int bipxyz_compute_tweak_schnorr(const secp256k1_context *ctx,
                                        unsigned char *tweak,
                                        const unsigned char *tag,
                                        size_t taglen,
                                        const unsigned char *Q_ser32,
                                        const unsigned char *msg32,
                                        const unsigned char *extra32) {
    unsigned char buf[96];

    memcpy(buf, Q_ser32, 32);
    memcpy(buf + 32, msg32, 32);
    memcpy(buf + 64, extra32, 32);
    return secp256k1_tagged_sha256(ctx, tweak, tag, taglen, buf, sizeof(buf));
}

static int bipxyz_compute_tweak_ecdsa(const secp256k1_context *ctx,
                                      unsigned char *tweak,
                                      const unsigned char *tag,
                                      size_t taglen,
                                      const unsigned char *Q_ser33,
                                      const unsigned char *msg32,
                                      const unsigned char *extra32) {
    unsigned char buf[97];

    memcpy(buf, Q_ser33, 33);
    memcpy(buf + 33, msg32, 32);
    memcpy(buf + 65, extra32, 32);
    return secp256k1_tagged_sha256(ctx, tweak, tag, taglen, buf, sizeof(buf));
}

static int bipxyz_reconstruct_schnorr_R(const secp256k1_context *ctx,
                                        unsigned char *R_ser32,
                                        const unsigned char *Q_ser32,
                                        const unsigned char *tag,
                                        size_t taglen,
                                        const unsigned char *msg32,
                                        const unsigned char *extra32) {
    secp256k1_xonly_pubkey Q;
    secp256k1_xonly_pubkey R_xonly;
    secp256k1_pubkey R;
    unsigned char tweak[32];
    int rv;

    rv = secp256k1_xonly_pubkey_parse(ctx, &Q, Q_ser32);
    if (!rv) {
        return 0;
    }
    rv = bipxyz_compute_tweak_schnorr(ctx, tweak, tag, taglen, Q_ser32, msg32, extra32);
    if (!rv) {
        return 0;
    }
    rv = secp256k1_xonly_pubkey_tweak_add(ctx, &R, &Q, tweak);
    if (!rv) {
        return 0;
    }
    rv = secp256k1_xonly_pubkey_from_pubkey(ctx, &R_xonly, NULL, &R);
    if (!rv) {
        return 0;
    }
    return secp256k1_xonly_pubkey_serialize(ctx, R_ser32, &R_xonly);
}

static int bipxyz_reconstruct_ecdsa_r(const secp256k1_context *ctx,
                                      unsigned char *R_r32,
                                      const unsigned char *Q_ser33,
                                      const unsigned char *tag,
                                      size_t taglen,
                                      const unsigned char *msg32,
                                      const unsigned char *extra32) {
    secp256k1_pubkey Q;
    secp256k1_pubkey R;
    secp256k1_xonly_pubkey R_xonly;
    unsigned char tweak[32];
    unsigned char R_ser[32];
    int rv;

    rv = secp256k1_ec_pubkey_parse(ctx, &Q, Q_ser33, 33);
    if (!rv) {
        return 0;
    }
    rv = bipxyz_compute_tweak_ecdsa(ctx, tweak, tag, taglen, Q_ser33, msg32, extra32);
    if (!rv) {
        return 0;
    }
    R = Q;
    rv = secp256k1_ec_pubkey_tweak_add(ctx, &R, tweak);
    if (!rv) {
        return 0;
    }
    rv = secp256k1_xonly_pubkey_from_pubkey(ctx, &R_xonly, NULL, &R);
    if (!rv) {
        return 0;
    }
    rv = secp256k1_xonly_pubkey_serialize(ctx, R_ser, &R_xonly);
    if (!rv) {
        return 0;
    }
    bipxyz_ecdsa_r_from_x(R_r32, R_ser);
    return 1;
}

#endif
