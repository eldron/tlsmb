#ifndef __mb_ec_util_h
#define __mb_ec_util_h

#include "blapi.h"
#include "ecl-exp.h"
#include "plarena.h"
#include "mpi.h"

/*
 * Computes scalar point multiplication pointQ = k1 * G + k2 * pointP for
 * the curve whose parameters are encoded in params with base point G.
 */
extern SECStatus
ec_points_mul(const ECParams *params, const mp_int *k1, const mp_int *k2,
              const SECItem *pointP, SECItem *pointQ);

extern SECStatus SECU_ecName2params(ECCurveName curve, SECItem *params);

/*
 * Computes scalar point multiplication pointQ = k1 * G + k2 * pointP for
 * the curve whose parameters are encoded in params with base point G.
 */
// pointP and pointQ: len = ((ecParams->fieldID.size + 7) >> 3) * 2 + 1;
// data: legacy_form, X and Y
// SECStatus ec_points_mul(const ECParams *params, const mp_int *k1, const mp_int *k2,
//               const SECItem *pointP, SECItem *pointQ)

// for curve 25519:
// X, P:len = ecParams->order.len;
// k: len should be the length of order
/*
 * Scalar multiplication for Curve25519.
 * If P == NULL, the base point is used.
 * Returns X = k*P
 */
//ec_Curve25519_pt_mul(SECItem *X, SECItem *k, SECItem *P)

// used by client
// generate a_{n+1}=H(g^(alpha*a_{n}))
// alpha_bytes: alpha, of length len, the length on octets of the order buffer
// prev_private_key_bytes: input a_{n}
// returns: a_{n + 1}
unsigned char *
fake_ec_GenerateRandomPrivateKey(ECParams * ecParams, unsigned char * alpha_bytes,
    unsigned char * prev_private_key_bytes);

// used by middlebox
// calculate a_{n+1}=H(A_{n}^alpha)
// alpha_bytes: alpha, of length len, the length in octets of the order buffer
// returns: a_{n+1}
unsigned char * generate_ec_private_key_for_middlebox(ECParams * ecParams, 
    SECItem * A, unsigned char * alpha_bytes);

ECParams * mb_get_ec_params(ECCurveName curve, PLArenaPool * arena);
#endif
