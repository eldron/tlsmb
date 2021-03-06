#include "mb_ec_util.h"
#include "mpi.h"
#include "ecl.h"

#include <stdio.h>

extern mp_err mp_init(mp_int *mp);

#define MB_CHECK_MPI_OK(func)      \
    if (MP_OKAY > (err = func)) \
    return 0

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
// return 1 if success, return 0 else
// caller is responsible for free private key and public key
int
fake_ec_GenerateRandomPrivateKey(ECParams * ecParams, unsigned char * alpha_bytes,
    unsigned char * prev_private_key_bytes, unsigned char ** p_private_key, unsigned char ** p_public_key)
{
    unsigned char * order = ecParams->order.data;
    int len = ecParams->order.len;

    SECStatus rv = SECSuccess;
    mp_err err;
    unsigned char *privKeyBytes = NULL;
    mp_int privKeyVal, order_1, one;

    MP_DIGITS(&privKeyVal) = 0;
    MP_DIGITS(&order_1) = 0;
    MP_DIGITS(&one) = 0;
    MB_CHECK_MPI_OK(mp_init(&privKeyVal));
    MB_CHECK_MPI_OK(mp_init(&order_1));
    //MB_CHECK_MPI_OK(mp_init(&one));
    MB_CHECK_MPI_OK(mp_read_unsigned_octets(&order_1, order, len));
    //MB_CHECK_MPI_OK(mp_set_int(&one, 1));
    //MB_CHECK_MPI_OK(mp_sub(&order_1, &one, &order_1));

    /* Generates 2*len random bytes using the global random bit generator
     * (which implements Algorithm 1 of FIPS 186-2 Change Notice 1) then
     * reduces modulo the group order.
     */
    if ((privKeyBytes = PORT_Alloc(2 * len)) == NULL){
        fprintf(stderr, "can not allocate privKeyBytes\n");
        return 0;
    }
    //CHECK_SEC_OK(RNG_GenerateGlobalRandomBytes(privKeyBytes, 2 * len));

    // compute g^(alpha * a_{n})
    mp_int alpha_value;
    mp_int prev_private_key_value;
    MB_CHECK_MPI_OK(mp_init(&alpha_value));
    MB_CHECK_MPI_OK(mp_init(&prev_private_key_value));
    mp_read_unsigned_octets(&prev_private_key_value, prev_private_key_bytes, len);
    SECItem previtem;
    previtem.len = len;
    previtem.data = prev_private_key_bytes;

    if(alpha_bytes){
        mp_read_unsigned_octets(&alpha_value, alpha_bytes, len);
    } else {
        mp_set_int(&alpha_value, 2);
    }

    if(ecParams->name == ECCurve_NIST_P256||
        ecParams->name == ECCurve_NIST_P384 ||
        ecParams->name == ECCurve_NIST_P521){

        MB_CHECK_MPI_OK(mp_mul(&alpha_value, &prev_private_key_value, &alpha_value));
        MB_CHECK_MPI_OK(mp_mod(&alpha_value, &order_1, &alpha_value));
    }

    fprintf(stderr, "alpha * prev_private_key_value calculated\n");

    SECItem alpha_item;// use this for calculation
    alpha_item.len = len;
    alpha_item.data = PORT_Alloc(len);
    if(alpha_item.data == NULL){
        fprintf(stderr, "failed to alloc mem for alpha_item\n");
        return 0;
    }
    MB_CHECK_MPI_OK(mp_to_fixlen_octets(&alpha_value, alpha_item.data, len));
    //MB_CHECK_MPI_OK(mp_add(&alpha_value, &one, &alpha_value));// maybe this should be sub

    //fprintf(stderr, "alpha_item set\n");

    SECItem pubkey;
    if(ecParams->name == ECCurve25519){
        pubkey.len = 32;
        pubkey.data = PORT_Alloc(pubkey.len);
        if(pubkey.data == NULL){
            fprintf(stderr, "failed to alloc memory for pubkey.data\n");
            return 0;
        }

        ec_Curve25519_pt_mul(&pubkey, &previtem, NULL);// g^prev
        ec_Curve25519_pt_mul(&pubkey, &alpha_item, &pubkey);// g^prev^alpha
        //fprintf(stderr, "after 25519 mul\n");
        // fprintf(stderr, "gen key for client: pubkey.len = %u\n", pubkey.len);
        // int i;
        // for(i = 0;i < pubkey.len;i++){
        //     fprintf(stderr, "%u ", pubkey.data[i]);
        // }
        // fprintf(stderr, "\n");
    } else if(ecParams->name == ECCurve_NIST_P256 ||
        ecParams->name == ECCurve_NIST_P384 ||
        ecParams->name == ECCurve_NIST_P521){

        pubkey.len = ((ecParams->fieldID.size + 7) >> 3) * 2 + 1;
        pubkey.data = PORT_Alloc(pubkey.len);
        if(pubkey.data == NULL){
            fprintf(stderr, "could not alloc mem for pubkey.data\n");
            return 0;
        }

        ec_points_mul(ecParams, &alpha_value, NULL, NULL, &pubkey);
    }
    
    fprintf(stderr, "g^alpha calculated\n");

    // hash pubkey to get a_{n+1}, 
    // we should only hash the corresponding part in the packet
    unsigned char sha512_hash_bytes[SHA512_LENGTH];
    if(ecParams->name == ECCurve25519){
        // for x25519, we hash 32 bytes U
        pubkey.len = 32;
        SHA512_HashBuf(sha512_hash_bytes, pubkey.data, pubkey.len);
    } else if(ecParams->name == ECCurve_NIST_P256 ||
        ecParams->name == ECCurve_NIST_P384 ||
        ecParams->name == ECCurve_NIST_P521){
        
        // for secp 256, 348, 521 curves, we hash legacy_form, X and Y together
        pubkey.len = ((ecParams->fieldID.size + 7) >> 3) * 2 + 1;
        SHA512_HashBuf(sha512_hash_bytes, pubkey.data, pubkey.len);
    } else {
        fprintf(stderr, "unsupported curve name\n");
        return 0;
    }
    // feed hash bytes into privKeyBytes
    int tmp_len = 2 * len;
    unsigned char * to = privKeyBytes;
    while(tmp_len > SHA512_LENGTH){
        memcpy(to, sha512_hash_bytes, SHA512_LENGTH);
        to += SHA512_LENGTH;
        tmp_len -= SHA512_LENGTH;
    }
    if(tmp_len > 0){
        memcpy(to, sha512_hash_bytes, tmp_len);
    }

    MB_CHECK_MPI_OK(mp_read_unsigned_octets(&privKeyVal, privKeyBytes, 2 * len));
    
    MB_CHECK_MPI_OK(mp_mod(&privKeyVal, &order_1, &privKeyVal));
    //MB_CHECK_MPI_OK(mp_add(&privKeyVal, &one, &privKeyVal));
    MB_CHECK_MPI_OK(mp_to_fixlen_octets(&privKeyVal, privKeyBytes, len));
    memset(privKeyBytes + len, 0, len);// outside functions should use privKeyBytes as an array of length len

    *p_private_key = privKeyBytes;
    // calculate the corresponding public key
    if(ecParams->name == ECCurve25519){
        SECItem pubitem;
        pubitem.len = 32;
        pubitem.data = PORT_Alloc(32);
        if(pubitem.data == NULL){
            fprintf(stderr, "alloc mem for pubitem failed\n");
        }

        SECItem privitem;// for calculation
        privitem.len = len;
        privitem.data = privKeyBytes;
        ec_Curve25519_pt_mul(&pubitem, &privitem, NULL);// use base point to calculate
        *p_public_key = pubitem.data;
    } else if(ecParams->name == ECCurve_NIST_P256 ||
        ecParams->name == ECCurve_NIST_P384 ||
        ecParams->name == ECCurve_NIST_P521){

        SECItem pubitem;
        pubitem.len = ((ecParams->fieldID.size + 7) >> 3) * 2 + 1;
        pubitem.data = PORT_Alloc(pubitem.len);
        if(pubitem.data == NULL){
            fprintf(stderr, "alloc mem for pubitem failed\n");
            return 0;
        }

        ec_points_mul(ecParams, &privKeyVal, NULL, NULL, &pubitem);
        unsigned char * tmp = (unsigned char *) pubitem.data;
        *tmp = 4;// legacy form

        *p_public_key = pubitem.data;
    } else {
        fprintf(stderr, "generate_ec_private_key_for_middlebox: unexpected curve name\n");
    }

    mp_clear(&privKeyVal);
    mp_clear(&order_1);
    mp_clear(&one);

    return 1;
}

// used by middlebox
// calculate a_{n+1}=H(A_{n}^alpha)
// alpha_bytes: alpha, of length len, the length in octets of the order buffer
// returns: a_{n+1}
// return 1 if success, return 0 else
// caller is reponsible for free private key and public key
int generate_ec_private_key_for_middlebox(ECParams * ecParams, 
    SECItem * A, unsigned char * alpha_bytes, unsigned char ** p_private_key,
    unsigned char ** p_public_key){

    unsigned char * order = ecParams->order.data;
    int len = ecParams->order.len;
    unsigned char *privKeyBytes = NULL;
    mp_int privKeyVal, order_1, one;
    mp_err err = MP_OKAY;

    MP_DIGITS(&privKeyVal) = 0;
    MP_DIGITS(&order_1) = 0;
    MP_DIGITS(&one) = 0;
    MB_CHECK_MPI_OK(mp_init(&privKeyVal));
    MB_CHECK_MPI_OK(mp_init(&order_1));
    //MB_CHECK_MPI_OK(mp_init(&one));

    if ((privKeyBytes = PORT_Alloc(2 * len)) == NULL){
        fprintf(stderr, "can not allocate privKeyBytes\n");
        return 0;
    }

    mp_int alpha_value;
    mp_int prev_private_key_value;
    MB_CHECK_MPI_OK(mp_init(&alpha_value));
    MB_CHECK_MPI_OK(mp_init(&prev_private_key_value));
    if(alpha_bytes){
        mp_read_unsigned_octets(&alpha_value, alpha_bytes, len);
    } else {
        mp_set_int(&alpha_value, 2);
    }

    SECItem alpha_item;// use this for calculation
    alpha_item.len = len;
    alpha_item.data = PORT_Alloc(len);
    if(alpha_item.data == NULL){
        fprintf(stderr, "failed alloc memory for alpha_item\n");
        return 0;
    }
    if(alpha_bytes){
        memcpy(alpha_item.data, alpha_bytes, len);
    } else {
        mp_to_fixlen_octets(&alpha_value, alpha_item.data, len);
    }

    // calculate 
    SECItem result;
    if(ecParams->name == ECCurve25519){
        result.len = 32;
        result.data = PORT_Alloc(result.len);
        if(result.data == NULL){
            fprintf(stderr, "failed to alloc memeory for result\n");
            return 0;
        }

        ec_Curve25519_pt_mul(&result, &alpha_item, A);// use A to calculate
        // fprintf(stderr, "gen key for middlebox: result.len = %u\n", result.len);
        // int i;
        // for(i = 0;i < result.len;i++){
        //     fprintf(stderr, "%u ", result.data[i]);
        // }
        // fprintf(stderr, "\n\n");
    } else if(ecParams->name == ECCurve_NIST_P256
        || ecParams->name == ECCurve_NIST_P384
        || ecParams->name == ECCurve_NIST_P521){

        result.len = ((ecParams->fieldID.size + 7) >> 3) * 2 + 1;
        result.data = PORT_Alloc(result.len);
        if(result.data == NULL){
            fprintf(stderr, "alloc memory for result failed\n");
            return 0;
        }

        ec_points_mul(ecParams, NULL, &alpha_value, A, &result);

        unsigned char * tmp = (unsigned char *) result.data;
        *tmp = 4;// legacy form
    } else {
        fprintf(stderr, "generate_ec_private_key_for_middlebox: error unexpected curve type\n");
        return 0;
    }

    unsigned char sha512_hash_bytes[SHA512_LENGTH];
    SHA512_HashBuf(sha512_hash_bytes, result.data, result.len);
    // feed hash bytes into privKeyBytes
    int tmp_len = 2 * len;
    unsigned char * to = privKeyBytes;
    while(tmp_len > SHA512_LENGTH){
        memcpy(to, sha512_hash_bytes, SHA512_LENGTH);
        to += SHA512_LENGTH;
        tmp_len -= SHA512_LENGTH;
    }
    if(tmp_len > 0){
        memcpy(to, sha512_hash_bytes, tmp_len);
    }

    MB_CHECK_MPI_OK(mp_read_unsigned_octets(&privKeyVal, privKeyBytes, 2 * len));
    MB_CHECK_MPI_OK(mp_read_unsigned_octets(&order_1, order, len));
    //MB_CHECK_MPI_OK(mp_set_int(&one, 1));
    //MB_CHECK_MPI_OK(mp_sub(&order_1, &one, &order_1));
    MB_CHECK_MPI_OK(mp_mod(&privKeyVal, &order_1, &privKeyVal));
    //MB_CHECK_MPI_OK(mp_add(&privKeyVal, &one, &privKeyVal));
    MB_CHECK_MPI_OK(mp_to_fixlen_octets(&privKeyVal, privKeyBytes, len));
    memset(privKeyBytes + len, 0, len);// outside functions should use privKeyBytes as an array of length len

    *p_private_key = privKeyBytes;
    // calculate the corresponding public key
    if(ecParams->name == ECCurve25519){
        SECItem pubitem;
        pubitem.len = 32;
        pubitem.data = PORT_Alloc(32);
        if(pubitem.data == NULL){
            fprintf(stderr, "alloc mem for pubitem failed\n");
        }

        SECItem privitem;// for calculation
        privitem.len = len;
        privitem.data = privKeyBytes;
        ec_Curve25519_pt_mul(&pubitem, &privitem, NULL);// use base point to calculate
        *p_public_key = pubitem.data;
    } else if(ecParams->name == ECCurve_NIST_P256 ||
        ecParams->name == ECCurve_NIST_P384 ||
        ecParams->name == ECCurve_NIST_P521){

        SECItem pubitem;
        pubitem.len = ((ecParams->fieldID.size + 7) >> 3) * 2 + 1;
        pubitem.data = PORT_Alloc(pubitem.len);
        if(pubitem.data == NULL){
            fprintf(stderr, "alloc mem for pubitem failed\n");
            return 0;
        }

        ec_points_mul(ecParams, &privKeyVal, NULL, NULL, &pubitem);
        unsigned char * tmp = (unsigned char *) pubitem.data;
        *tmp = 4;// legacy form

        *p_public_key = pubitem.data;
    } else {
        fprintf(stderr, "generate_ec_private_key_for_middlebox: unexpected curve name\n");
    }

    mp_clear(&privKeyVal);
    mp_clear(&order_1);
    mp_clear(&one);
    return 1;
}

ECParams * mb_get_ec_params(ECCurveName curve, PLArenaPool * arena){
    if(arena == NULL){
        fprintf(stderr, "mb_get_ec_params: arena is NULL\n");
        return NULL;
    }

    ECParams * ecParams = (ECParams *) malloc(sizeof(ECParams));
    if(ecParams == NULL){
        fprintf(stderr, "mb_get_ec_params: alloc for ecParams failed\n");
        return NULL;
    } else {
        fprintf(stderr, "mb_get_ec_params: alloc for ecParams succeeded\n");
    }
    memset(ecParams, 0, sizeof(ECParams));

    SECItem ecEncodedParams = { siBuffer, NULL, 0 };
    SECStatus rv = SECU_ecName2params(curve, &ecEncodedParams);
    if (rv != SECSuccess) {
        fprintf(stderr, "mb_get_ec_params: SECU_ecName2params failed\n");
        return NULL;
    } else {
        fprintf(stderr, "mb_get_ec_params: SEC_ecName2params succeeded\n");
    }

    fprintf(stderr, "before EC_FillParams\n");
    EC_FillParams(arena, &ecEncodedParams, ecParams);
    fprintf(stderr, "after EC_FillParams\n");

    return ecParams;
}