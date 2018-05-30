#include "blapi.h"
#include "prerr.h"
#include "secerr.h"
#include "secmpi.h"
#include "secitem.h"
#include "mplogic.h"
#include "ec.h"
#include "ecl.h"

// a_bytes: input
// a_value: input, integer value of a_bytes
// a_len: input, length of a_bytes
// pubkey: output
SECStatus my_ec_point_mul(PLArenaPool * arena, ECParams * ecParams, int a_len, mp_int * a_value,
    SECItem ** pubkey){
    
    SECStatus rv = SECFailure;
    mp_err err = MP_OKAY;
    //PLArenaPool *arena;
    ECPrivateKey *key;
    int len;
    // if (!(arena = PORT_NewArena(NSS_FREEBL_DEFAULT_CHUNKSIZE)))
    //     return SECFailure;

    key = (ECPrivateKey *)PORT_ArenaZAlloc(arena, sizeof(ECPrivateKey));
    if (!key) {
        PORT_FreeArena(arena, PR_TRUE);
        return SECFailure;
    }

    SECITEM_AllocItem(arena, &key->publicValue, EC_GetPointSize(ecParams));
    len = ecParams->order.len;
    SECITEM_AllocItem(arena, &key->privateValue, len);

    if(len != a_len){
        fprintf(stderr, "len != a_len, this should not happen\n");
    }
    /* Copy private key */
    mp_to_fixlen_octets(a_value, key->privateValue.data, len);
    
    /* Use curve specific code for point multiplication */
    if (ecParams->fieldID.type == ec_field_plain) {
        const ECMethod *method = ec_get_method_from_name(ecParams->name);
        if (method == NULL || method->mul == NULL) {
            /* unknown curve */
            return SECFailure;
        }
        rv = method->mul(&key->publicValue, &key->privateValue, NULL);
        *pubkey = &(key->publicValue);
        return SECSuccess;
    } else {
        rv = ec_points_mul(ecParams, &a_value, NULL, NULL, &(key->publicValue));
        if (rv != SECSuccess) {
            return SECFailure;
        } else {
            *pubkey = &(key->publicValue);
            return SECSuccess;
        }
    }
}

// generate a_{n+1}=H(g^(alpha*a_{n}))
// order: a buffer that holds the curve's group order
// len: the length in octets of the order buffer, also the length of the private key bytes buffer
// alpha_bytes: alpha, of length len
// prev_private_key_bytes: a_{n}
// new_private_key_bytes: a_{n + 1}
static unsigned char *
fake_ec_GenerateRandomPrivateKey(PLArenaPool * arena, ECParams * ecParams,
    const unsigned char *order, int len,
    unsigned char * alpha_bytes,
    unsigned char * prev_private_key_bytes, unsigned char * new_private_key_bytes)
{
    if(len != ecParams->order.len){
        fprintf(stderr, "len != ecParams->order.len, this should not happen\n");
        return SECFailure;
    }

    SECStatus rv = SECSuccess;
    mp_err err;
    unsigned char *privKeyBytes = NULL;
    mp_int privKeyVal, order_1, one;

    MP_DIGITS(&privKeyVal) = 0;
    MP_DIGITS(&order_1) = 0;
    MP_DIGITS(&one) = 0;
    CHECK_MPI_OK(mp_init(&privKeyVal));
    CHECK_MPI_OK(mp_init(&order_1));
    CHECK_MPI_OK(mp_init(&one));

    /* Generates 2*len random bytes using the global random bit generator
     * (which implements Algorithm 1 of FIPS 186-2 Change Notice 1) then
     * reduces modulo the group order.
     */
    if ((privKeyBytes = PORT_Alloc(2 * len)) == NULL)
        goto cleanup;
    //CHECK_SEC_OK(RNG_GenerateGlobalRandomBytes(privKeyBytes, 2 * len));

    // compute g^(alpha * a_{n})
    mp_int alpha_value;
    mp_int prev_private_key_value;
    CHECK_MPI_OK(mp_init(&alpha_value));
    CHECK_MPI_OK(mp_init(&prev_private_key_value));
    if(alpha_bytes){
        mp_read_unsigned_octets(&alpha_value, alpha_bytes, len);
    } else {
        mp_set_int(&alpha_value, 2);
    }
    CHECK_MPI_OK(mp_mul(&alpha_value, &prev_private_key_value, &alpha_value));
    SECItem * pubkey;
    my_ec_point_mul(arena, ecParams, len, &alpha_value, &pubkey);
    // hash pubkey to get a_{n+1}, 
    // we should only hash the corresponding part in the packet

    CHECK_MPI_OK(mp_read_unsigned_octets(&privKeyVal, privKeyBytes, 2 * len));
    CHECK_MPI_OK(mp_read_unsigned_octets(&order_1, order, len));
    CHECK_MPI_OK(mp_set_int(&one, 1));
    CHECK_MPI_OK(mp_sub(&order_1, &one, &order_1));
    CHECK_MPI_OK(mp_mod(&privKeyVal, &order_1, &privKeyVal));
    CHECK_MPI_OK(mp_add(&privKeyVal, &one, &privKeyVal));
    CHECK_MPI_OK(mp_to_fixlen_octets(&privKeyVal, privKeyBytes, len));
    memset(privKeyBytes + len, 0, len);
cleanup:
    mp_clear(&privKeyVal);
    mp_clear(&order_1);
    mp_clear(&one);
    if (err < MP_OKAY) {
        MP_TO_SEC_ERROR(err);
        rv = SECFailure;
    }
    if (rv != SECSuccess && privKeyBytes) {
        PORT_ZFree(privKeyBytes, 2 * len);
        privKeyBytes = NULL;
    }
    return privKeyBytes;
}