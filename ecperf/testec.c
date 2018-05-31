#include "blapi.h"
#include "ec.h"
#include "ecl-curve.h"
#include "prprf.h"
#include "basicutil.h"
#include "pkcs11.h"
#include "nspr.h"

#include "mb_ec_util.h"

#include <stdio.h>

int main(){
    const char * nist256name = "NIST-P256";
    const char * nist384name = "NIST-P384";
    const char * nist521name = "NIST-P521";
    const char * name25519 = "Curve25519";

    PLArenaPool * arena = PORT_NewArena(NSS_FREEBL_DEFAULT_CHUNKSIZE);
    if(arena == NULL){
        fprintf(stderr, "failed to alloc arena\n");
        return 1;
    }

    printf("testing %s\n", nist256name);
    ECParams * ecParams = mb_get_ec_params(ECCurve_NIST_P256, arena);
    ECPrivateKey *ecPriv = NULL;
    SECStatus rv = EC_NewKey(ecParams, &ecPriv);
    if (rv != SECSuccess) {
        fprintf(stderr, "EC_NewKey failed\n");
        return 1;
    }

    printf("testing %s\n", nist384name);
    ecParams = mb_get_ec_params(ECCurve_NIST_P384, arena);
    ecPriv = NULL;
    rv = EC_NewKey(ecParams, &ecPriv);
    if (rv != SECSuccess) {
        fprintf(stderr, "EC_NewKey failed\n");
        return 1;
    }

    printf("testing %s\n", nist521name);
    ecParams = mb_get_ec_params(ECCurve_NIST_P521, arena);
    ecPriv = NULL;
    rv = EC_NewKey(ecParams, &ecPriv);
    if (rv != SECSuccess) {
        fprintf(stderr, "EC_NewKey failed\n");
        return 1;
    }

    printf("testing %s\n", name25519);
    ecParams = mb_get_ec_params(ECCurve25519, arena);
    ecPriv = NULL;
    rv = EC_NewKey(ecParams, &ecPriv);
    if (rv != SECSuccess) {
        fprintf(stderr, "EC_NewKey failed\n");
        return 1;
    }

    return 0;
}