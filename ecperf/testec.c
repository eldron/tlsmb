#include "blapi.h"
#include "ec.h"
#include "ecl-curve.h"
#include "prprf.h"
#include "basicutil.h"
#include "pkcs11.h"
#include "nspr.h"
#include <stdio.h>
#include <dlfcn.h>

#include "mb_ec_util.h"


#define __PASTE(x, y) x##y

/*
 * Get the NSS specific PKCS #11 function names.
 */
#undef CK_PKCS11_FUNCTION_INFO
#undef CK_NEED_ARG_LIST

#define CK_EXTERN extern
#define CK_PKCS11_FUNCTION_INFO(func) \
    CK_RV __PASTE(NS, func)
#define CK_NEED_ARG_LIST 1

#include "pkcs11f.h"

typedef SECStatus (*op_func)(void *, void *, void *);
typedef SECStatus (*pk11_op_func)(CK_SESSION_HANDLE, void *, void *, void *);

typedef struct ThreadDataStr {
    op_func op;
    void *p1;
    void *p2;
    void *p3;
    int iters;
    PRLock *lock;
    int count;
    SECStatus status;
    int isSign;
} ThreadData;

void
PKCS11Thread(void *data)
{
    ThreadData *threadData = (ThreadData *)data;
    pk11_op_func op = (pk11_op_func)threadData->op;
    int iters = threadData->iters;
    unsigned char sigData[256];
    SECItem sig;
    CK_SESSION_HANDLE session;
    CK_RV crv;

    threadData->status = SECSuccess;
    threadData->count = 0;

    /* get our thread's session */
    PR_Lock(threadData->lock);
    crv = NSC_OpenSession(1, CKF_SERIAL_SESSION, NULL, 0, &session);
    PR_Unlock(threadData->lock);
    if (crv != CKR_OK) {
        return;
    }

    if (threadData->isSign) {
        sig.data = sigData;
        sig.len = sizeof(sigData);
        threadData->p2 = (void *)&sig;
    }

    while (iters--) {
        threadData->status = (*op)(session, threadData->p1,
                                   threadData->p2, threadData->p3);
        if (threadData->status != SECSuccess) {
            break;
        }
        threadData->count++;
    }
    return;
}

int main(int argc, char ** args){
    void * handle = NULL;
    char * error_string;
    handle = dlopen("libecutil.so", RTLD_LAZY);
    if(handle == NULL){
        fprintf(stderr, "dl open libecutil.so failed\n");
        return 1;
    }
    ECParams * (*func_mbgetecparams)(ECCurveName, PLArenaPool *);
    int (*func_fakeecgenprivatekey)(ECParams *, unsigned char *,
        unsigned char *, unsigned char ** , unsigned char ** );
    int(*func_genkeyformiddlebox)(ECParams *, SECItem *, unsigned char *, unsigned char **, unsigned char **);
    
    func_mbgetecparams = dlsym(handle, "mb_get_ec_params");
    if((error_string = dlerror()) != NULL){
        fprintf(stderr, "load function mb_get_ec_params failed\n");
    } else {
        fprintf(stderr, "laod function mb_get_ec_params succeeded\n");
    }

    func_fakeecgenprivatekey = dlsym(handle, "fake_ec_GenerateRandomPrivateKey");
    if((error_string = dlerror()) != NULL){
        fprintf(stderr, "load function fake_ec_GenerateRandomPrivateKey failede\n");
    } else {
        fprintf(stderr, "laod fake_ec_GenerateRandomPrivateKey succeeded\n");
    }

    func_genkeyformiddlebox = dlsym(handle, "generate_ec_private_key_for_middlebox");
    if((error_string = dlerror()) != NULL){
        fprintf(stderr, "load generate_ec_private_key_for_middlebox failed\n");
    } else {
        fprintf(stderr, "load generate_ec_private_key_for_middlebox succeeded\n");
    }

    SECStatus rv = SECSuccess;

    rv = RNG_RNGInit();
    if (rv != SECSuccess) {
        fprintf(stderr, "fuck you\n");
        SECU_PrintError("Error:", "RNG_RNGInit");
        return -1;
    }
    RNG_SystemInfoForRNG();

    rv = SECOID_Init();
    if (rv != SECSuccess) {
        SECU_PrintError("Error:", "SECOID_Init");
        return -1;
    }
    
    PLArenaPool * arena = PORT_NewArena(NSS_FREEBL_DEFAULT_CHUNKSIZE);
    if(arena == NULL){
        fprintf(stderr, "failed to alloc arena\n");
        return 1;
    } else {

    }

    unsigned char * private_key;
    unsigned char * public_key;
    int i;

    printf("testing 256\n");
    //ECParams * ecParams = mb_get_ec_params(ECCurve_NIST_P256, arena);
    ECParams * ecParams = func_mbgetecparams(ECCurve_NIST_P256, arena);
    if(ecParams){
        fprintf(stderr, "got ecparams\n");
    } else {
        fprintf(stderr, "get ecparams failed\n");
    }

    ECPrivateKey *ecPriv = NULL;
    rv = EC_NewKey(ecParams, &ecPriv);
    if (rv != SECSuccess) {
        fprintf(stderr, "EC_NewKey failed\n");
        return 1;
    } else {
        fprintf(stderr, "EC_NewKey succeeded\n");
    }

    // test generate fake key for client
    printf("testing generate fake key for client\n");
    //fake_ec_GenerateRandomPrivateKey(ecParams, NULL, ecPriv->privateValue.data, &private_key, &public_key);
    func_fakeecgenprivatekey(ecParams, NULL, ecPriv->privateValue.data, &private_key, &public_key);

    printf("generated fake private key is:\n");
    for(i = 0;i < ecPriv->privateValue.len;i++){
        printf("%u ", private_key[i]);
    }
    printf("\ngenerated fake public key is:\n");
    for(i = 0;i < ecPriv->publicValue.len;i++){
        printf("%u ", public_key[i]);
    }
    printf("\n");

    // test generate fake key for middlebox
    printf("testing generate fake key for middlebox\n");
    //generate_ec_private_key_for_middlebox(ecParams, &(ecPriv->publicValue), NULL, &private_key, &public_key);
    func_genkeyformiddlebox(ecParams, &(ecPriv->publicValue), NULL, &private_key, &public_key);

    printf("generated fake private key is:\n");
    for(i = 0;i < ecPriv->privateValue.len;i++){
        printf("%u ", private_key[i]);
    }
    printf("\ngenerated fake public key is:\n");
    for(i = 0;i < ecPriv->publicValue.len;i++){
        printf("%u ", public_key[i]);
    }
    printf("\n");

    printf("\ntesting 384\n");
    //ecParams = mb_get_ec_params(ECCurve_NIST_P384, arena);
    ecParams = func_mbgetecparams(ECCurve_NIST_P384, arena);
    ecPriv = NULL;
    rv = EC_NewKey(ecParams, &ecPriv);
    if (rv != SECSuccess) {
        fprintf(stderr, "EC_NewKey failed\n");
        return 1;
    } else {
        printf("EC_NewKey succeeded\n");
    }
    // test generate fake key for client
    printf("testing generate fake key for client\n");
    //fake_ec_GenerateRandomPrivateKey(ecParams, NULL, ecPriv->privateValue.data, &private_key, &public_key);
    func_fakeecgenprivatekey(ecParams, NULL, ecPriv->privateValue.data, &private_key, &public_key);

    printf("generated fake private key is:\n");
    for(i = 0;i < ecPriv->privateValue.len;i++){
        printf("%u ", private_key[i]);
    }
    printf("\ngenerated fake public key is:\n");
    for(i = 0;i < ecPriv->publicValue.len;i++){
        printf("%u ", public_key[i]);
    }
    printf("\n");

    // test generate fake key for middlebox
    printf("testing generate fake key for middlebox\n");
    //generate_ec_private_key_for_middlebox(ecParams, &(ecPriv->publicValue), NULL, &private_key, &public_key);
    func_genkeyformiddlebox(ecParams, &(ecPriv->publicValue), NULL, &private_key, &public_key);

    printf("generated fake private key is:\n");
    for(i = 0;i < ecPriv->privateValue.len;i++){
        printf("%u ", private_key[i]);
    }
    printf("\ngenerated fake public key is:\n");
    for(i = 0;i < ecPriv->publicValue.len;i++){
        printf("%u ", public_key[i]);
    }
    printf("\n");

    printf("testing 521\n");
    //ecParams = mb_get_ec_params(ECCurve_NIST_P521, arena);
    ecParams = func_mbgetecparams(ECCurve_NIST_P521, arena);

    ecPriv = NULL;
    rv = EC_NewKey(ecParams, &ecPriv);
    if (rv != SECSuccess) {
        fprintf(stderr, "EC_NewKey failed\n");
        return 1;
    } else {
        printf("succeeded\n");
    }
    // test generate fake key for client
    printf("testing generate fake key for client\n");
    //fake_ec_GenerateRandomPrivateKey(ecParams, NULL, ecPriv->privateValue.data, &private_key, &public_key);
    func_fakeecgenprivatekey(ecParams, NULL, ecPriv->privateValue.data, &private_key, &public_key);
    
    printf("generated fake private key is:\n");
    for(i = 0;i < ecPriv->privateValue.len;i++){
        printf("%u ", private_key[i]);
    }
    printf("\ngenerated fake public key is:\n");
    for(i = 0;i < ecPriv->publicValue.len;i++){
        printf("%u ", public_key[i]);
    }
    printf("\n");

    // test generate fake key for middlebox
    printf("testing generate fake key for middlebox\n");
    //generate_ec_private_key_for_middlebox(ecParams, &(ecPriv->publicValue), NULL, &private_key, &public_key);
    func_genkeyformiddlebox(ecParams, &(ecPriv->publicValue), NULL, &private_key, &public_key);
    
    printf("generated fake private key is:\n");
    for(i = 0;i < ecPriv->privateValue.len;i++){
        printf("%u ", private_key[i]);
    }
    printf("\ngenerated fake public key is:\n");
    for(i = 0;i < ecPriv->publicValue.len;i++){
        printf("%u ", public_key[i]);
    }
    printf("\n");

    printf("testing 25519\n");
    //ecParams = mb_get_ec_params(ECCurve25519, arena);
    ecParams = func_mbgetecparams(ECCurve25519, arena);
    ecPriv = NULL;
    rv = EC_NewKey(ecParams, &ecPriv);
    if (rv != SECSuccess) {
        fprintf(stderr, "EC_NewKey failed\n");
        return 1;
    } else {
        printf("succeeded\n");
    }
    // test generate fake key for client
    printf("testing generate fake key for client\n");
    //fake_ec_GenerateRandomPrivateKey(ecParams, NULL, ecPriv->privateValue.data, &private_key, &public_key);
    func_fakeecgenprivatekey(ecParams, NULL, ecPriv->privateValue.data, &private_key, &public_key);

    printf("generated fake private key is:\n");
    for(i = 0;i < ecPriv->privateValue.len;i++){
        printf("%u ", private_key[i]);
    }
    printf("\ngenerated fake public key is:\n");
    for(i = 0;i < ecPriv->publicValue.len;i++){
        printf("%u ", public_key[i]);
    }
    printf("\n");

    // test generate fake key for middlebox
    printf("testing generate fake key for middlebox\n");
    //generate_ec_private_key_for_middlebox(ecParams, &(ecPriv->publicValue), NULL, &private_key, &public_key);
    func_genkeyformiddlebox(ecParams, &(ecPriv->publicValue), NULL, &private_key, &public_key);
    
    printf("generated fake private key is:\n");
    for(i = 0;i < ecPriv->privateValue.len;i++){
        printf("%u ", private_key[i]);
    }
    printf("\ngenerated fake public key is:\n");
    for(i = 0;i < ecPriv->publicValue.len;i++){
        printf("%u ", public_key[i]);
    }
    printf("\n");
    
    printf("test ld libecutil.so succeeded\n");
    
    rv |= SECOID_Shutdown();
    RNG_RNGShutdown();
    if (rv != SECSuccess) {
        printf("Error: exiting with error value\n");
    }
    return rv;
}