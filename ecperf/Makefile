INCLUDE_FREEBL_PATH=../nss/lib/freebl/
INCLUDE_MPI_PATH=../nss/lib/freebl/mpi/
INCLUDE_ECL_PATH=../nss/lib/freebl/ecl/
INCLUDE_UTIL_PATH=../nss/lib/util
INCLUDE_PR_PATH=../nspr/pr/include
DIST_INCLUDE_PATH=../dist/Linux4.15_x86_64_cc_glibc_PTH_64_DBG.OBJ/include/
DIST_PUBLIC_NSS_PATH=../dist/public/nss
DIST_PRIVATE_NSS_PATH=../dist/private/nss
DIST_LD_PATH=../dist/Linux4.15_x86_64_cc_glibc_PTH_64_DBG.OBJ/lib

INCLUDE_PATHS=-I$(INCLUDE_FREEBL_PATH) -I$(INCLUDE_UTIL_PATH) -I$(INCLUDE_PR_PATH) -I$(DIST_INCLUDE_PATH) -I$(DIST_PUBLIC_NSS_PATH) -I$(DIST_PRIVATE_NSS_PATH) -I$(INCLUDE_MPI_PATH) -I$(INCLUDE_ECL_PATH)
LD_PATHS=-L$(DIST_LD_PATH)
LD_DYNAMIC_LIBRARIES=-lfreebl3 -lnspr4 -lnsssysinit -lsmime3 -lfreeblpriv3 -lnss3 -lnssutil3 -lsoftokn3 -lgtest1 -lnssckbi -lplc4 -lsqlite3 -lgtestutil -lnssdbm3 -lplds4 -lssl3
LD_STATIC_LIBRARIES=-lfreebl -lcertdb -lcerthi -lcpputil -lcrmf -lcryptohi -ldbm  -lgtest -ljar -lnss -lnssb -lnssckfw -lnssdbm -lnssdev -lnsspki -lnssutil -lpk11wrap -lpkcs12 -lpkcs7 -lpkixcertsel -lpkixchecker -lpkixcrlsel -lpkixmodule -lpkixparams -lpkixpki -lpkixresults -lpkixstore -lpkixsystem -lpkixtop -lpkixutil -lsectool -lsmime -lsoftokn -lsqlite -lssl

MB_LD_STATIC_LIBRARIES=-lcertdb -lcerthi -lcpputil -lcrmf -lcryptohi -ldbm  -lgtest -ljar -lnss -lnssb -lnssckfw -lnssdbm -lnssdev -lnsspki -lnssutil -lpk11wrap -lpkcs12 -lpkcs7 -lpkixcertsel -lpkixchecker -lpkixcrlsel -lpkixmodule -lpkixparams -lpkixpki -lpkixresults -lpkixstore -lpkixsystem -lpkixtop -lpkixutil -lsectool -lsmime -lsoftokn -lsqlite -lssl

LD_SYSTEM_LIBRARIES=-lpthread -lm -ldl

EXTERNAL_OBJECTS=aeskeywrap.o blake2b.o curve25519_64.o ecl_gf.o ecp_256.o fipsfreebl.o Hacl_Poly1305_64.o mpi_amd64.o rawhash.o shvfy.o aes-x86.o blinit.o desblapi.o ecl_mult.o ecp_384.o freeblver.o hmacct.o md2.o mpi.o rijndael.o stubs.o alg2268.o camellia.o des.o ecl.o ecp_521.o gcm.o intel-aes.o md5.o mplogic.o rsa.o sysrand.o alghmac.o chacha20poly1305.o dh.o ec_naf.o ecp_aff.o gcm-x86.o intel-gcm.o mp_comba.o mpmontg.o rsapkcs.o tlsprfalg.o arcfive.o crypto_primitives.o drbg.o ec.o ecp_jac.o Hacl_Chacha20.o intel-gcm-wrap.o mpcpucache.o mpprime.o seed.o arcfour-amd64-gas.o ctr.o dsa.o ecp_25519.o ecp_jm.o Hacl_Chacha20_Vec128.o jpake.o mp_gf2m.o sha512.o arcfour.o cts.o ecdecode.o ecp_256_32.o ecp_mont.o Hacl_Curve25519.o ldvector.o mpi_amd64_gas.o pqg.o sha_fast.o

all:ecperf testec
	echo "built all"

ecperf:ecperf.o
	gcc $(LD_PATHS) ecperf.o -o ecperf $(LD_STATIC_LIBRARIES)  $(LD_DYNAMIC_LIBRARIES) $(LD_SYSTEM_LIBRARIES)

testec:testec.o fake_ec.o
	gcc $(LD_PATHS) testec.o fake_ec.o $(EXTERNAL_OBJECTS) -o testec $(MB_LD_STATIC_LIBRARIES) $(LD_DYNAMIC_LIBRARIES) -lfreeblpriv3 $(LD_SYSTEM_LIBRARIES)

ecperf.o:ecperf.c
	gcc $(INCLUDE_PATHS) -c ecperf.c

testec.o:testec.c
	gcc $(INCLUDE_PATHS) -c testec.c

fake_ec.o:fake_ec.c
	gcc $(INCLUDE_PATHS) -c fake_ec.c

clean:
	rm -f ecperf
	rm -f testec


