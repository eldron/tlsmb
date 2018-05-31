INCLUDE_FREEBL_PATH=../nss/lib/freebl/
INCLUDE_UTIL_PATH=../nss/lib/util
INCLUDE_PR_PATH=../nspr/pr/include
DIST_INCLUDE_PATH=../dist/Linux4.15_x86_64_cc_glibc_PTH_64_DBG.OBJ/include/
DIST_PUBLIC_NSS_PATH=../dist/public/nss
DIST_PRIVATE_NSS_PATH=../dist/private/nss
DIST_LD_PATH=../dist/Linux4.15_x86_64_cc_glibc_PTH_64_DBG.OBJ/lib

INCLUDE_PATHS=-I$(INCLUDE_FREEBL_PATH) -I$(INCLUDE_UTIL_PATH) -I$(INCLUDE_PR_PATH) -I$(DIST_INCLUDE_PATH) -I$(DIST_PUBLIC_NSS_PATH) -I$(DIST_PRIVATE_NSS_PATH)
LD_PATHS=-L$(DIST_LD_PATH)
LD_DYNAMIC_LIBRARIES=-lfreebl3 -lnspr4 -lnsssysinit -lsmime3 -lfreeblpriv3 -lnss3 -lnssutil3 -lsoftokn3 -lgtest1 -lnssckbi -lplc4 -lsqlite3 -lgtestutil -lnssdbm3 -lplds4 -lssl3
LD_STATIC_LIBRARIES=-lcertdb -lcerthi -lcpputil -lcrmf -lcryptohi -ldbm -lfreebl -lgtest -ljar -lnss -lnssb -lnssckfw -lnssdbm -lnssdev -lnsspki -lnssutil -lpk11wrap -lpkcs12 -lpkcs7 -lpkixcertsel -lpkixchecker -lpkixcrlsel -lpkixmodule -lpkixparams -lpkixpki -lpkixresults -lpkixstore -lpkixsystem -lpkixtop -lpkixutil -lsectool -lsmime -lsoftokn -lsqlite -lssl
LD_SYSTEM_LIBRARIES=-lpthread -lm -ldl

all:ecperf testec
	echo "built all"

ecperf:ecperf.c
	gcc $(INCLUDE_PATHS) $(LD_PATHS) ecperf.c -o ecperf $(LD_STATIC_LIBRARIES) $(LD_DYNAMIC_LIBRARIES) $(LD_SYSTEM_LIBRARIES)

testec:
	gcc $(INCLUDE_PATHS) $(LD_PATHS) testec.c fake_ec.c -o testec $(LD_STATIC_LIBRARIES) $(LD_DYNAMIC_LIBRARIES) $(LD_SYSTEM_LIBRARIES)

clean:
	rm -f ecperf
	rm -f testec


