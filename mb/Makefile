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
LD_PATHS=-L./ -L$(DIST_LD_PATH)
LD_DYNAMIC_LIBRARIES=-lfreebl3 -lnspr4 -lnsssysinit -lsmime3 -lfreeblpriv3 -lnss3 -lnssutil3 -lsoftokn3 -lgtest1 -lnssckbi -lplc4 -lsqlite3 -lgtestutil -lnssdbm3 -lplds4 -lssl3
LD_STATIC_LIBRARIES=-lfreebl -lcertdb -lcerthi -lcpputil -lcrmf -lcryptohi -ldbm  -lgtest -ljar -lnss -lnssb -lnssckfw -lnssdbm -lnssdev -lnsspki -lnssutil -lpk11wrap -lpkcs12 -lpkcs7 -lpkixcertsel -lpkixchecker -lpkixcrlsel -lpkixmodule -lpkixparams -lpkixpki -lpkixresults -lpkixstore -lpkixsystem -lpkixtop -lpkixutil -lsectool -lsmime -lsoftokn -lsqlite -lssl

MB_LD_STATIC_LIBRARIES=-lcertdb -lcerthi -lcpputil -lcrmf -lcryptohi -ldbm  -lgtest -ljar -lnss -lnssb -lnssckfw -lnssdbm -lnssdev -lnsspki -lnssutil -lpk11wrap -lpkcs12 -lpkcs7 -lpkixcertsel -lpkixchecker -lpkixcrlsel -lpkixmodule -lpkixparams -lpkixpki -lpkixresults -lpkixstore -lpkixsystem -lpkixtop -lpkixutil -lsectool -lsmime -lsoftokn -lsqlite -lssl

LD_SYSTEM_LIBRARIES=-lpthread -lm -ldl

all:mb
	echo "built all"

mb:mb.o mb_ec_util.o
	gcc $(LD_PATHS) -o mb mb.o mb_ec_util.o $(LD_STATIC_LIBRARIES) $(LD_DYNAMIC_LIBRARIES) -lfreeblpriv3 $(LD_SYSTEM_LIBRARIES)

mb.o:mb.c
	gcc $(INCLUDE_PATHS) -c mb.c

mb_ec_util.o:mb_ec_util.c
	gcc $(INCLUDE_PATHS) -c mb_ec_util.c

clean:
	rm -f mb
	rm *.o