NSS_INCLUDE_PATH=./original_nss_lib/dist/public/nss
NSPR_INCLUDE_PATH=./original_nss_lib/dist/Debug/include/nspr
NSPR_LIBRARY_PATH=./original_nss_lib/dist/Debug/lib
FREEBL_INCLUDE_PATH=./nss/lib/freebl
MODIFIED_LIBRARY_PATH=./dist/Debug/lib
LINK_FLAGS=-lfreebl3 -lnssckbi -lplc4 -lsqlite3 -lfreeblpriv3 -lnssdbm3 -lplds4 -lssl3 -lnspr4 -lnsssysinit -lsmime3 -lnss3 -lnssutil3 -lsoftokn3

all:client server simple_tls_client simple_tls_server
	echo 'built all'

client:client.c sslsample.c
	gcc client.c sslsample.c -I$(NSS_INCLUDE_PATH) -I$(NSPR_INCLUDE_PATH) -I$(FREEBL_INCLUDE_PATH) -L$(NSPR_LIBRARY_PATH) $(LINK_FLAGS) -o client

server:server.c sslsample.c
	gcc server.c sslsample.c -I$(NSS_INCLUDE_PATH) -I$(NSPR_INCLUDE_PATH) -I$(FREEBL_INCLUDE_PATH) -L$(NSPR_LIBRARY_PATH) $(LINK_FLAGS) -o server

#mb:mb.c
#	gcc mb.c -lpthread -o mb

simple_tls_client:
	gcc simple_tls_client.c sslsample.c -I$(NSS_INCLUDE_PATH) -I$(NSPR_INCLUDE_PATH) -I$(FREEBL_INCLUDE_PATH) -L$(MODIFIED_LIBRARY_PATH) $(LINK_FLAGS) -o simple_tls_client

simple_tls_server:
	gcc simple_tls_server.c sslsample.c -I$(NSS_INCLUDE_PATH) -I$(NSPR_INCLUDE_PATH) -I$(FREEBL_INCLUDE_PATH) -L$(NSPR_LIBRARY_PATH) $(LINK_FLAGS) -o simple_tls_server

clean:
	rm -f mb
	rm -f client
	rm -f server
	rm -f simple_tls_client
	rm -f simple_tls_server
