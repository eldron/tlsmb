OPENSSL_INCS_LOCATION=-I/home/work/Documents/openssl/include
OPENSSL_LIBS_LOCATION=-L/home/work/Documents/openssl

CFLAGS = $(OPENSSL_INCS_LOCATION)
LDFLAGS = $(OPENSSL_LIBS_LOCATION) -lssl -lcrypto

all: dec_ins

dec_ins:
	gcc dec_ins.c inspection.c -o dec_ins $(CFLAGS) $(LDFLAGS)
