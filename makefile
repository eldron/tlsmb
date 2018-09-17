OPENSSL_INCS_LOCATION=-I/home/work/Documents/openssl/include
OPENSSL_LIBS_LOCATION=-L/home/work/Documents/openssl

CFLAGS = $(OPENSSL_INCS_LOCATION)
LDFLAGS = $(OPENSSL_LIBS_LOCATION) -lssl -lcrypto

all: dec_ins ins dec_ins128 dec_ins20

dec_ins:
	gcc dec_ins.c inspection.c -o dec_ins $(CFLAGS) $(LDFLAGS)

ins:
	gcc ins.c inspection.c -o ins

dec_ins128:
	gcc dec_ins128.c inspection.c -o dec_ins128 $(CFLAGS) $(LDFLAGS)

dec_ins20:
	gcc dec_ins20.c inspection.c -o dec_ins20 $(CFLAGS) $(LDFLAGS)

clean:
	rm -f dec_ins
	rm -f ins
	rm -f dec_ins128
	rm -f dec_ins20