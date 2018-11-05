OPENSSL_INCS_LOCATION=-I/home/work/Documents/openssl/include
OPENSSL_LIBS_LOCATION=-L/home/work/Documents/openssl

CFLAGS = $(OPENSSL_INCS_LOCATION)
LDFLAGS = $(OPENSSL_LIBS_LOCATION) -lssl -lcrypto

all: inspection

inspection:
	g++ -std=c++11 ClamavRule.cpp SnortRule.cpp StringMatch.cpp inspection.cpp -o inspection $(CFLAGS) $(LDFLAGS)

clean:
	rm inspection