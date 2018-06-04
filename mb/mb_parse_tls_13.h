#ifndef __mb_parse_tls_13_h
#define __mb_parse_tls_13_h

#include "nss/lib/ssl/sslimpl.h"
#include "sslt.h" // /nss/lib/ssl/sslt.h
#include "prclist.h"

// later we should replace malloc with customized memory management functions


const PRUint8 ssl_hello_retry_random[] = {
    0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11,
    0xBE, 0x1D, 0x8C, 0x02, 0x1E, 0x65, 0xB8, 0x91,
    0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB, 0x8C, 0x5E,
    0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8, 0x33, 0x9C
};

// TLSExtension copied from nss/lib/ssl/ssl3ext.h
typedef struct TLSExtensionStr {
    PRCList link;  /* The linked list link */
    PRUint16 type; /* Extension type */
    SECItem data;  /* Pointers into the handshake data. */
} TLSExtension;

// copird from nss/lib/ssl/ssl3prot.h
typedef enum {
    content_change_cipher_spec = 20,
    content_alert = 21,
    content_handshake = 22,
    content_application_data = 23,
    content_alt_handshake = 24,
    content_ack = 25
} SSL3ContentType;

struct server_hello_str{
    uint16_t legacy_version;// should be 0x0303 (tls 1.2), consumes 2 bytes
    uint8_t * random;// random consumes 32 bytes
    SECItem legacy_session_id;// <0..32> length field consumes 1 byte
    uint16_t cipher_suit;// consumes 2 bytes
    uint8_t legacy_compression_method;// consume 1 byte, should be 0
    SECItem extensions;// <6..2^16-1>, length field consumes 2 bytes
    PRCList ext_list;// link the TLSExtensions together
};

struct client_hello_str{
    uint16_t legacy_version;// should be 0x0303 (tls 1.2), consumes 2 bytes
    uint8_t * random;// random consumes 32 bytes
    SECItem legacy_session_id;// <0..32> lenght field consumes 1 byte
    SECItem cipher_suits;// <2..2^16-2> length field consumes 2 bytes, each cipher suit consumes 2 bytes
    SECItem legacy_compression_methods;// <1..2^8-1> length field consumes 1 byte
    SECItem extensions;// <8..2^16-1> length field consumes 2 bytes
    PRCList ext_list;// link the TLSExtensions to this list
};

// consume handshake functions copied from ssl3cons.c
/* Read up the next "bytes" number of bytes from the (decrypted) input
 * stream "b" (which is *length bytes long). Copy them into buffer "v".
 * Reduces *length by bytes.  Advances *b by bytes.
 *
 * If this function returns SECFailure, it has already sent an alert,
 * and has set a generic error code.  The caller should probably
 * override the generic error code by setting another.
 */
SECStatus
ssl3_ConsumeHandshake(void *v, PRUint32 bytes, PRUint8 **b,
                      PRUint32 *length);
/* Read up the next "bytes" number of bytes from the (decrypted) input
 * stream "b" (which is *length bytes long), and interpret them as an
 * integer in network byte order.  Sets *num to the received value.
 * Reduces *length by bytes.  Advances *b by bytes.
 *
 * On error, an alert has been sent, and a generic error code has been set.
 */
SECStatus
ssl3_ConsumeHandshakeNumber64(PRUint64 *num, PRUint32 bytes,
                              PRUint8 **b, PRUint32 *length);

SECStatus
ssl3_ConsumeHandshakeNumber(PRUint32 *num, PRUint32 bytes,
                            PRUint8 **b, PRUint32 *length);

/* Read in two values from the incoming decrypted byte stream "b", which is
 * *length bytes long.  The first value is a number whose size is "bytes"
 * bytes long.  The second value is a byte-string whose size is the value
 * of the first number received.  The latter byte-string, and its length,
 * is returned in the SECItem i.
 *
 * Returns SECFailure (-1) on failure.
 * On error, an alert has been sent, and a generic error code has been set.
 *
 * RADICAL CHANGE for NSS 3.11.  All callers of this function make copies
 * of the data returned in the SECItem *i, so making a copy of it here
 * is simply wasteful.  So, This function now just sets SECItem *i to
 * point to the values in the buffer **b.
 */
SECStatus
ssl3_ConsumeHandshakeVariable(SECItem *i, PRUint32 bytes,
                              PRUint8 **b, PRUint32 *length);

char * get_ext_name(uint16_t type);

void print_extensions(PRCList * ext_list);

char * get_psk_exhange_mode_name(uint8_t mode);

TLSExtension * find_extension(PRCList * extensions_list, SSLExtensionType extension_type);

// parse server hello
// *buffer should point to legacy_version
// the HelloRetryRequest message uses the same struct reu as the ServerHello, but with random
// set to the special value of the SHA-256 of "HelloRetryRequest"
// upon receiving a message with type server_hello, client needs to examine the random value
// and see if it matches this value
SECStatus parse_server_hello(struct server_hello_str * server_hello,
    PRUint8 ** buffer, PRUint32 * length);
// parse client hello
// *buffer should point to legacy_version
SECStatus parse_client_hello(struct client_hello_str * client_hello,
    PRUint8 ** buffer, PRUint32 * length);

SECStatus parse_record(PRUint8 ** buffer, PRUint32 len, uint8_t * content_type, 
    uint32_t * handshake_type, void ** content_struct);

int is_hello_retry(struct server_hello_str * server_hello);

typedef enum{
    // initial state, waiting for client hello
    // when received client hello, jump to state mb_wait_server_hello
    mb_wait_client_hello,

    // wait for server hello
    // when received server hello, jump to state mb_handshake_done
    // when received hello retry, jump to state mb_wait_client_hello
    mb_wait_server_hello,

    // handshake is done
    mb_handshake_done
} MBState;

struct MBTLSConnection{
    MBState state;
    int client_socket_fd;
    int server_socket_fd;

    struct client_hello_str * client_hello;
    struct server_hello_str * server_hello;

    // compute and store master secret, early_traffic_secret, traffic_secret, etc
    sslSocket * ss;
};
#endif