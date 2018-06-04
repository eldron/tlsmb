#include "mb_parse_tls_13.h"

#define TLS_1_3_DRAFT_VERSION 28

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
                      PRUint32 *length){

    if ((PRUint32)bytes > *length) {
        fprintf(stderr, "ssl3_ConsumeHandshake: bytes larger than length\n");
        return SECFailure;
    }
    PORT_Memcpy(v, *b, bytes);
    *b += bytes;
    *length -= bytes;
    return SECSuccess;
}
/* Read up the next "bytes" number of bytes from the (decrypted) input
 * stream "b" (which is *length bytes long), and interpret them as an
 * integer in network byte order.  Sets *num to the received value.
 * Reduces *length by bytes.  Advances *b by bytes.
 *
 * On error, an alert has been sent, and a generic error code has been set.
 */
SECStatus
ssl3_ConsumeHandshakeNumber64(PRUint64 *num, PRUint32 bytes,
                              PRUint8 **b, PRUint32 *length)
{
    PRUint8 *buf = *b;
    PRUint32 i;
    *num = 0;
    if (bytes > sizeof(*num)) {
        //PORT_SetError(SEC_ERROR_LIBRARY_FAILURE);
        fprintf(stderr, "ssl3_ConsumeHandshakeNumber64: bytes larger than size of *num\n");
        return SECFailure;
    }

    if (bytes > *length) {
        fprintf(stderr, "ssl3_ConsumeHandshakeNumber64: bytes larger than *length\n");
        return SECFailure;
    }

    for (i = 0; i < bytes; i++) {
        *num = (*num << 8) + buf[i];
    }
    *b += bytes;
    *length -= bytes;
    return SECSuccess;
}

SECStatus
ssl3_ConsumeHandshakeNumber(PRUint32 *num, PRUint32 bytes,
                            PRUint8 **b, PRUint32 *length)
{
    PRUint64 num64;
    SECStatus rv;

    PORT_Assert(bytes <= sizeof(*num));
    if (bytes > sizeof(*num)) {
        fprintf(stderr, "ssl3_ConsumeHandshakeNumber: bytes larger than *num\n");
        return SECFailure;
    }
    rv = ssl3_ConsumeHandshakeNumber64(&num64, bytes, b, length);
    if (rv != SECSuccess) {
        return SECFailure;
    }
    *num = num64 & 0xffffffff;
    return SECSuccess;
}
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
                              PRUint8 **b, PRUint32 *length)
{
    PRUint32 count;
    SECStatus rv;

    PORT_Assert(bytes <= 3);
    i->len = 0;
    i->data = NULL;
    i->type = siBuffer;
    rv = ssl3_ConsumeHandshakeNumber(&count, bytes, b, length);
    if (rv != SECSuccess) {
        return SECFailure;
    }
    if (count > 0) {
        if (count > *length) {
            fprintf(stderr, "ssl3_ConsumeHandshakeVariable: count larger than *length\n");
            return SECFailure;
        }
        i->data = *b;
        i->len = count;
        *b += count;
        *length -= count;
    }
    return SECSuccess;
}

char * get_ext_name(uint16_t type){
    switch(type){
        case ssl_server_name_xtn:// defined in sslt.h
        return "server_name_xtn";
        case ssl_cert_status_xtn:
        return "cert_status_xtn";
        case ssl_supported_groups_xtn:
            return "supported_groups_xtn";
        case ssl_ec_point_formats_xtn:
            return "ec_point_formats_xtn";
        case ssl_signature_algorithms_xtn:
            return "signature_algorithms_xtn";
        case ssl_use_srtp_xtn:
            return "use_srtp_xtn";
        case ssl_app_layer_protocol_xtn:
            return "app_layer_protocol_xtn";
        case ssl_signed_cert_timestamp_xtn:
            return "signed_cert_timestamp_xtn";
        case ssl_padding_xtn:
            return "padding_xtn";
        case ssl_extended_master_secret_xtn:
            return "extended_master_secret_xtn";
        case ssl_session_ticket_xtn:
            return  "session_ticket_xtn";
        case ssl_tls13_pre_shared_key_xtn:
            return "tls13_pre_shared_key_xtn";
        case ssl_tls13_early_data_xtn:
            return "tls13_early_data_xtn";
        case ssl_tls13_supported_versions_xtn:
            return "tls13_supported_versions_xtn";
        case ssl_tls13_cookie_xtn:
            return "tls13_cookie_xtn";
        case ssl_tls13_psk_key_exchange_modes_xtn:
            return "tls13_psk_key_exchange_modes_xtn";
        case ssl_tls13_ticket_early_data_info_xtn:
            return "tls13_ticket_early_data_info_xtn";
        case ssl_tls13_certificate_authorities_xtn:
            return "tls13_certificate_authorities_xtn";
        case ssl_signature_algorithms_cert_xtn:
            return "signautre_algorithms_cert";
        case ssl_tls13_key_share_xtn:
            return "tls13_key_share_xtn";
        case ssl_next_proto_nego_xtn:
            return "next_proto_nego_xtn";
        case ssl_renegotiation_info_xtn:
            return "renegotiation_info_xtn";
        case ssl_tls13_short_header_xtn:
            return "tls13_short_header_xtn";
        default:
            return "unknown extension";
    }

    return "unknown extension";
}

void print_extensions(PRCList * ext_list){
    PRCList * cursor;
    for(cursor = PR_NEXT_LINK(ext_list); cursor != ext_list; cursor = PR_NEXT_LINK(cursor)){
        TLSExtension * ext = (TLSExtension *) cursor;
        printf("type is %u %s, length is %u\n", ext->type, get_ext_name(ext->type), ext->data.len);
    }
}

char * get_psk_exhange_mode_name(uint8_t mode){
    if(mode == 0){
        return "psk_ke psk-only key establishment";
    } else if(mode == 1){
        return "psk_dhe_ke with (EC)DHE key establishment";
    } else {
        return "illegal psk exchange mode";
    }
}

TLSExtension * find_extension(PRCList * extensions_list, SSLExtensionType extension_type){
    PRCList * cursor;
    for(cursor = PR_NEXT_LINK(extensions_list); cursor != extensions_list; cursor = PR_NEXT_LINK(cursor)){
        TLSExtension * extension = (TLSExtension *) cursor;
        if(extension->type == extension_type){
            return extension;
        }
    }
}

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
                      PRUint32 *length)
{
    PORT_Assert(ss->opt.noLocks || ssl_HaveRecvBufLock(ss));
    PORT_Assert(ss->opt.noLocks || ssl_HaveSSL3HandshakeLock(ss));

    if ((PRUint32)bytes > *length) {
        fprintf(stderr, "ssl3_ConsumeHandshake: bytes larger than *length\n");
        return SECFailure;
    }
    PORT_Memcpy(v, *b, bytes);
    *b += bytes;
    *length -= bytes;
    return SECSuccess;
}

// parse server hello
// *buffer should point to legacy_version
// the HelloRetryRequest message uses the same struct reu as the ServerHello, but with random
// set to the special value of the SHA-256 of "HelloRetryRequest"
// upon receiving a message with type server_hello, client needs to examine the random value
// and see if it matches this value
SECStatus parse_server_hello(struct server_hello_str * server_hello,
    PRUint8 ** buffer, PRUint32 * length){
        uint32_t legacy_version;
        SECStatus rv;
        rv = ssl3_ConsumeHandshakeNumber(&legacy_version, 2, buffer, length);// legacy_version consumes 2 bytes
        if(rv == SECFailure){
            fprintf(stderr, "parse_server_hello: error reading legacy_version");
            return rv;
        }
        server_hello->legacy_version = (uint16_t) legacy_version;

        server_hello->random = *buffer;// random consumes 32 bytes
        *buffer += 32;
        *length -= 32;

        // legacy_session_id length consumes 1 byte
        rv = ssl3_ConsumeHandshakeVariable(&(server_hello->legacy_session_id), 1, buffer, length);
        if(rv == SECFailure){
            fprintf(stderr, "parse_server_hello: error reading legacy_session_id\n");
            return rv;
        }

        uint32_t cipher_suit;
        // cipher_suit consumes 2 bytes
        rv = ssl3_ConsumeHandshakeNumber(&cipher_suit, 2, buffer, length);
        if(rv == SECFailure){
            fprintf(stderr, "parse_server_hello: error reading cipher_suit\n");
            return rv;
        }
        server_hello->cipher_suit = (uint16_t) cipher_suit;

        uint32_t legacy_compression_method;
        // legacy_compression_method consumes 1 byte
        rv = ssl3_ConsumeHandshakeNumber(&legacy_compression_method, 1, buffer, length);
        if(rv == SECFailure){
            fprintf(stderr, "parse_server_hello: error reading legacy_compression_method\n");
            return rv;
        }
        server_hello->legacy_compression_method = (uint8_t) legacy_compression_method;

        // extensions length consumes 2 bytes
        rv = ssl3_ConsumeHandshakeVariable(&(server_hello->extensions), 2, buffer, length);
        if(rv == SECFailure){
            fprintf(stderr, "parse_server_hello: error reading extensions\n");
            return rv;
        }
        // parse extensions, link them together
        PR_INIT_CLIST(&(server_hello->ext_list));
        PRUint8 * buf = server_hello->extensions.data;
        PRUint32 len = server_hello->extensions.len;
        while(len > 0){
            TLSExtension * ext = (TLSExtension *) malloc(sizeof(TLSExtension));
            uint32_t type;
            rv = ssl3_ConsumeHandshakeNumber(&type, 2, &buf, &len);// extension type consumes 2 bytes
            if(rv == SECFailure){
                fprintf(stderr, "parse_server_hello: error reading extension type\n");
                return rv;
            }
            ext->type = (PRUint16) type;
            rv = ssl3_ConsumeHandshakeVariable(&(ext->data), 2, &buf, &len);
            if(rv == SECFailure){
                fprintf(stderr, "parse_server_hello: error reading extension content\n");
                return rv;
            }
            PR_APPEND_LINK(&(ext->link), &(server_hello->ext_list));
        }

        return SECSuccess;
}
// parse client hello
// *buffer should point to legacy_version
SECStatus parse_client_hello(struct client_hello_str * client_hello,
    PRUint8 ** buffer, PRUint32 * length){
        uint32_t legacy_version;
        ssl3_ConsumeHandshakeNumber(&legacy_version, 2, buffer, length);// legacy version consumes 2 bytes
        client_hello->legacy_version = (uint16_t) legacy_version;
        client_hello->random = *buffer;// random consumes 32 bytes
        *buffer += 32;
        *length -= 32;
        SECStatus rv;
        rv = ssl3_ConsumeHandshakeVariable(&(client_hello->legacy_session_id), 1, buffer, length);
        if(rv == SECFailure){
            fprintf(stderr, "parse_client_hello: error reading legacy_session_id\n");
            return rv;
        }
        rv = ssl3_ConsumeHandshakeVariable(&(client_hello->cipher_suits), 2, buffer, length);
        if(rv == SECFailure){
            fprintf(stderr, "parse_client_hello: error reading cipher_suits\n");
            return rv;
        }
        rv = ssl3_ConsumeHandshakeVariable(&(client_hello->legacy_compression_methods), 1, buffer, length);
        if(rv == SECFailure){
            fprintf(stderr, "parse_client_hello: error reading legacy_compression_methods\n");
            return rv;
        }
        rv = ssl3_ConsumeHandshakeVariable(&(client_hello->extensions), 2, buffer, length);
        if(rv == SECFailure){
            fprintf(stderr, "parse_client_hello: error reading extensions\n");
            return rv;
        }
        // parse extensions, link them together
        PR_INIT_CLIST(&(client_hello->ext_list));
        PRUint8 * buf = client_hello->extensions.data;
        PRUint32 len = client_hello->extensions.len;
        while(len > 0){
            TLSExtension * ext = (TLSExtension *) malloc(sizeof(TLSExtension));
            uint32_t type;
            rv = ssl3_ConsumeHandshakeNumber(&type, 2, &buf, &len);// extension type consumes 2 bytes
            if(rv == SECFailure){
                fprintf(stderr, "parse_client_hello: error reading extension type\n");
                return rv;
            }
            ext->type = (PRUint16) type;
            rv = ssl3_ConsumeHandshakeVariable(&(ext->data), 2, &buf, &len);
            if(rv == SECFailure){
                fprintf(stderr, "parse_client_hello: error reading extension content\n");
                return rv;
            }
            PR_APPEND_LINK(&(ext->link), &(client_hello->ext_list));
        }

        return SECSuccess;
}

/* Go through hello extensions in |b| and deserialize
 * them into the list in |ss->ssl3.hs.remoteExtensions|.
 * The only checking we do in this point is for duplicates.
 *
 * IMPORTANT: This list just contains pointers to the incoming
 * buffer so they can only be used during ClientHello processing.
 */
// *length equals to the length of all extensions
// *length is read from *b before the function is called
SECStatus
ssl3_ParseExtensions(PRCList * ext_list, PRUint8 **b, PRUint32 *length)
{
    // /* Clean out the extensions list. */
    // ssl3_DestroyRemoteExtensions(&ss->ssl3.hs.remoteExtensions);

    while (*length) {
        SECStatus rv;
        PRUint32 extension_type;
        SECItem extension_data = { siBuffer, NULL, 0 };
        TLSExtension *extension;
        PRCList *cursor;

        /* Get the extension's type field */
        rv = ssl3_ConsumeHandshakeNumber(&extension_type, 2, b, length);
        if (rv != SECSuccess) {
            return SECFailure; /* alert already sent */
        }

        // SSL_TRC(10, ("%d: SSL3[%d]: parsing extension %d",
        //              SSL_GETPID(), ss->fd, extension_type));
        /* Check whether an extension has been sent multiple times. */
        for (cursor = PR_NEXT_LINK(ext_list);
             cursor != ext_list;
             cursor = PR_NEXT_LINK(cursor)) {
            if (((TLSExtension *)cursor)->type == extension_type) {
                fprintf(stderr, "extension %s has been sent multiple times\n", get_ext_name(extension_type));
                return SECFailure;
            }
        }

        /* Get the data for this extension, so we can pass it or skip it. */
        rv = ssl3_ConsumeHandshakeVariable(&extension_data, 2, b, length);
        if (rv != SECSuccess) {
            return rv; /* alert already sent */
        }

        extension = PORT_ZNew(TLSExtension);// this needs to be modified
        if (!extension) {
            return SECFailure;
        }

        extension->type = (PRUint16)extension_type;
        extension->data = extension_data;
        PR_APPEND_LINK(&extension->link, ext_list);
    }

    return SECSuccess;
}

SECStatus parse_record(PRUint8 ** buffer, PRUint32 len, uint8_t * content_type, 
    uint32_t * handshake_type, void ** content_struct){

        //fprintf(stderr, "parse_record called\n");

        SECStatus rv;
        //fprintf(stderr, "fuck you\n");
        *content_type = (uint8_t) (*buffer)[0];// content type consumes 1 byte
        //fprintf(stderr, "fuck you again\n");
        //fprintf(stderr, "parse_record: content_type is %u\n", *content_type);

        *buffer += 3;// legacy record version consumes 2 bytes
        uint16_t * ptr = (uint16_t *) (*buffer);
        uint32_t length = ntohs(*ptr);
        //fprintf(stderr, "parse_record: content length = %u\n", length);
        *buffer += 2;// length field consumes 2 bytes
        if(length > (len - 5)){
            fprintf(stderr, "parse_record error, length larger than (len - 5)\n");
            return SECFailure;
        } else {
            if(*content_type == content_handshake){
                //fprintf(stderr, "parse_record: content type is content_handshake\n");
                PRUint32 msg_type;
                PRUint32 handshake_length;
                ssl3_ConsumeHandshakeNumber(&msg_type, 1, buffer, &length);// handshake type consumes 1 byte
                ssl3_ConsumeHandshakeNumber(&handshake_length, 3, buffer, &length);// handshake length consumes 3 bytes
                if(msg_type == ssl_hs_client_hello/* defined in sslt.h*/){
                    // parse client hello
                    //fprintf(stderr, "parse_record: parsing client hello\n");
                    *handshake_type = msg_type;
                    struct client_hello_str * client_hello = (struct client_hello_str *) malloc(sizeof(struct client_hello_str));
                    rv = parse_client_hello(client_hello, buffer, &handshake_length);
                    *content_struct = client_hello;
                    if(rv == SECFailure){
                        fprintf(stderr, "parse_record: error parse_client_hello\n");
                    }
                    return rv;
                } else if (msg_type == ssl_hs_server_hello){
                    // parse server hello
                    *handshake_type = msg_type;
                    struct server_hello_str * server_hello = (struct server_hello_str *) malloc(sizeof(struct server_hello_str));
                    rv = parse_server_hello(server_hello, buffer, &handshake_length);
                    if(rv == SECFailure){
                        fprintf(stderr, "parse_record: error parse_server_hello\n");
                    }
                    *content_struct = server_hello;
                    return rv;
                } else {
                    fprintf(stderr, "parse_record: unimplemented handshake type\n");
                    return SECSuccess;
                }
            } else {
                fprintf(stderr, "parse_record: unimplemented content type\n");
                return SECFailure;
            }
        }
}

PRUint16
tls13_EncodeDraftVersion(SSL3ProtocolVersion version)
{
#ifdef TLS_1_3_DRAFT_VERSION
    if (version == SSL_LIBRARY_VERSION_TLS_1_3) {
        return 0x7f00 | TLS_1_3_DRAFT_VERSION;
    }
#endif
    return (PRUint16)version;
}

SECStatus
tls13_ClientReadSupportedVersion(PRCList * ext_list)
{
    PRUint32 temp;
    PRUint16 v;
    TLSExtension *versionExtension;
    SECItem it;
    SECStatus rv;

    /* Update the version based on the extension, as necessary. */
    //versionExtension = ssl3_FindExtension(ss, ssl_tls13_supported_versions_xtn);
    versionExtension = find_extension(ext_list, ssl_tls13_supported_versions_xtn);
    if (!versionExtension) {
        return SECSuccess;
    }

    /* Struct copy so we don't damage the extension. */
    it = versionExtension->data;

    rv = ssl3_ConsumeHandshakeNumber(&temp, 2, &it.data, &it.len);
    if (rv != SECSuccess) {
        return SECFailure;
    }
    if (it.len) {
        //FATAL_ERROR(ss, SSL_ERROR_RX_MALFORMED_SERVER_HELLO, illegal_parameter);
        fprintf(stderr, "tls13_ClientReadSupportedVersion: received malformed server hello\n");
        return SECFailure;
    }
    v = (SSL3ProtocolVersion)temp;

    /* You cannot negotiate < TLS 1.3 with supported_versions. */
    if (v < SSL_LIBRARY_VERSION_TLS_1_3) {
        //FATAL_ERROR(ss, SSL_ERROR_RX_MALFORMED_SERVER_HELLO, illegal_parameter);
        fprintf(stderr, "tls13_ClientReadSupportedVersion: received malformed server hello\n");
        return SECFailure;
    }

#ifdef TLS_1_3_DRAFT_VERSION
    if (temp == SSL_LIBRARY_VERSION_TLS_1_3) {
        //FATAL_ERROR(ss, SSL_ERROR_UNSUPPORTED_VERSION, protocol_version);
        fprintf(stderr, "tls13_ClientReadSupportedVersion: unsupported version\n");
        return SECFailure;
    }
    if (temp == tls13_EncodeDraftVersion(SSL_LIBRARY_VERSION_TLS_1_3)) {
        v = SSL_LIBRARY_VERSION_TLS_1_3;
    } else {
        v = (SSL3ProtocolVersion)temp;
    }
#else
    v = (SSL3ProtocolVersion)temp;
#endif

    ss->version = v;
    return SECSuccess;
}

int is_hello_retry(struct server_hello_str * server_hello){
    int result = memcmp(server_hello->random, ssl_hello_retry_random, 32);
    return result == 0;
}

void print_SECItem(SECItem * item){
    int i;
    printf("item length is %u\n", item->len);
    for(i = 0;i < item->len;i++){
        uint8_t value = (uint8_t) item->data[i];
        printf("%u ", value);
    }
    printf("\n");
}
// called when middlebox received server hello
// buffer now points to the record layer
SECStatus compute_handshake_secrets_from_server_hello(struct MBTLSConnection * conn, 
    uint8_t * buffer, uint32_t length){

    SECStatus rv = ssl3_HandleServerHello(conn->ss, buffer + 5, length - 5);
    if(rv == SECFailure){
        fprintf(stderr, "compute handshake secrets: ssl3_HandleServerHello failed\n");
        return rv;
    }

    fprintf(stderr, "computed master secret is:\n");
    printSECItem(conn->ss->ssl3.hs.currentSecret->data);
    // calculated master secret
    // we still need to calculate client_application_traffic_secret_0
    // server_application_traffic_secret_0
    // exporter_master_secret
    // and resumption_master_secret

    return rv;
}

// caled when middlebox received client hello
// buffer now points to the record layer
// we should maintain the state indicating whether we are responding to a client hello retry
// the caller should chck the client hello is a tls 1.3 client hello
// the caller should set type to client_hello_retry or client_hello_initial
// the caller is reponsible for setting sid for conn->ss
// if we set client to not use stateless resumption, caller should set ss->sec.ci.sid = NULL,
// and ss->opt.noCache = PR_TRUE
SECStatus set_ss_from_client_hello(struct MBTLSConnection * conn, 
    sslClientHelloType type, uint8_t * buffer, uint32_t length){
    
    // we don't need to consider fall back SCSV
    sslSocket * ss = conn->ss;
    ss->sec.isServer = PR_FALSE;
    SECStatus rv = ssl_CheckConfigSanity(ss);
    if (rv != SECSuccess){
        fprintf(stderr, "ssl_CheckConfigSanity failed\n");
    }
    
    ss->vrange.max = SSL_LIBRARY_VERSION_TLS_1_3;// or encoded 
    sslSessionID *sid;
    SECStatus rv;
    unsigned int i;
    unsigned int length;
    unsigned int num_suites;
    unsigned int actual_count = 0;
    PRBool isTLS = PR_TRUE;
    PRBool requestingResume = PR_FALSE, fallbackSCSV = PR_FALSE;
    PRBool unlockNeeded = PR_FALSE;
    sslBuffer extensionBuf = SSL_BUFFER_EMPTY;
    PRUint16 version = conn->ss->vrange.max;
    PRInt32 flags;
    unsigned int cookieLen = conn->ss->ssl3.hs.cookie.len;

    /* shouldn't get here if SSL3 is disabled, but ... */
    if (SSL_ALL_VERSIONS_DISABLED(&ss->vrange)) {
        fprintf(stderr, "no versions of SSL 3.0 or later are enabled\n");
        return SECFailure;
    }

    /* If there's an sid set from an external cache, use it. */
    if (ss->sec.ci.sid && ss->sec.ci.sid->cached == in_external_cache) {
        sid = ss->sec.ci.sid;
        SSL_TRC(3, ("%d: SSL[%d]: using external token", SSL_GETPID(), ss->fd));
    } else if (!ss->opt.noCache) {
        /* Try to find server in our session-id cache */
        sid = ssl_LookupSID(&ss->sec.ci.peer, ss->sec.ci.port, ss->peerID,
                            ss->url);
    }
    if (sid) {
        if (sid->version >= ss->vrange.min && sid->version <= ss->vrange.max) {
            // this should matter
            //PORT_Assert(!ss->sec.localCert);
            //ss->sec.localCert = CERT_DupCertificate(sid->localCert);
        } else {
            ssl_UncacheSessionID(ss);
            ssl_FreeSID(sid);
            sid = NULL;
        }
    }
    if (!sid) {
        sid = PORT_ZNew(sslSessionID);
        if (!sid) {
            goto loser;
        }
        sid->references = 1;
        sid->cached = never_cached;
        sid->addr = ss->sec.ci.peer;
        sid->port = ss->sec.ci.port;
        // we may need to modify this
        if (ss->peerID != NULL) {
            sid->peerID = PORT_Strdup(ss->peerID);
        }
        if (ss->url != NULL) {
            sid->urlSvrName = PORT_Strdup(ss->url);
        }
    }
    ss->sec.ci.sid = sid;
    ss->gs.state = GS_INIT;

    /* If we are responding to a HelloRetryRequest, don't reinitialize. We need
     * to maintain the handshake hashes. */
    // type should never be retransmit or renegotiation, only client_hello_retry
    // or client_hello_initial
    if(type == client_hello_retry){
        ss->ssl3.hs.helloRetry = PR_TRUE;
        cookieLen = 0;
    } else {
        ss->ssl3.hs.helloRetry = PR_FALSE;
        ssl3_RestartHandshakeHashes(ss);
    }

    if (type == client_hello_initial) {
        ssl_SetClientHelloSpecVersion(ss, ss->ssl3.cwSpec);
    }
    /* These must be reset every handshake. */
    ssl3_ResetExtensionData(&ss->xtnData, ss);
    ss->ssl3.hs.sendingSCSV = PR_FALSE;// fallbackSCSV and sendingSCSV are always not set in TLS 1.3
    ss->ssl3.hs.preliminaryInfo = 0;
    PORT_Assert(IS_DTLS(ss) || type != client_hello_retransmit);
    SECITEM_FreeItem(&ss->ssl3.hs.newSessionTicket.ticket, PR_FALSE);
    ss->ssl3.hs.receivedNewSessionTicket = PR_FALSE;
    /* How many suites does our PKCS11 support (regardless of policy)? */
    if (ssl3_config_match_init(ss) == 0) {
        fprintf(stderr, "ssl3_config_match_init failed\n");
        return SECFailure; /* ssl3_config_match_init has set error code. */
    }

    ss->firstHsDone = PR_FALSE;// renegotiation is not allowed in TlS 1.3
    /*
     * During a renegotiation, ss->clientHelloVersion will be used again to
     * work around a Windows SChannel bug. Ensure that it is still enabled.
     */
    if (ss->firstHsDone) {
        PORT_Assert(type != client_hello_initial);
        if (SSL_ALL_VERSIONS_DISABLED(&ss->vrange)) {
            PORT_SetError(SSL_ERROR_SSL_DISABLED);
            return SECFailure;
        }

        if (ss->clientHelloVersion < ss->vrange.min ||
            ss->clientHelloVersion > ss->vrange.max) {
            PORT_SetError(SSL_ERROR_NO_CYPHER_OVERLAP);
            return SECFailure;
        }
    }

    // the caller is reponsible for setting sid
    /* Check if we have a ss->sec.ci.sid.
     * Check that it's not expired.
     * If we have an sid and it comes from an external cache, we use it. */
    if (ss->sec.ci.sid && ss->sec.ci.sid->cached == in_external_cache) {
        PORT_Assert(!ss->sec.isServer);
        sid = ss->sec.ci.sid;
        SSL_TRC(3, ("%d: SSL3[%d]: using external resumption token in ClientHello",
                    SSL_GETPID(), ss->fd));
    } else if (!ss->opt.noCache) {
        /* We ignore ss->sec.ci.sid here, and use ssl_Lookup because Lookup
         * handles expired entries and other details.
         * XXX If we've been called from ssl_BeginClientHandshake, then
         * this lookup is duplicative and wasteful.
         */
        sid = ssl_LookupSID(&ss->sec.ci.peer, ss->sec.ci.port, ss->peerID, ss->url);
    } else {
        sid = NULL;
    }

    /* We can't resume based on a different token. If the sid exists,
     * make sure the token that holds the master secret still exists ...
     * If we previously did client-auth, make sure that the token that holds
     * the private key still exists, is logged in, hasn't been removed, etc.
     */
    if (sid) {
        PRBool sidOK = PR_TRUE;
        const ssl3CipherSuiteCfg *suite;

        /* Check that the cipher suite we need is enabled. */
        suite = ssl_LookupCipherSuiteCfg(sid->u.ssl3.cipherSuite,
                                         ss->cipherSuites);
        PORT_Assert(suite);
        if (!suite || !config_match(suite, ss->ssl3.policy, &ss->vrange, ss)) {
            sidOK = PR_FALSE;
        }

        /* Check that we can recover the master secret. */
        if (sidOK) {
            PK11SlotInfo *slot = NULL;
            if (sid->u.ssl3.masterValid) {
                slot = SECMOD_LookupSlot(sid->u.ssl3.masterModuleID,
                                         sid->u.ssl3.masterSlotID);
            }
            if (slot == NULL) {
                sidOK = PR_FALSE;
            } else {
                PK11SymKey *wrapKey = NULL;
                if (!PK11_IsPresent(slot) ||
                    ((wrapKey = PK11_GetWrapKey(slot,
                                                sid->u.ssl3.masterWrapIndex,
                                                sid->u.ssl3.masterWrapMech,
                                                sid->u.ssl3.masterWrapSeries,
                                                ss->pkcs11PinArg)) == NULL)) {
                    sidOK = PR_FALSE;
                }
                if (wrapKey)
                    PK11_FreeSymKey(wrapKey);
                PK11_FreeSlot(slot);
                slot = NULL;
            }
        }
        /* If we previously did client-auth, make sure that the token that
        ** holds the private key still exists, is logged in, hasn't been
        ** removed, etc.
        */
       // suppose we don't do client auth
        // if (sidOK && !ssl3_ClientAuthTokenPresent(sid)) {
        //     sidOK = PR_FALSE;
        // }

        if (sidOK) {
            /* Set version based on the sid. */
            if (ss->firstHsDone) {
                /*
                 * Windows SChannel compares the client_version inside the RSA
                 * EncryptedPreMasterSecret of a renegotiation with the
                 * client_version of the initial ClientHello rather than the
                 * ClientHello in the renegotiation. To work around this bug, we
                 * continue to use the client_version used in the initial
                 * ClientHello when renegotiating.
                 *
                 * The client_version of the initial ClientHello is still
                 * available in ss->clientHelloVersion. Ensure that
                 * sid->version is bounded within
                 * [ss->vrange.min, ss->clientHelloVersion], otherwise we
                 * can't use sid.
                 */
                if (sid->version >= ss->vrange.min &&
                    sid->version <= ss->clientHelloVersion) {
                    version = ss->clientHelloVersion;
                } else {
                    sidOK = PR_FALSE;
                }
            } else {
                /*
                 * Check sid->version is OK first.
                 * Previously, we would cap the version based on sid->version,
                 * but that prevents negotiation of a higher version if the
                 * previous session was reduced (e.g., with version fallback)
                 */
                if (sid->version < ss->vrange.min ||
                    sid->version > ss->vrange.max) {
                    sidOK = PR_FALSE;
                }
            }
        }

        if (!sidOK) {
            SSL_AtomicIncrementLong(&ssl3stats.sch_sid_cache_not_ok);
            ssl_UncacheSessionID(ss);
            ssl_FreeSID(sid);
            sid = NULL;
        }
    }

    if (sid) {
        requestingResume = PR_TRUE;
        SSL_AtomicIncrementLong(&ssl3stats.sch_sid_cache_hits);

        PRINT_BUF(4, (ss, "client, found session-id:", sid->u.ssl3.sessionID,
                      sid->u.ssl3.sessionIDLength));

        ss->ssl3.policy = sid->u.ssl3.policy;
    } else {
        SSL_AtomicIncrementLong(&ssl3stats.sch_sid_cache_misses);

        /*
         * Windows SChannel compares the client_version inside the RSA
         * EncryptedPreMasterSecret of a renegotiation with the
         * client_version of the initial ClientHello rather than the
         * ClientHello in the renegotiation. To work around this bug, we
         * continue to use the client_version used in the initial
         * ClientHello when renegotiating.
         */
        if (ss->firstHsDone) {
            version = ss->clientHelloVersion;
        }

        sid = ssl3_NewSessionID(ss, PR_FALSE);
        if (!sid) {
            return SECFailure; /* memory error is set */
        }
        /* ss->version isn't set yet, but the sid needs a sane value. */
        sid->version = version;
    }

    isTLS = (version > SSL_LIBRARY_VERSION_3_0);
    ssl_GetSpecWriteLock(ss);
    if (ss->ssl3.cwSpec->macDef->mac == ssl_mac_null) {
        /* SSL records are not being MACed. */
        ss->ssl3.cwSpec->version = version;
    }
    ssl_ReleaseSpecWriteLock(ss);

    if (ss->sec.ci.sid != NULL) {
        ssl_FreeSID(ss->sec.ci.sid); /* decrement ref count, free if zero */
    }
    ss->sec.ci.sid = sid;

    /* When we attempt session resumption (only), we must lock the sid to
     * prevent races with other resumption connections that receive a
     * NewSessionTicket that will cause the ticket in the sid to be replaced.
     * Once we've copied the session ticket into our ClientHello message, it
     * is OK for the ticket to change, so we just need to make sure we hold
     * the lock across the calls to ssl_ConstructExtensions.
     */
    if (sid->u.ssl3.lock) {
        unlockNeeded = PR_TRUE;
        PR_RWLock_Rlock(sid->u.ssl3.lock);
    }

    if (ss->vrange.max >= SSL_LIBRARY_VERSION_TLS_1_3 &&
        type == client_hello_initial) {
        //rv = tls13_SetupClientHello(ss);
        // we read client hello and set corresponding values in ss
        if (rv != SECSuccess) {
            goto loser;
        }
    }
    if (isTLS || (ss->firstHsDone && ss->peerRequestedProtection)) {
        //rv = ssl_ConstructExtensions(ss, &extensionBuf, ssl_hs_client_hello);
        // we read client hello and set corresponding values in ss
        if (rv != SECSuccess) {
            goto loser;
        }
    }

    /* how many suites are permitted by policy and user preference? */
    //num_suites = count_cipher_suites(ss, ss->ssl3.policy);
    // we read num_suites from client hello
    if (!num_suites) {
        goto loser; /* count_cipher_suites has set error code. */
    }

    length = sizeof(SSL3ProtocolVersion) + SSL3_RANDOM_LENGTH +
             1 + /* session id */
             2 + num_suites * sizeof(ssl3CipherSuite) +
             1 + 1 /* compression methods */;
    if (sid->version < SSL_LIBRARY_VERSION_TLS_1_3) {
        length += sid->u.ssl3.sessionIDLength;
    } else if (ss->opt.enableTls13CompatMode && !IS_DTLS(ss)) {
        length += SSL3_SESSIONID_BYTES;
    }

    if (extensionBuf.len) {
        rv = ssl_InsertPaddingExtension(ss, length, &extensionBuf);
        if (rv != SECSuccess) {
            goto loser; /* err set by ssl_InsertPaddingExtension */
        }
        length += 2 + extensionBuf.len;
    }

    rv = ssl3_AppendHandshakeHeader(ss, ssl_hs_client_hello, length);
    if (rv != SECSuccess) {
        goto loser; /* err set by ssl3_AppendHandshake* */
    }

    ss->clientHelloVersion = PR_MIN(version, SSL_LIBRARY_VERSION_TLS_1_2);
    rv = ssl3_AppendHandshakeNumber(ss, ss->clientHelloVersion, 2);

    /* Generate a new random if this is the first attempt. */
    // we read random from client hello and set the cooresponding values
    if (type == client_hello_initial) {
        rv = ssl3_GetNewRandom(ss->ssl3.hs.client_random);
        if (rv != SECSuccess) {
            goto loser; /* err set by GetNewRandom. */
        }
    }
    rv = ssl3_AppendHandshake(ss, ss->ssl3.hs.client_random,
                              SSL3_RANDOM_LENGTH);
    if (rv != SECSuccess) {
        goto loser; /* err set by ssl3_AppendHandshake* */
    }

    // we read sessionID from client hello and set ss
    if (sid->version < SSL_LIBRARY_VERSION_TLS_1_3) {
        // this should not happen
        rv = ssl3_AppendHandshakeVariable(
            ss, sid->u.ssl3.sessionID, sid->u.ssl3.sessionIDLength, 1);
    } else if (ss->opt.enableTls13CompatMode && !IS_DTLS(ss)) {
        /* We're faking session resumption, so rather than create new
         * randomness, just mix up the client random a little. */
        PRUint8 buf[SSL3_SESSIONID_BYTES];
        ssl_MakeFakeSid(ss, buf);
        rv = ssl3_AppendHandshakeVariable(ss, buf, SSL3_SESSIONID_BYTES, 1);
    } else {
        rv = ssl3_AppendHandshakeNumber(ss, 0, 1);
    }
    if (rv != SECSuccess) {
        goto loser; /* err set by ssl3_AppendHandshake* */
    }

    rv = ssl3_AppendHandshakeNumber(ss, num_suites * sizeof(ssl3CipherSuite), 2);
    if (rv != SECSuccess) {
        goto loser; /* err set by ssl3_AppendHandshake* */
    }

    // we read cipher suits from client hello and set ss
    for (i = 0; i < ssl_V3_SUITES_IMPLEMENTED; i++) {
        ssl3CipherSuiteCfg *suite = &ss->cipherSuites[i];
        if (config_match(suite, ss->ssl3.policy, &ss->vrange, ss)) {
            actual_count++;
            if (actual_count > num_suites) {
                /* set error card removal/insertion error */
                PORT_SetError(SSL_ERROR_TOKEN_INSERTION_REMOVAL);
                goto loser;
            }
            rv = ssl3_AppendHandshakeNumber(ss, suite->cipher_suite,
                                            sizeof(ssl3CipherSuite));
            if (rv != SECSuccess) {
                goto loser; /* err set by ssl3_AppendHandshake* */
            }
        }
    }

    /* Compression methods: count is always 1, null compression. */
    // we may not need to modify this
    rv = ssl3_AppendHandshakeNumber(ss, 1, 1);
    if (rv != SECSuccess) {
        goto loser; /* err set by ssl3_AppendHandshake* */
    }
    rv = ssl3_AppendHandshakeNumber(ss, ssl_compression_null, 1);
    if (rv != SECSuccess) {
        goto loser; /* err set by ssl3_AppendHandshake* */
    }

    // we read psk binders from client hello and set ss
    if (extensionBuf.len) {
        /* If we are sending a PSK binder, replace the dummy value.  Note that
         * we only set statelessResume on the client in TLS 1.3. */
        if (ss->statelessResume &&
            ss->xtnData.sentSessionTicketInClientHello) {
            rv = tls13_WriteExtensionsWithBinder(ss, &extensionBuf);
        } else {
            rv = ssl3_AppendBufferToHandshakeVariable(ss, &extensionBuf, 2);
        }
        if (rv != SECSuccess) {
            goto loser; /* err set by AppendHandshake. */
        }
    }

    sslBuffer_Clear(&extensionBuf);
    if (unlockNeeded) {
        /* Note: goto loser can't be used past this point. */
        PR_RWLock_Unlock(sid->u.ssl3.lock);
    }

    // we read session ticket from client hello and set ss
    if (ss->xtnData.sentSessionTicketInClientHello) {
        SSL_AtomicIncrementLong(&ssl3stats.sch_sid_stateless_resumes);
    }

    // modify this
    flags = 0;
    rv = ssl3_FlushHandshake(ss, flags);
    if (rv != SECSuccess) {
        return rv; /* error code set by ssl3_FlushHandshake */
    }

    // we read early data from client hello and set ss
    if (version >= SSL_LIBRARY_VERSION_TLS_1_3) {
        rv = tls13_MaybeDo0RTTHandshake(ss);
        if (rv != SECSuccess) {
            return SECFailure; /* error code set already. */
        }
    }

    ss->ssl3.hs.ws = wait_server_hello;
    return SECSuccess;

    // we should not need this goto
loser:
    if (unlockNeeded) {
        PR_RWLock_Unlock(sid->u.ssl3.lock);
    }
    sslBuffer_Clear(&extensionBuf);
    return SECFailure;
}