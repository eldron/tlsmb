// aes256gcm decryption traffic, then perform inspection

#include <openssl/bio.h>
#include <openssl/evp.h>

#include "inspection.h"

// big endian conversion
uint64_t bytes_to_uint64t(unsigned char * buf){
    uint64_t value = 0;
    int i = 0;
    for(i = 0;i < 8;i++){
        value = value | (((uint64_t) buf[i]) << ((7 - i) * 8));
    }
    return value;
}

// big endian conversion
void uint64t_to_bytes(uint64_t value, unsigned char * buf){
    int i;
    for(i = 0;i < 8;i++){
        buf[i] = (value >> ((7 - i) * 8)) & 0x00000000000000ff;
    }

    // printf("sequence number bytes are:\n");
    // BIO_dump_fp(stdout, buf, 8);
}

void get_nonce(uint64_t * number, unsigned char * nonce, unsigned char * static_iv){
    unsigned char tmp[12];
    memset(tmp, 0, 12);
    uint64t_to_bytes(*number, tmp + 4);
    (*number)++;

    int i;
    for(i = 0;i < 12;i++){
        nonce[i] = tmp[i] ^ static_iv[i];
    }
}

int main(int argc, char ** args){
    if(argc != 4){
		fprintf(stderr, "usage: %s rule_type rule_file number_of_rules\n", args[0]);
		exit(1);
	}

	int rule_type = atoi(args[1]);
	char * rule_file = args[2];
	int number_of_rules = atoi(args[3]);

    if(number_of_rules > 0){
	    initialize_mem_pool();
    }
	fprintf(stderr, "mem pool initialized\n");

	struct rule_inspect ins;
    if(number_of_rules > 0){
	    initialize_rule_inspect(rule_type, &ins, rule_file, number_of_rules);
    }

    int server_sock;
	if((server_sock = socket(AF_UNIX, SOCK_STREAM, 0)) < 0){
		perror("create unix server socket failed");
		exit(1);
	} else {
		fprintf(stderr, "created server socket\n");
	}

	struct sockaddr_un server_address;
	server_address.sun_family = AF_UNIX;
	strcpy(server_address.sun_path, SERVER_ADDRESS);
	unlink(SERVER_ADDRESS);
	int server_address_len = sizeof(server_address.sun_family) + strlen(server_address.sun_path);
	if(bind(server_sock, &server_address, server_address_len) < 0){
		perror("bind unix server socket failed");
		exit(1);
	} else {
		fprintf(stderr, "bind server socket\n");
	}

	if(listen(server_sock, 5) < 0){
		perror("listen failed");
		exit(1);
	} else {
		fprintf(stderr, "server socket listening\n");
	}

	int client_sock;
	struct sockaddr_un client_address;
	int client_address_len;
	if((client_sock = accept(server_sock, &client_address, &client_address_len)) < 0){
		perror("accept failed");
		exit(1);
	} else {
		fprintf(stderr, "accepted client socket\n");
	}
	// we use stdio to read the socket
	FILE * fin = fdopen(client_sock, "r");

    unsigned char key[16];
    unsigned char static_iv[12];
    unsigned char seqnum[8];
    int len;
    len = fread(key, 1, 16, fin);
    if(len != 32){
        printf("read key failed\n");
    } else {
        printf("read key succeeded\n");
    }
    len = fread(static_iv, 1, 12, fin);
    if(len != 12){
        printf("read iv failed\n");
    } else {
        printf("read iv succeeded\n");
    }

    len = fread(seqnum, 1, 8, fin);
    if(len != 8){
        printf("read seqnum failed\n");
    } else {
        printf("read seqnum secceeded\n");
    }
    uint64_t sequence_number = bytes_to_uint64t(seqnum);
    printf("seq number = %ul\n", sequence_number);
    
    EVP_CIPHER_CTX *ctx;
    ctx = EVP_CIPHER_CTX_new();
    /* Select cipher */
    EVP_DecryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, NULL, NULL);
    /* Set IV length, omit for 96 bits */
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, 12, NULL);

    unsigned char record[1000000];// TLSCiphertext 
    unsigned char header[5];
    unsigned char nonce[12];
    unsigned char outbuf[1000000];
    int outlen;
    int rv;
    int offset = 0;
    unsigned char matched_reply[1];
	matched_reply[0] = 1;
	unsigned char no_match_reply[1];
	no_match_reply[0] = 0;

    while(1){
        len = fread(header, 1, 1, fin);
        if(len == 1){
            //printf("received opaque type\n");
        } else {
            printf("receive opaque type failed, len = %d\n", len);
        }
        unsigned char opaque_type = header[0];
        if(opaque_type == 23){
            //printf("opaque type correct\n");
        } else {
            printf("opaque type wrong\n");
        }

        len = fread(header + 1, 1, 2, fin);
        if(len == 2){
            //printf("read version succeeded\n");
        } else {
            printf("read version failed, len = %d\n", len);
        }
        unsigned int version = (header[1] << 8) | header[2];
        if(version == 0x0303){

        } else {
            printf("version is not 0x0303\n");
        }

        len = fread(header + 3, 1, 2, fin);
        if(len == 2){
            //printf("read length succeeded\n");
        } else {
            printf("read length failed, len = %d\n", len);
        }
        unsigned int ciphertext_len = (header[3] << 8) | header[4];
        
        len = fread(record, 1, ciphertext_len, fin);
        if(len == ciphertext_len){
            //printf("read encrypted record succeeded\n");
        } else {
            printf("read encrypted record failed, len = %d, ciphertext len = %d\n", len, ciphertext_len);
            return 0;
        }
        unsigned char * gcmtag = record + (len - 16);

        get_nonce(&sequence_number, nonce, static_iv);
        //printf("sequence number = %ul\n", sequence_number);
        /* Specify key and nonce */
        EVP_DecryptInit_ex(ctx, NULL, NULL, key, nonce);
        /* Zero or more calls to specify any AAD */
        EVP_DecryptUpdate(ctx, NULL, &outlen, header, 5);
        /* Decrypt plaintext */
        EVP_DecryptUpdate(ctx, outbuf, &outlen, record, len - 16);

        // perform inspection on the decrypted data
        while(outbuf[outlen - 1] == 0){
            outlen--;
        }
        outlen--;

        if(number_of_rules > 0){
            int i;
            for(i = 0;i < outlen;i++){
                ac_inspect(rule_type, ins.states, &(ins.global_state_number), outbuf[i], offset, &(ins.matched_rules));
                offset++;
            }
        }
        if(ins.matched_rules){
			send(client_sock, matched_reply, 1, 0);
		} else {
			send(client_sock, no_match_reply, 1, 0);
		}

        /* Set expected tag value. */
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, 16, gcmtag);
        /* Finalise: note get no output for GCM */
        rv = EVP_DecryptFinal_ex(ctx, outbuf, &outlen);
        if(rv){
            //printf("decryption secceeded\n");
        } else {
            printf("decryption failed\n");
        }
    }
}

// int main(int argc, char ** args){
// 	if(argc != 4){
// 		fprintf(stderr, "usage: %s rule_type rule_file number_of_rules\n", args[0]);
// 		exit(1);
// 	}

// 	int rule_type = atoi(args[1]);
// 	char * rule_file = args[2];
// 	int number_of_rules = atoi(args[3]);
// 	initialize_mem_pool();
// 	fprintf(stderr, "mem pool initialized\n");

// 	struct rule_inspect ins;
// 	initialize_rule_inspect(rule_type, &ins, rule_file, number_of_rules);

// 	int server_sock;
// 	if((server_sock = socket(AF_UNIX, SOCK_STREAM, 0)) < 0){
// 		perror("create unix server socket failed");
// 		exit(1);
// 	} else {
// 		fprintf(stderr, "created server socket\n");
// 	}

// 	struct sockaddr_un server_address;
// 	server_address.sun_family = AF_UNIX;
// 	strcpy(server_address.sun_path, SERVER_ADDRESS);
// 	unlink(SERVER_ADDRESS);
// 	int server_address_len = sizeof(server_address.sun_family) + strlen(server_address.sun_path);
// 	if(bind(server_sock, &server_address, server_address_len) < 0){
// 		perror("bind unix server socket failed");
// 		exit(1);
// 	} else {
// 		fprintf(stderr, "bind server socket\n");
// 	}

// 	if(listen(server_sock, 5) < 0){
// 		perror("listen failed");
// 		exit(1);
// 	} else {
// 		fprintf(stderr, "server socket listening\n");
// 	}

// 	int client_sock;
// 	struct sockaddr_un client_address;
// 	int client_address_len;
// 	if((client_sock = accept(server_sock, &client_address, &client_address_len)) < 0){
// 		perror("accept failed");
// 		exit(1);
// 	} else {
// 		fprintf(stderr, "accepted client socket\n");
// 	}
// 	// we use stdio to read the socket
// 	FILE * fin = fdopen(client_sock, "r");
// 	int data_len;
// 	int offset = 0;
// 	unsigned char token;
// 	int i;
// 	unsigned char matched_reply[1];
// 	matched_reply[0] = 1;
// 	unsigned char no_match_reply[1];
// 	no_match_reply[0] = 0;

// 	unsigned char buffer[20000];
// 	while(1){
// 		// read data_len
// 		int high = fgetc(fin);
// 		int low = fgetc(fin);
// 		data_len = (high << 8) | low;
// 		fprintf(stderr, "data_len = %d\n", data_len);
// 		if(data_len > 0){
// 			// read data, perform inspection, send back result
// 			// for(i = 0;i < data_len;i++){
// 			// 	token = (unsigned char) fgetc(fin);
// 			// 	ac_inspect(rule_type, ins.states, &(ins.global_state_number), token, offset, &(ins.matched_rules));
// 			// }
// 			int len = fread(buffer, 1, data_len, fin);
// 			for(i = 0;i < len;i++){
//                 token = buffer[i];
// 				ac_inspect(rule_type, ins.states, &(ins.global_state_number), token, offset, &(ins.matched_rules));
// 				offset++;
// 			}
// 			if(ins.matched_rules){
// 				send(client_sock, matched_reply, 1, 0);
// 			} else {
// 				send(client_sock, no_match_reply, 1, 0);
// 			}
// 		} else {
// 			break;
// 		}
// 	}

// 	close(server_sock);
// 	return 0;
// }