#include <openssl/bio.h>
#include <openssl/evp.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <iostream>
#include <vector>

#include "ACState.h"
#include "SnortRule.h"
#include "SnortContent.h"
#include "ClamavRule.h"
#include "SignatureFragment.h"

using namespace std;

#define SERVER_ADDRESS "inspection_server"
#define RULETYPE_CLAMAV 0
#define RULETYPE_SNORT 1

#define ENC_NULL 0
#define ENC_128 128 // aes128gcm
#define ENC_256 256 // aes256gcm
#define ENC_20 20 // chacha20-poly1305

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
	if(argc != 5){
		cout << "usage: " << string(args[0]) << " rule_type filename number_of_rules enc_method" << endl;
		cout << "rule_type: 0 for clamav, 1 for snort" << endl;
		cout << "filename: rules file name" << endl;
		cout << "enc_method: 0 for no encryption, 128 for aes128gcm, 256 for aes256gcm, 20 for chacha20-poly1305" << endl;
		return 0;
	}

	int rule_type = stoi(string(args[1]));
	string filename = string(args[2]);
	int number_of_rules = stoi(string(args[3]));
	int enc_method = stoi(string(args[4]));
	
	vector<SnortRule *> snort_rules;
	vector<ClamavRule *> clamav_rules;
	vector<ACState> states;
	initialize_states(states);

	int total_number_of_rules;
	if(rule_type == RULETYPE_SNORT){
		total_number_of_rules = read_snort_rules(snort_rules, filename, number_of_rules);
		for(auto rule : snort_rules){
			for(auto sc : rule->contents){
				insert_pattern(states, sc->s, sc);
			}
		}
	} else {
		total_number_of_rules = read_clamav_rules(clamav_rules, filename, number_of_rules);
		for(auto rule : clamav_rules){
			for(auto sf : rule->sfs){
				insert_pattern(states, sf->s, sf);
			}
		}
	}
	cal_failure_states(states);

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
	if(bind(server_sock, (struct sockaddr *) &server_address, server_address_len) < 0){
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
	unsigned int client_address_len;
	if((client_sock = accept(server_sock, (struct sockaddr *) &client_address, &client_address_len)) < 0){
		perror("accept failed");
		exit(1);
	} else {
		fprintf(stderr, "accepted client socket\n");
	}
	// we use stdio to read the socket
	FILE * fin = fdopen(client_sock, "r");
	//int len;

    unsigned char record[1000000];
    int offset = 0;
    unsigned char matched_reply[1];
	matched_reply[0] = 1;
	unsigned char no_match_reply[1];
	no_match_reply[0] = 0;
	int cur = 0;
	bool matched = false;

	if(enc_method == ENC_NULL){
		int len;
		while(1){
	        len = fread(record, 1, 1, fin);
	        len = fread(record + 1, 1, 1, fin);
	        unsigned datalen = (record[0] << 8) | record[1];
	        printf("datalen = %u\n", datalen);
	        len = fread(record, 1, datalen, fin);
	        if(len == datalen){
	            
	        } else {
	            printf("len != datalen\n");
	        }

	        int i;
	        for(i = 0;i < len;i++){
	        	unsigned char c = record[i];
    			while(states[cur].edges.count(c) <= 0){
					cur = states[cur].fail_state_number;
				}
				cur = states[cur].edges[c];
				if(rule_type == RULETYPE_SNORT){
					for(auto ptr : states[cur].output){
						SnortContent * sc = (SnortContent *) ptr;
						sc->offset = offset;
						if(sc->rule->is_matched()){
							matched = true;
						}
					}
				} else {
					for(auto ptr : states[cur].output){
						SignatureFragment * sf = (SignatureFragment *) ptr;
						sf->offset = offset;
						if(sf->rule->is_matched()){
							matched = true;
						}
					}
				}
				offset++;
	        }
	        send(client_sock, matched ? matched_reply : no_match_reply, 1, 0);
	    }
	} else {
		unsigned char key[32];
	    unsigned char static_iv[12];
	    unsigned char seqnum[8];
	    int len;

	    if(enc_method != ENC_128){
	    	len = fread(key, 1, 32, fin);
	    	cout << (len != 32 ? "read key failed" : "read key succeeded") << endl;
	    } else {
	    	len = fread(key, 1, 16, fin);
	    	cout << (len != 16 ? "read key failed" : "read key succeeded") << endl;
	    }
	    
	    len = fread(static_iv, 1, 12, fin);
	    cout << (len != 12 ? "read iv failed" : "read iv succeeded") << endl;

	    len = fread(seqnum, 1, 8, fin);
	    cout << (len != 8 ? "read seqnum failed" : "read seqnum succeeded") << endl;
	    
	    uint64_t sequence_number = bytes_to_uint64t(seqnum);
	    printf("seq number = %ul\n", sequence_number);
	    
	    EVP_CIPHER_CTX *ctx;
	    ctx = EVP_CIPHER_CTX_new();
	    /* Select cipher */
	    if(enc_method == ENC_128){
	    	EVP_DecryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, NULL, NULL);
	    } else if(enc_method == ENC_256){
	    	EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL);
	    } else {
	    	EVP_DecryptInit_ex(ctx, EVP_chacha20_poly1305(), NULL, NULL, NULL);
	    }
	    /* Set IV length, omit for 96 bits */
	    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, 12, NULL);

	    unsigned char record[1000000];// TLSCiphertext 
	    unsigned char header[5];
	    unsigned char nonce[12];
	    unsigned char outbuf[1000000];
	    int outlen;
	    int rv;
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

	        int i;
	        for(i = 0;i < outlen;i++){
	        	unsigned char c = outbuf[i];
	        	while(states[cur].edges.count(c) <= 0){
					cur = states[cur].fail_state_number;
				}
				cur = states[cur].edges[c];
				if(rule_type == RULETYPE_SNORT){
					for(auto ptr : states[cur].output){
						SnortContent * sc = (SnortContent *) ptr;
						sc->offset = offset;
						if(sc->rule->is_matched()){
							matched = true;
						}
					}
				} else {
					for(auto ptr : states[cur].output){
						SignatureFragment * sf = (SignatureFragment *) ptr;
						sf->offset = offset;
						if(sf->rule->is_matched()){
							matched = true;
						}
					}
				}
				offset++;
	        }
	        send(client_sock, matched ? matched_reply : no_match_reply, 1, 0);

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
}