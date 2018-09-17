// perform inspection on plaintext 

#include "inspection.h"

int main(int argc, char ** args){
    if(argc != 4){
		fprintf(stderr, "usage: %s rule_type rule_file number_of_rules\n", args[0]);
		exit(1);
	}

	int rule_type = atoi(args[1]);
	char * rule_file = args[2];
	int number_of_rules = atoi(args[3]);
	initialize_mem_pool();
	fprintf(stderr, "mem pool initialized\n");

	struct rule_inspect ins;
	initialize_rule_inspect(rule_type, &ins, rule_file, number_of_rules);

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

    int len;

    unsigned char record[1000000];
    int offset = 0;
    unsigned char matched_reply[1];
	matched_reply[0] = 1;
	unsigned char no_match_reply[1];
	no_match_reply[0] = 0;

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
            ac_inspect(rule_type, ins.states, &(ins.global_state_number), record[i], offset, &(ins.matched_rules));
			offset++;
        }
        if(ins.matched_rules){
			send(client_sock, matched_reply, 1, 0);
		} else {
			send(client_sock, no_match_reply, 1, 0);
		}
    }
}