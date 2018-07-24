#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <stdio.h>

#define ADDRESS "mysocket"
#define SERVER_ADDRESS "inspection_server"

char * strs[3] = {
    "this is the first string from the client",
    "this is the second string from the client",
    "this is the third string from the client"
};

void test_inspection(){
    struct sockaddr_un client_address;
    int client_sock;

    FILE * fin = fopen("bigger.pcap", "r");
    client_sock = socket(AF_UNIX, SOCK_STREAM, 0);
    client_address.sun_family = AF_UNIX;
    strcpy(client_address.sun_path, SERVER_ADDRESS);
    int client_address_len = sizeof(client_address.sun_family) + strlen(client_address.sun_path);
    connect(client_sock, &client_address, client_address_len);

    FILE * fp = fdopen(client_sock, "r");
    // read file, send to server for inspection, read result
    unsigned char buffer[3000];
    unsigned char * high = &(buffer[0]);
    unsigned char * low = &(buffer[1]);
    int number_read;
    unsigned char result;
    while(1){
        number_read = fread(buffer + 2, 1, 2048, fin);
        if(number_read < 2048){
            if(number_read > 0){
                // send to server for inspection
                *high = (number_read & 0xff00) >> 8;
                *low = (number_read & 0x00ff);
                send(client_sock, buffer, number_read + 2, 0);
                // read reply
                result = fgetc(fp);
                if(result > 0){
                    printf("some rules matched\n");
                }
            }
            break;
        } else {
            // send to server for inspection
            *high = (number_read & 0xff00) >> 8;
            *low = (number_read & 0x00ff);
            send(client_sock, buffer, number_read + 2, 0);
            // read reply
            result = fgetc(fp);
            if(result){
                printf("some rules matched\n");
            }
        }
    }
    fclose(fin);
    close(client_sock);
}

void test_client_main(){
    struct sockaddr_un client_address;
    int client_sock;
    char c;
    FILE * fp;

    client_sock = socket(AF_UNIX, SOCK_STREAM, 0);
    client_address.sun_family = AF_UNIX;
    strcpy(client_address.sun_path, SERVER_ADDRESS);
    int client_address_len = sizeof(client_address.sun_family) + strlen(client_address.sun_path);
    connect(client_sock, &client_address, client_address_len);
    fp = fdopen(client_sock, "r");
    // first we read the strings from the server
    int i;
    for(i = 0;i < 3;i++){
        while((c = fgetc(fp)) != EOF){
            putchar(c);
            if(c == '\n'){
                break;
            }
        }
    }

    // now we send some strings to the server
    for(i = 0;i < 3;i++){
        send(client_sock, strs[i], strlen(strs[i]), 0);
    }
    // we can simply use close to terminate the connection,
    // since we are done with both sides
    close(client_sock);
}
int main(){
    //test_client_main();
    test_inspection();

    return 0;
}