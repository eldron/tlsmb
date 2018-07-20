#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <stdio.h>
#include <stdlib.h>

#define SERVER_ADDRESS "mysocket"

// strings we send to the client
char * strs[3] = {
    "this is the first string from the server\n",
    "this is the second string from the server\n",
    "this is the third string from the server\n"
};

void test_server_main(){
    char c;
    FILE * fp;
    struct sockaddr_un server_address;
    struct sockaddr_un client_address;
    int server_sock;
    int client_sock;
    
    // get a socket to work with, the socket willbe in the UNIX domain,
    // and will be a stream socket
    if((server_sock = socket(AF_UNIX, SOCK_STREAM, 0)) < 0){
        perror("server: socket");
        exit(1);
    }
    // create the address we will be binding to
    server_address.sun_family = AF_UNIX;
    strcpy(server_address.sun_path, SERVER_ADDRESS);
    // try to bind the address to the server socket, we unlink
    // the name first so that the bind won't fail
    unlink(SERVER_ADDRESS);
    int server_address_len = sizeof(server_address.sun_family) + strlen(server_address.sun_path);
    if(bind(server_sock, &server_address, server_address_len) < 0){
        perror("server: bind");
        exit(1);
    }
    // listen on server socket
    if(listen(server_sock, 5) < 0){
        perror("server: listen");
        exit(1);
    }

    int client_address_len;
    if((client_sock = accept(server_sock, &client_address, &client_address_len)) < 0){
        perror("server: accept");
        exit(1);
    }
    // we will use stdio for reading the socket
    fp = fdopen(client_sock, "r");
    // first we send some strings to the client
    int i;
    for(i = 0;i < 3;i++){
        send(client_sock, strs[i], strlen(strs[i]), 0);
    }

    // then we read some strings from the client and
    // print them out
    for(i = 0;i < 3;i++){
        while((c = fgetc(fp)) != EOF){
            putchar(c);
            if(c == '\n'){
                break;
            }
        }
    }
    // we can simply use close() to terminate the connection,
    // since we are done with both sides
    close(server_sock);
}
int main(){
    // char c;
    // FILE * fp;
    // int from_len;
    // int i, s, ns, len;
    // struct sockaddr_un saun, fsaun;

    // // get a socket to work with, the socket will be
    // // in the UNIX domain, and will be a stream socket
    // if((s = socket(AF_UNIX, SOCK_STREAM, 0)) < 0){
    //     perror("server: socket");
    //     exit(1);
    // }

    // // create the address we will be binding to
    // saun.sun_family = AF_UNIX;
    // strcpy(saun.sun_path, SERVER_ADDRESS);

    // // try to bind the address to the socket, we unlink
    // // the name first so that the bind won't fail
    // unlink(SERVER_ADDRESS);
    // len = sizeof(saun.sun_family) + strlen(saun.sun_path);
    // if(bind(s, &saun, len) < 0){
    //     perror("server: bind");
    //     exit(1);
    // }

    // // listen on the socket
    // if(listen(s, 5) < 0){
    //     perror("server: listen");
    //     exit(1);
    // }

    // // accept connections, when we accept one, 
    // // ns will be connected to the client, fsaun
    // // wull contain the address of the client
    // if((ns = accept(s, &fsaun, &from_len)) < 0){
    //     perror("server: accept");
    //     exit(1);
    // }

    // // we will use stdio for reading the socket
    // fp = fdopen(ns, "r");
    // // first we send some strings to the client
    // for(i = 0;i < 3;i++){
    //     send(ns, strs[i], strlen(strs[i]), 0);
    // }

    // // then we read some strings from the client and
    // // print them out
    // for(i = 0;i < 3;i++){
    //     while((c = fgetc(fp)) != EOF){
    //         putchar(c);
    //         if(c == '\n'){
    //             break;
    //         }
    //     }
    // }
    // // we can simply use close() to terminate the connection,
    // // since we are done with both sides
    // close(s);

    test_server_main();
    return 0;
}