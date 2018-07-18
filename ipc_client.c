#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <stdio.h>

#define ADDRESS "mysocket"

char * strs[3] = {
    "this is the first string from the client",
    "this is the second string from the client",
    "this is the third string from the client"
};

int main(){
    char c;
    FILE * fp;
    int i, s, len;
    struct sockaddr_un saun;

    // get a socket to work with, this socket will be
    // in the UNIX domain, and will be a stream socket
    if((s = socket(AF_UNIX, SOCK_STREAM, 0)) < 0){
        perror("client: socket");
        exit(1);
    }

    // create the address we will be connecting to
    saun.sun_family = AF_UNIX;
    strcpy(saun.sun_path, ADDRESS);

    // try to connect to the address
    len = sizeof(saun.sun_family) + strlen(saun.sun_path);

    if(connect(s, &saun, len) < 0){
        perror("client: connect");
        exit(1);
    }

    // we will use stdio for reading the socket
    fp = fdopen(s, "r");
    // first we read the strings from the server
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
        send(s, strs[i], strlen(strs[i]), 0);
    }
    // we can simply use close to terminate the connection,
    // since we are done with both sides
    close(s);

    return 0;
}