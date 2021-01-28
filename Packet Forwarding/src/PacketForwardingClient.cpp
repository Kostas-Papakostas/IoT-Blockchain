#include <unistd.h>
#include <stdio.h>
#include <iostream>
#include <sys/socket.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <string.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <vector>


#define PORT 80 //this is the port of my server
#define FORWARD_PORT 8080 //this is the port of qemu

struct sockaddr_in client;

struct clientCom{
    int client_sock;
    int e, n;
    struct sockaddr* addr_cl;
    std::string client_ip;
};//each client's info

void* connection_Handler(void *socket_desc_p)
{
    //Get the socket descriptor
    struct clientCom *cl_t= (struct clientCom*)socket_desc_p;
    int sock = cl_t->client_sock;

    std::string ip_cl = cl_t->client_ip;

    struct sockaddr_in client;

    /***ACTUAL MESSAGE LOOP THINGY**/
    do
    {
        int encryptedMessage[2048];

        int resBytesReceived=0;
        int totalBytesReceived=0;
        
        /****RECEIVING BLOCK REQUEST***/
        resBytesReceived=recv(sock,encryptedMessage,2048*sizeof(int), 0);
        totalBytesReceived+=resBytesReceived;

        int bytesSent=0;

        if(cl_t->client_ip.compare("192.168.56.103")){//IF MESSAGE COMES FROM THE HOST
            client.sin_family = AF_INET;

            inet_aton("192.168.100.103", &client.sin_addr);//QEMU address
            client.sin_port = htons( FORWARD_PORT );
            bytesSent = sendto(sock,encryptedMessage,sizeof(encryptedMessage)*sizeof(encryptedMessage), 0,(struct sockaddr*)&client, sizeof(client.sin_addr.s_addr));
        }else if(cl_t->client_ip.compare("192.168.100.103")){//IF MESSAGE COMES FROM THE QEMU
            client.sin_family = AF_INET;

            inet_aton("192.168.56.102", &client.sin_addr);//QEMU address
            client.sin_port = htons( FORWARD_PORT );
            bytesSent = sendto(sock,encryptedMessage,sizeof(encryptedMessage)*sizeof(encryptedMessage), 0,(struct sockaddr*)&client, sizeof(client.sin_addr.s_addr));
        }

        /**CHECKING RECEIVE FOR ERRORS**/
        if(bytesSent<0){
            printf("error sendind data %d \n",bytesSent);
            break;
        }
        

    }while(true);

    //Free the socket pointer and remove from vector
    free(socket_desc_p);
    free(cl_t);
}

int main(int argc, char const *argv[]){
    int server_fd, client_socket, *new_thread;
    int client_sock=0;
    struct sockaddr_in server, client;
    int addrlen = sizeof(struct sockaddr_in);

    /**sockets thing**/
    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd == -1)
    {
        perror("socket failed");
        exit(EXIT_FAILURE);
    }

    if ((client_sock = socket(AF_INET, SOCK_STREAM, 0)) < 0)
    {
        printf("\n Socket creation error \n");
        return -1;
    }

    server.sin_family = AF_INET;

    inet_aton("192.168.56.102", &server.sin_addr);//HERE DEFINING YOUR SERVER'S IP(using host-only ip for this one)
    server.sin_port = htons( PORT );

    if (bind(server_fd, (struct sockaddr *)&server, sizeof(server))<0)
    {
        perror("bind failed");
        exit(EXIT_FAILURE);
    }

    char addrSS[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(server.sin_addr), addrSS, INET_ADDRSTRLEN);

    printf("my address %s\n",addrSS);
    printf("my port %d\n",htons(server.sin_port));

    /**packets forwarding*/
    if (listen(server_fd, 3) < 0)
    {
        perror("listen");
        exit(EXIT_FAILURE);
    }
    
    /**sockets thing END**/
    do
    {
        /**connections handling using pthreads***/
        if (listen(server_fd, 3) < 0)
        {
            perror("listen");
            exit(EXIT_FAILURE);
        }

        client_socket = accept(server_fd, (struct sockaddr *)&client,(socklen_t*)&addrlen);

        pthread_t sniffer_thread;
        new_thread = (int*) malloc(1);
        *new_thread = client_socket;
        
        char s_addr[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &(client.sin_addr), s_addr, INET_ADDRSTRLEN);

        struct clientCom cl;
        cl.client_ip=s_addr;
        cl.client_sock=*new_thread;
        cl.addr_cl = (struct sockaddr *)&client;

        if(client_socket>0){
            int threadError = pthread_create( &sniffer_thread , NULL ,  connection_Handler , (void*)&cl );
            if( threadError < 0)
            {
                perror("error handling the thread\n");
                //ERROR
            }
            printf("Handler assigned\n");
            perror("accept");
            char sclient[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &(client.sin_addr), sclient, INET_ADDRSTRLEN);

            printf("client with address %s connected\n",sclient);
        }
    }while(client_socket>0);

    return 0;
}