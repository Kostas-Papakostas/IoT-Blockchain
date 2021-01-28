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
#include "Keys.h"
#include "SHA256.h"
#include <chrono>
#include <bitset>
#include <bits/stdc++.h> 
#include "RSAAlgorithm.h"

#define PORT 8080

struct sockaddr_in client;

struct clientCom{
    int client_sock;
    int e, n;
    std::string client_ip;
};//each client's info

std::vector<struct clientCom> clients;//active clients connected
int hex = 0x1f;
std::string previousHash="1F";
char *serverHandshakeMessage;
RSAAlgorithm *prep_algo = new RSAAlgorithm();

std::string strToBinary(std::string s);

int handshake_handler(bool clientConnected, int sock_p, int i_p){
    int handshakeReadSize=0, handshakeSendSize=0;
    char client_HandshakeMessage[2048];
    /*checks if clients connected before or not
    *if not then initialize handshake
    */
    if(!clientConnected){
        struct clientCom cl;
        //Receive a handshake message from client
        printf("prlp\n");
        handshakeReadSize = recv(sock_p , client_HandshakeMessage, 2048, 0);
        std::string s(client_HandshakeMessage);
        size_t pos;

        /**CHECKING recv for errors**/
        if(handshakeReadSize == 0)
        {
            printf("Client disconnected\n");
            fflush(stdout);
            return -1;
        }
        if(handshakeReadSize == -1)
        {
            perror("error receiving data\n");
            return -1;
            //ERROR
        }


        /**EXTRACTING public key from handshake message(e,n)
         * and assign it to the correspinding client
         * **/
        if(handshakeReadSize>0){
            if((pos=s.find("GET Handshake/"))==0){
                cl.client_ip=s.substr(strlen("GET Handshake/"),s.find("/public key/"));/*Gets the string between GET Handshae/ and /public key/ which is ip address*/
                cl.e=atoi(s.substr(s.find("/e/")+3,s.find("/n/")).c_str());/*getting client's e from public key*/
                cl.n=atoi(s.substr(s.find("/n/")+3,s.length()-1).c_str());/*Getting client's n from public key*/
                cl.client_sock=sock_p;
            }
        }
        clients.push_back(cl);

        //Replying to handshake with ACK and public key
        handshakeSendSize = sizeof(serverHandshakeMessage)*sizeof(serverHandshakeMessage[0]);
        int resSentBytes=send(sock_p,serverHandshakeMessage, handshakeSendSize,0);
        
        /**CHECKING SEND FOR ERRORS**/
        if(resSentBytes<0){
            perror("error sending handshake data\n");
            return -1;
        }
    }

    return 0;
}



void* connection_Handler(void *socket_desc_p)
{
    //Get the socket descriptor
    int sock = *(int*)socket_desc_p;

    std::string smatrix ;
    std::string tok ;
    bool clientConnected = false;
    int i;

    for(i=0; i<clients.size(); i++){
        if(clients.at(i).client_sock==sock){
            clientConnected=true;
            break;
        }
    }

    int resBytesReceived=0;
    int resBytesSent=0;
    
    int res=handshake_handler(clientConnected, sock, i);
    if(res==-1){
        /**IF ANY ERRORS OCCURE JUMP TO DISCONNECT**/
        goto DISCONNECT;
    }


    /***ACTUAL MESSAGE LOOP THINGY**/
    do
    {
        std::vector<unsigned long long> encryptedMessageReceived;
        std::string decryptedMessage;
        std::string hashedMessage;
        unsigned long long encryptedMessage[2048];

        int resBytesReceived=0;
        int totalBytesReceived=0;
        
        /****RECEIVING BLOCK REQUEST***/
        resBytesReceived=recv(sock,encryptedMessage,2047*sizeof(unsigned long long), 0);
        totalBytesReceived+=resBytesReceived;
        /**CHECKING RECEIVE FOR ERRORS**/
        if(resBytesReceived<0){
            perror("error receiving data \n");
            goto DISCONNECT;
        }
        
        /**IF BYTES RECEIVED THE DECRYPT AND HASH THE MESSAGE**/
        if(totalBytesReceived>0){
            encryptedMessageReceived.insert(encryptedMessageReceived.begin(),std::begin(encryptedMessage),std::end(encryptedMessage));
            
            auto startDecr = std::chrono::high_resolution_clock::now();

            decryptedMessage = prep_algo->decryption(encryptedMessageReceived);

            auto stopDecr = std::chrono::high_resolution_clock::now();
            auto decrDuration = std::chrono::duration_cast<std::chrono::milliseconds>(stopDecr-startDecr);
            printf("Decryption time elapsed(ms): %ld\n",decrDuration.count());

            /*CHECKING IF THERE IS PREVIOUS HASH OR IT IS THE FIRST CLIENT ASKING FOR BLOCK*/
            auto startHashing = std::chrono::high_resolution_clock::now();
            bool hashedMessageComputed = true;
            std::string hashedMessage;
            if(previousHash.compare("1F")==0){
                do{
                    hashedMessage = sha256(decryptedMessage);
                    previousHash+=hashedMessage;
                    std::string stbp = strToBinary(previousHash);
                    for(int i=0; i<3; i++){
                        hashedMessageComputed=true;
                        if(stbp.at(i)!=0){
                            hashedMessageComputed=false;
                        }
                    }
                }while(!hashedMessageComputed);
            }else if(!previousHash.empty()){
                do{
                    hashedMessage = sha256(previousHash);
                    std::string stbp = strToBinary(hashedMessage);
                    for(int i=0; i<3; i++){
                        std::bitset<21>(previousHash.c_str());
                        hashedMessageComputed=true;
                        
                        if(stbp.at(i)!=0){
                            hashedMessageComputed=false;
                        }
                    }
                }while(!hashedMessageComputed);
            }

            auto stopHashing = std::chrono::high_resolution_clock::now();
            auto hashDuration = std::chrono::duration_cast<std::chrono::milliseconds>(stopHashing-startHashing);
            printf("Hashing time elapsed(ms): %ld\n",hashDuration.count());
        }
        /**ADDING IP TO THE HASH MESSAGE AND SEND IT TO ALL OF THE CLIENTS CONNECTED**/
        hashedMessage+="/ip:"+clients.at(i).client_ip;
        auto startEncr = std::chrono::high_resolution_clock::now();
        std::vector<unsigned long long> messageToEncrypt(prep_algo->encryption(hashedMessage, clients.at(i).e, clients.at(i).n));
        int EncryptionToSend[messageToEncrypt.size()];

        auto stopEncr = std::chrono::high_resolution_clock::now();
        auto EncrDuration = std::chrono::duration_cast<std::chrono::milliseconds>(stopEncr-startEncr);
        printf("Encryption time elapsed(ms): %ld\n",EncrDuration.count());

        /**sending to all active clients**/
        for(int k=0; k<clients.size(); k++){
            resBytesSent=send(clients.at(k).client_sock, EncryptionToSend,sizeof(EncryptionToSend)*sizeof(int),0);
        }

        if(resBytesSent<0){
            perror("error sending data\n");
            goto DISCONNECT;
        }

    }while(resBytesReceived<=0 || resBytesSent<=0);

DISCONNECT:
    //Free the socket pointer and remove from vector
    clients.erase(clients.begin()+i);
    free(socket_desc_p);
}

std::string strToBinary(std::string s) 
{ 
    int n = s.length(); 
  
    std::string bin = ""; 
    for (int i = 0; i <= n; i++) 
    { 
        // convert each char to 
        // ASCII value 
        int val = int(s[i]); 
  
        // Convert ASCII value to binary 
        
        while (val > 0) 
        { 
            (val % 2)? bin.push_back('1') : 
                       bin.push_back('0'); 
            val /= 2; 
        } 
        std::reverse(bin.begin(), bin.end());
    } 

    return bin;
} 

int main(int argc, char const *argv[])
{
    int server_fd, client_socket, *new_thread;
    struct sockaddr_in server;
    int addrlen = sizeof(struct sockaddr_in);
    int myE, myN;

    auto startRSAAlgorithm = std::chrono::high_resolution_clock::now();
    prep_algo->main_Algorithm();
    auto stopRSAAlgorithm = std::chrono::high_resolution_clock::now();
    auto RSAAlgorithmDuration = std::chrono::duration_cast<std::chrono::milliseconds>(stopRSAAlgorithm-startRSAAlgorithm);
    printf("RSAAlgorithm key generation elapsed time(ms): %d", RSAAlgorithmDuration.count());

    myE = prep_algo->getMyKeys()->getE();
    myN = prep_algo->getMyKeys()->getN();

    

    /**sockets thing**/
    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd == -1)
    {
        perror("socket failed");
        exit(EXIT_FAILURE);
    }

    server.sin_family = AF_INET;

    inet_aton("127.0.0.1", &server.sin_addr);//HERE DEFINING YOUR SERVER'S IP
    server.sin_port = htons( PORT );

    if (bind(server_fd, (struct sockaddr *)&server, sizeof(server))<0)
    {
        perror("bind failed");
        exit(EXIT_FAILURE);
    }
    char sss[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(server.sin_addr), sss, INET_ADDRSTRLEN);

    printf("my address %s\n",sss);
    printf("my port %d\n",htons(server.sin_port));


    std::string tempStr = "ACCEPT/e/"+std::to_string(myE)+"/n/"+std::to_string(myN);
    serverHandshakeMessage=(char*)tempStr.c_str();
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

        if(client_socket>0){
            int threadError = pthread_create( &sniffer_thread , NULL ,  connection_Handler , (void*) new_thread);
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
