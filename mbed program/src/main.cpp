#include "HighResClock.h"
#include "Keys.h"
#include "NetworkInterface.h"
#include "SocketAddress.h"
#include "mbed.h"
#include "mbed_wait_api.h"
#include "watchdog_api.h"
#include "RSAAlgorithm.h"
#include <chrono>
#include <cstdio>
#include <string>
#include <Timer.h>
#include <vector>
 
const char* ECHO_SERVER_ADDRESS = "83.212.187.9";
const int ECHO_SERVER_PORT = 80;
 
struct neighbourNodes{
    std::vector<string> Notebook;
    std::vector<string> IPs;
};

struct neighbourNodes nodes;
NetworkInterface *net;
TCPSocket socket;

int main() {
    
    string eString, nString, dString;
    int node = std::rand() % 10;
    Timer t;
    net=NetworkInterface::get_default_instance();
    t.start();
    RSAAlgorithm *prepAlgor = new RSAAlgorithm();
    prepAlgor->main_Algorithm();
    t.stop();
    int rsaDuration = t.read_ms();

    printf("RSA computation time(ms): %d\n", rsaDuration);
    Keys *keysObj = prepAlgor->getMyKeys();
    unsigned long e=keysObj->getE(), n=keysObj->getN();
    
  //  e=18077;
    //n=579494389;
    //keysObj->setD(169534805);
/*************TO BE REMOVED******************/
    t.start();
    std::string inS = "block request node/"+to_string(node);
    std::vector<unsigned long long> encrMSG = prepAlgor->encryption(inS, e, n);
    t.stop();
    int encrDuration = t.read_ms();
    printf("RSA encryption time(ms): %d\n", encrDuration);

    t.start();
    std::string sssss = prepAlgor->decryption(encrMSG);
    t.stop();
    int decrDuration = t.read_ms();
    printf("RSA decryption time(ms): %d\n", decrDuration);
/***********END TO BE REMOVED*****************/
    eString=to_string(prepAlgor->getMyKeys()->getE());
    nString=to_string(prepAlgor->getMyKeys()->getN());

    printf("socket thingy\n");

    if (!net) {
        printf("Error! No network inteface found.\n");
        return 0;
    }

    int result = net->connect();
    if (result < 0) {
        printf("Error! net->connect() returned: %d\n", result);
        return result;
    }

    // Show the network address
    SocketAddress a;
    net->get_ip_address(&a);
    printf("IP address: %s\n", a.get_ip_address() ? a.get_ip_address() : "None");
    net->get_netmask(&a);
    printf("Netmask: %s\n", a.get_ip_address() ? a.get_ip_address() : "None");
    net->get_gateway(&a);
    printf("Gateway: %s\n", a.get_ip_address() ? a.get_ip_address() : "None");

    
   
    result = socket.open(net);
    
    if (result != 0) {
        printf("Error! socket.open() returned: %d\n", result);
        socket.close();
        return result;
    }

    int hostNameResult = net->gethostbyname(ECHO_SERVER_ADDRESS, &a);
    if (hostNameResult != 0) {
      printf("Error! gethostbyname(%s) returned: %d\n", ECHO_SERVER_ADDRESS, hostNameResult);
      printf("Invalid Address\n");
      net->disconnect();
      exit(-1);
    }
    printf("Host address is %s\n", (a.get_ip_address() ? a.get_ip_address() : "None") );
    a.set_port(ECHO_SERVER_PORT);

    int sock = socket.connect(a);
    if(sock<0){
        printf("Connection error to socket Error:%d\n",sock);
        socket.close();
        return sock;
    }

    printf("Connection to server established\n");

    socket.set_blocking(true);
    
    string connectionEstablishMsg = "GET Handshake/"+to_string(net->get_ip_address(&a))+
                                        "/public key/e/"+to_string(e)+"/n/"+to_string(n);
    nsapi_size_t size = connectionEstablishMsg.length();

    while (size) {
        
        result = socket.send(connectionEstablishMsg.c_str(), size);
        if(result<0){
            printf("Error sending data: %d\n",result);
            break;
        }
        size -= result;
        printf("sent %d bytes\n", result);
    }
 
    printf("%s from client\n",connectionEstablishMsg.c_str());

    
    
    printf("Waiting for connection establishment request\n");
    char bufAcceptRequest[2048]={0};
    int dataReceived=0;
    int n2=0;
    int bytes=0;
    string acceptRequest;
    
    while(dataReceived<2048 && (bytes<2048-dataReceived)){
        //bytes = socket.recv( bufAcceptRequest, sizeof(bufAcceptRequest)*sizeof(char));    //it throws stack overflow error(weird)
        if(bytes<0){
            printf("Error receiving data code: %d",bytes);
            socket.close();
            return -1;
        }
        dataReceived+=bytes;
    }
    printf("received data in bytes: %d\n",dataReceived);

    acceptRequest = bufAcceptRequest;
    printf("%s", acceptRequest.c_str());
    
    int serversE, serversN;
    if(acceptRequest.substr(0,acceptRequest.find("/")).compare("ACCEPTED")==0){//breaking accept request and public key
        serversE = stoi(acceptRequest.substr(acceptRequest.find("e/")+2,acceptRequest.find("/n")));
        serversN = stoi(acceptRequest.substr(acceptRequest.find("n/")+2,acceptRequest.length()-1));
    }

    /**ACTUAL BLOCK REQUESTS**/
    int requestSize;
    int reqResult;

    while(true){
        string blockRequest = "block request node/"+to_string(node);
        
        t.start();
        std::vector<unsigned long long> messageEncrypted(prepAlgor->encryption(blockRequest, serversE, serversN));
        t.stop();

        int encryptionDuration = t.read_ms();
        printf("Encryption time elapsed(ms): %d\n",encryptionDuration);

        requestSize=messageEncrypted.size();
        reqResult=0;
        int arrayToSend[requestSize];
        std::copy(messageEncrypted.begin(), messageEncrypted.end(),arrayToSend);

        //sending encryptd message
        while (requestSize>0) {
            reqResult = socket.send(arrayToSend, (requestSize)*sizeof(arrayToSend[0]));
            if(reqResult<0){
                printf("Error sending data: %d\n",reqResult);
                break;
            }
            requestSize -= reqResult;
            printf("sent %d bytes\n", reqResult);
        }

        //receiving update data to notebook
        int bytesReceived=0;
        int updateDataBuffer[2048];
        int bufSizedUp=0;
        while(bufSizedUp<2048 && (bytesReceived<2048-bufSizedUp)){
            bytesReceived = socket.recv( updateDataBuffer, (sizeof(updateDataBuffer))*sizeof(int));
            if(bytesReceived<0){
                printf("Error receiving data code: %d",bytesReceived);
                socket.close();
                return -1;
            }
            bufSizedUp+=bytesReceived;
        }
        printf("received data in bytes: %d\n",bufSizedUp);
        
        t.start();
        string updateInfo = prepAlgor->decryption(std::vector<unsigned long long>(updateDataBuffer, updateDataBuffer + sizeof updateDataBuffer / sizeof updateDataBuffer[0]));
        nodes.Notebook.push_back(updateInfo);
        t.stop();

        int decryptionDuration = t.read_ms();
        printf("Decryption time elapsed(ms): %d",decryptionDuration);
    }

DISCONNECT1:
    socket.close();
//    net->disconnect();
    printf("Done\n");
    
    //while(true) {}
    //return 0;
}