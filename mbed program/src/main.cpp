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
#include <ctime>
#include <cstdlib>
#include <string>
#include <Timer.h>
#include <vector>

#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#if defined(MBEDTLS_PLATFORM_C)
#include "mbedtls/platform.h"
#else
#include <stdio.h>
#define mbedtls_printf     printf
#endif

#if defined(MBEDTLS_BIGNUM_C) && defined(MBEDTLS_ENTROPY_C) && \
    defined(MBEDTLS_RSA_C) && defined(MBEDTLS_GENPRIME) && \
    defined(MBEDTLS_FS_IO) && defined(MBEDTLS_CTR_DRBG_C)
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/bignum.h"
#include "mbedtls/x509.h"
#include "mbedtls/rsa.h"

#endif

#define KEY_SIZE 2048
#define EXPONENT 65537

const char* ECHO_SERVER_ADDRESS = "127.0.0.1";//add server ip here
const int ECHO_SERVER_PORT = 80;
 
struct neighbourNodes{
    std::vector<string> Notebook;
    std::vector<string> IPs;
};

struct neighbourNodes nodes;
NetworkInterface *net;
TCPSocket socket;

int nonce=std::rand()%255;

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
    
    int ret;
    mbedtls_rsa_context rsa;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_mpi N, P, Q, D, E, DP, DQ, QP;
    FILE *fpub  = NULL;
    FILE *fpriv = NULL;
    const char *pers = "rsa_genkey";
    unsigned long e, n;

    mbedtls_ctr_drbg_init( &ctr_drbg );
    mbedtls_rsa_init( &rsa, MBEDTLS_RSA_PKCS_V15, 0 );
    mbedtls_mpi_init( &N ); mbedtls_mpi_init( &P ); mbedtls_mpi_init( &Q );
    mbedtls_mpi_init( &D ); mbedtls_mpi_init( &E ); mbedtls_mpi_init( &DP );
    mbedtls_mpi_init( &DQ ); mbedtls_mpi_init( &QP );

    mbedtls_printf( "\n  . Seeding the random number generator..." );
    fflush( stdout );

    mbedtls_entropy_init( &entropy );
    if( ( ret = mbedtls_ctr_drbg_seed( &ctr_drbg, mbedtls_entropy_func, &entropy,
                               (const unsigned char *) pers,
                               strlen( pers ) ) ) != 0 )
    {
        mbedtls_printf( " failed\n  ! mbedtls_ctr_drbg_seed returned %d\n", ret );
        return 0;
    }

    mbedtls_printf( " ok\n  . Generating the RSA key [ %d-bit ]...", KEY_SIZE );
    fflush( stdout );

    if( ( ret = mbedtls_rsa_gen_key( &rsa, mbedtls_ctr_drbg_random, &ctr_drbg, KEY_SIZE,
                                     EXPONENT ) ) != 0 )
    {
        mbedtls_printf( " failed\n  ! mbedtls_rsa_gen_key returned %d\n\n", ret );
        return 0;
    }

    mbedtls_printf( " ok\n  . Exporting the public  key in rsa_pub.txt...." );
    fflush( stdout );

    if( ( ret = mbedtls_rsa_export    ( &rsa, &N, &P, &Q, &D, &E ) ) != 0 ||
        ( ret = mbedtls_rsa_export_crt( &rsa, &DP, &DQ, &QP ) )      != 0 )
    {
        mbedtls_printf( " failed\n  ! could not export RSA parameters\n\n" );
        ret = 1;
        return 0;
    }
    e=*E.p; n=*N.p;
    prepAlgor->getMyKeys()->setE(e);
    prepAlgor->getMyKeys()->setN(n);

    printf(" q:%zu, p:%zu, d:%zu, e:%zu, n:%zu\n", *Q.p, *(P.p), *D.p, *E.p, *N.p);
    printf(" e:%lu, n:%lu\n", e, n);

/*************TO BE REMOVED******************/
    t.start();
    std::string inS = "block request node/"+to_string(node);
    std::vector<unsigned long long> encrMSG = prepAlgor->encryption(inS, e, n);
    t.stop();
    int encrDuration = t.read_ms();
    printf("RSA encryption time(ms): %d\n", encrDuration);

    t.start();
    prepAlgor->getMyKeys()->setD(*D.p);
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
        bytes = socket.recv( bufAcceptRequest, sizeof(bufAcceptRequest)*sizeof(char));    //it throws stack overflow error(weird) don't know the reason, maybe mbed's version bug
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


    time_t rawtime;
    struct tm * timeinfo;
    char timeBuffer[80];

    time (&rawtime);
    timeinfo = localtime(&rawtime);

    strftime(timeBuffer,sizeof(timeBuffer),"%d-%m-%Y %H:%M:%S",timeinfo);
    std::string timeStr(timeBuffer);


    while(true){
        string blockRequest =std::to_string(nonce)+"nonce/block request node/"+to_string(node)+"I'm some data"+timeStr;
        
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
    net->disconnect();
    printf("Done\n");
    
    return 0;
}