// RSAAlgorithm.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <iostream>
#include <math.h>
#include <cmath>
#include <string>
#include <cstring>
#include <stdio.h>
#include <sstream>
#include <cstdio>
#include <iterator>
#include "Keys.h"
#include <time.h>
#include <fstream>
#include <vector>
#include "RSAAlgorithm.h"

std::vector<unsigned long long int> RSAAlgorithm::encryption(std::string inputString,unsigned long otherEndE, unsigned long otherEndN){
    printf("The value of string \"%s\" ", inputString.c_str());

    unsigned long temp;
    std::vector<unsigned long long int> str2;
    for (int i = 0; inputString[i]!='\0'; i++) {
        temp = mykeys->moduloExponential(inputString[i], otherEndE, otherEndN);
        str2.push_back(temp);
    }

    printf("\ncyphered text: ");
    std::string tempstr(str2.begin(),str2.end());
    printf("%s\n", tempstr.c_str());

    return str2;
}

std::string RSAAlgorithm::decryption(std::vector<unsigned long long int> encryptedString){
    printf("decyphered text: ");
    std::string strDecrypted;

    for (int i = 0; i < encryptedString.size(); i++) {
        unsigned long long temp = mykeys->moduloExponential(encryptedString.operator[](i), mykeys->getD(), mykeys->getN());
        strDecrypted+=temp;
    }
    printf("%s", strDecrypted.c_str());
    printf("\n");

    return strDecrypted;
}

void RSAAlgorithm::main_Algorithm()
{
    char approval;
    std::ofstream outputFile;
    std::ifstream inputFile;
    std::string str;
    std::string strDecrypted = "";
    std::vector<unsigned long> str2;
    mykeys=new Keys();

    std::cout<<"Do you want to generate RSA keys??(y or n)\n";
    approval=getchar();
    if(approval=='y'){
      std::remove("build/keys");
      mykeys->generateKeys();
    }else{
      std::cout<<"using already existing keys file\n";
    }
    inputFile.open("build/keys");
    if (!inputFile.is_open()) {
        outputFile.open("build/keys", std::ios::out);
        std::string tempStrPrivate = "(" + std::to_string(mykeys->getD()) + "," + std::to_string(mykeys->getN()) + ")\n";
        std::string tempStrPublic = "(" + std::to_string(mykeys->getE()) + "," + std::to_string(mykeys->getN()) + ")\n";
        outputFile<<tempStrPrivate<<tempStrPublic;
        outputFile.close();
    }
    else if (inputFile.is_open()) {
        std::string tempInputPrivate;
        std::string tempInputPublic;
        std::getline(inputFile, tempInputPrivate);
        std::getline(inputFile, tempInputPublic);
        tempInputPrivate.erase(tempInputPrivate.begin());
        tempInputPrivate.erase(tempInputPrivate.end()-1);

        mykeys->setD(std::stoull(tempInputPrivate.substr(0,tempInputPrivate.find(','))));
        mykeys->setN(std::stoull(tempInputPrivate.substr(tempInputPrivate.find(',')+1,tempInputPrivate.length()-1)));

        tempInputPublic.erase(tempInputPublic.begin());
        tempInputPublic.erase(tempInputPublic.end()-1);

        mykeys->setE(std::stoull(tempInputPublic.substr(0, tempInputPublic.find(','))));
        inputFile.close();
    }

    // std::cout << "please type your message\n" << std::endl;
    // getline(std::cin, str);
    // getline(std::cin, str);

    // str2 = encryption(str);
    // std::string testString;
    // testString = std::to_string(str2.at(0));
    
    // std::string myString = decryption(str2);
    // printf("outer prunsigned long %d\n",atoi(testString.c_str()));

}
