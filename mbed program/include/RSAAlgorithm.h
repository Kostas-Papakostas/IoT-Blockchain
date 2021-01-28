#include "Keys.h"
#include <vector>
#include <string>
class RSAAlgorithm{
private:
    Keys *mykeys;

public:
    void main_Algorithm();
    std::vector<unsigned long long int> encryption(std::string inputString,unsigned long otherEndE, unsigned long otherEndN);
    std::string decryption(std::vector<unsigned long long int> encyptedString);
    Keys* getMyKeys(){return mykeys;}
};