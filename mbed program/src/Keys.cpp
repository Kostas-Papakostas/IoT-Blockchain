#include "Keys.h"
#include <iostream>
#include <time.h>
#include <random>
#include <cmath>
#include <tuple>
#include <utility>
#include <exception>
#include "RSAAlgorithm.h"
#include <algorithm>

unsigned long Keys::gcd(unsigned long a, unsigned long b) {
	if (b == 0) {
		return a;
	}
	else {
		return gcd(b, a % b);
	}
}

unsigned long Keys::lcm(unsigned long a, unsigned long b) {
	unsigned long max = (a > b) ? a : b;
	do
	{
		if (max % a == 0 && max % b == 0)
		{
			std::cout << "LCM = " << max;
			return max;
		}
		else
			++max;
	} while (true);
}

bool Keys::isPrime(unsigned long a) {
	for (unsigned long i = 2; i < sqrt(a); i++) {
		if (a % i == 0) {
			//std::cout << "Prime not found for number " << a << "\ndivider is "<<i<<std::endl;
			return false;
		}
	}
	return true;
}

unsigned long Keys::modInverse(unsigned long a, unsigned long m) {
	unsigned long t = 0, newt = 1;
    unsigned long r = m, newr = a;  
    while (newr != 0) {
        auto quotient = r /newr;
        std::tie(t, newt) = std::make_tuple(newt, t- quotient * newt);
        std::tie(r, newr) = std::make_tuple(newr, r - quotient * newr);
    }
    if (r > 1)
        perror("a is not invertible");
    if (t < 0)
        t += n;
    return t;
}

unsigned long long int Keys::moduloExponential(unsigned long a, unsigned long key, unsigned long m) {
	unsigned long long int result = 1;
    while (key > 0)
	{
		if (key & 1)
		{
			
			a=a%m;
			result = (result * a)%m;
			result=result%m;
		}
		key=key>>1;
		a=a%m;
		a = (a*a)%m;
		a=a%m;
	}
    return result;
}

void Keys::generateKeys() {
	std::pair<unsigned long , unsigned long > keyPair;
	std::vector<std::pair<unsigned long , unsigned long >> notCompPairs;
	bool pairExists = false;
	do{
		bool p_prime=false, q_prime=false;
		q=0; p=0;
		do {
			srand(time(NULL));

			if(!p_prime){
				p = 3 + ( std::rand() % ( (unsigned long)pow(2,bitsNumber) -1 ) );
				p_prime = isPrime(p);
			}

			q = 3 + ( std::rand() % ( (unsigned long)pow(2,bitsNumber) -1 ) );
			q_prime = isPrime(q);
			if(!q_prime || p==q){
				q = 3 + ( std::rand() % ( (unsigned long)pow(2,bitsNumber) -1 ) );
				q_prime = isPrime(q);
			}
			keyPair.first=p;
			keyPair.second=q;

			std::vector<std::pair<unsigned long , unsigned long >>::iterator it = std::find(notCompPairs.begin(), notCompPairs.end(), keyPair);
			pairExists=false;
			if(it != notCompPairs.end()){
				pairExists=true;
			}else if(it == notCompPairs.end()){
				pairExists=false;
				notCompPairs.push_back(keyPair);
			}
		} while ((!p_prime || !q_prime) || (p == q) || pairExists);

		n = p * q;
		phiN = (p - 1)*(q - 1);

		K = modInverse(phiN,n);

		while(true){
			srand(time(NULL));
			e = 3 + std::rand() % ((unsigned long)std::pow(2, bitsNumber)-1);
			if (gcd(phiN,e) == 1) {
				break;
			}
		}

		d = modInverse(e, phiN);

		std::string verify = "Signature OK";
		std::vector<unsigned long long> V;
		bool paired=false;
		unsigned long long t;
		for(int i=0;i<verify.length();i++){
			t = moduloExponential(verify[i],e,n);
			V.push_back(t);
		}

		int k=0;
		std::string s="";
		for(int k=0; k<V.size();k++){
			unsigned long long t2 = moduloExponential(V.at(k),d,n);
			s+=t2;
		}
		
		if(s.compare(verify)==0){
			break;
		}
	}while(true);

	std::cout << "p and q: " << p << " and " << q << std::endl;

	std::cout << "public key: {e,n}= ";
	printf("{%lu,%lu}\n", e, n);

	std::cout << "private key: {d,n}= ";
	printf("{%lu,%lu}\n", d, n);
}
