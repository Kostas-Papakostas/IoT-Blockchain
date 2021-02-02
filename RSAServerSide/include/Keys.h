#pragma once
#include <string>
class Keys
{
private:
	unsigned long p = 0, q = 0, n = 0, phiN = 0;
	unsigned long e, d, K;
	bool isPrime(unsigned long a);
	unsigned long gcd(unsigned long a, unsigned long b);
	unsigned long lcm(unsigned long a, unsigned long b);

	unsigned long modInverse(unsigned long a, unsigned long m);
	int bitsNumber=16;

public:
	unsigned long getN() { return n; }
	unsigned long getE() { return e; }
	unsigned long getD() { return d; }

	void setE(unsigned long e_p) { e = e_p; }
	void setD(unsigned long d_p) { d = d_p; }
	void setN(unsigned long n_p) { n = n_p; }

	unsigned long long int moduloExponential(unsigned long a, unsigned long key, unsigned long m);
	void generateKeys();
};

