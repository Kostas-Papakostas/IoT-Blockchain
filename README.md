# IoT-Blockchain</br>

This repository is about an IoT project based on block-chain.</br>

RSAServerSide contains anything concerns the server that a node sending requests.</br>

mbed_program folder is the client code which is running on a STM32 board with cortex-M7 MCU. </br>

PacketForwarding folder contains a program made by me implementing a kind of NAT server used to forward packets between VMs as I used a "babushka doll" style for this project(VM in VM). It is specific made for this reason so it works only for 2 IPs. To work for more than one clients, clients should include destination and source address.</br>

Subfiles: Anything related to Keys and RSA contains the implementation of the RSA algorithm. SHA256 implements the hash algorithm which is implement by these guys http://www.zedwood.com/article/cpp-sha256-function (kudos).
