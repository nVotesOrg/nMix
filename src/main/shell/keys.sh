#!/bin/sh

# generate public and private key in ssh format
ssh-keygen -t rsa -b 4096 -f keys/id_rsa -q -N ""

# generate public key from ssh keygen private key
openssl rsa -in keys/id_rsa -pubout > keys/id_rsa.pub.pem

# generate private key in pkcs8 pem format from ssh key gen private key
openssl pkcs8 -topk8 -inform PEM -outform PEM -in keys/id_rsa -out keys/id_rsa.pem -nocrypt