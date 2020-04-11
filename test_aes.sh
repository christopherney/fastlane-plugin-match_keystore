#!/usr/bin/env bash

PASSWORD="my-super-secret"

rm -f test.key.txt
echo ${PASSWORD} | openssl dgst -sha512 | awk '{print $2}' | cut -c1-128 > test.key.txt

rm -f test.LICENSE.enc.txt
openssl enc -aes-256-cbc -salt -pbkdf2 -in LICENSE -out test.LICENSE.enc.txt -pass file:test.key.txt

rm -f text.LICENSE.txt
openssl enc -d -aes-256-cbc -pbkdf2 -in test.LICENSE.enc.txt -out text.LICENSE.txt -pass file:test.key.txt
