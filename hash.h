#ifndef HASH_H
#define HASH_H

#include <openssl/evp.h>

#define SHA256_DIGEST_LENGTH 32

int calculate_sha256(const char *path, unsigned char output[SHA256_DIGEST_LENGTH]);
void print_hash(unsigned char hash[SHA256_DIGEST_LENGTH], unsigned int length);

#endif
