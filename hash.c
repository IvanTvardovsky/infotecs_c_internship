#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include "hash.h"

int calculate_sha256(const char *path, unsigned char output[SHA256_DIGEST_LENGTH]) {
    FILE *file = fopen(path, "rb");
    if (!file) return -1;

    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (!mdctx) {
        fclose(file);
        return -1;
    }

    if (EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL) != 1) {
        EVP_MD_CTX_free(mdctx);
        fclose(file);
        return -1;
    }

    const int bufSize = 32768;
    unsigned char *buffer = malloc(bufSize);
    if (!buffer) {
        EVP_MD_CTX_free(mdctx);
        fclose(file);
        return -1;
    }

    int bytesRead = 0;
    while ((bytesRead = fread(buffer, 1, bufSize, file))) {
        if (EVP_DigestUpdate(mdctx, buffer, bytesRead) != 1) {
            EVP_MD_CTX_free(mdctx);
            fclose(file);
            free(buffer);
            return -1;
        }
    }

    unsigned int length = 0;
    if (EVP_DigestFinal_ex(mdctx, output, &length) != 1) {
        EVP_MD_CTX_free(mdctx);
        fclose(file);
        free(buffer);
        return -1;
    }

    EVP_MD_CTX_free(mdctx);
    fclose(file);
    free(buffer);
    return 0;
}

void print_hash(unsigned char hash[SHA256_DIGEST_LENGTH], unsigned int length) {
    for (unsigned int i = 0; i < length; i++) {
        printf("%02x", hash[i]);
    }
    printf("\n");
}
