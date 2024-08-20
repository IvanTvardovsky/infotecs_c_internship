#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <openssl/evp.h>
#include <ctype.h>
#include <syslog.h>
#include "integrity.h"
#include "hash.h"

#define SHA256_LENGTH 64

int is_hex_string(const char *str, size_t length) {
    for (size_t i = 0; i < length; i++) {
        if (!isxdigit(str[i])) {
            return 0;
        }
    }
    return 1;
}

int check_integrity_list_format(const char *list_path) {
    FILE *file = fopen(list_path, "r");
    if (!file) {
        perror("Error opening file");
        syslog(LOG_ERR, "Error opening file: %s", list_path);
        return -1;
    }

    char line[1024];
    int line_number = 0;
    while (fgets(line, sizeof(line), file)) {
        line_number++;
        line[strcspn(line, "\n")] = 0;

        char *token = strtok(line, " \t");
        if (!token) {
            fprintf(stderr, "Format error at line %d: missing file path\n", line_number);
            syslog(LOG_ERR, "Format error at line %d: missing file path", line_number);
            fclose(file);
            return -1;
        }

        token = strtok(NULL, " \t");
        if (!token) {
            fprintf(stderr, "Format error at line %d: missing hash\n", line_number);
            syslog(LOG_ERR, "Format error at line %d: missing hash", line_number);
            fclose(file);
            return -1;
        }

        char *hash = token;

        token = strtok(NULL, " \t");
        if (token) {
            fprintf(stderr, "Format error at line %d: extra data after hash\n", line_number);
            syslog(LOG_ERR, "Format error at line %d: extra data after hash", line_number);
            fclose(file);
            return -1;
        }

        // Check hash length and characters
        if (strlen(hash) != SHA256_LENGTH || !is_hex_string(hash, SHA256_LENGTH)) {
            fprintf(stderr, "Format error at line %d: invalid hash format\n", line_number);
            syslog(LOG_ERR, "Format error at line %d: invalid hash format", line_number);
            fclose(file);
            return -1;
        }
    }

    fclose(file);
    syslog(LOG_INFO, "Integrity list format is correct");
    return 0;
}

int generate_integrity_list(const char *dir_path, const char *list_path) {
    FILE *list_file = fopen(list_path, "w");
    if (!list_file) {
        perror("Error creating list file");
        syslog(LOG_ERR, "Error creating list file: %s", list_path);
        return -1;
    }

    DIR *dir = opendir(dir_path);
    if (!dir) {
        perror("Error opening directory");
        syslog(LOG_ERR, "Error opening directory: %s", dir_path);
        fclose(list_file);
        return -1;
    }

    struct dirent *entry;
    char file_path[1024];
    unsigned char hash[SHA256_DIGEST_LENGTH];
    unsigned int hash_length;

    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_type == DT_REG) {
            snprintf(file_path, sizeof(file_path), "%s/%s", dir_path, entry->d_name);
            if (calculate_sha256(file_path, hash) == 0) {
                fprintf(list_file, "%s ", file_path);
                for (hash_length = 0; hash_length < SHA256_DIGEST_LENGTH; hash_length++) {
                    fprintf(list_file, "%02x", hash[hash_length]);
                }
                fprintf(list_file, "\n");
                syslog(LOG_INFO, "File %s added to integrity list", file_path);
            } else {
                fprintf(stderr, "Failed to calculate hash for file %s\n", file_path);
                syslog(LOG_ERR, "Failed to calculate hash for file %s", file_path);
            }
        }
    }

    closedir(dir);
    fclose(list_file);
    syslog(LOG_INFO, "Integrity list generated successfully");
    printf("Integrity list generated successfully\n");
    return 0;
}

int verify_integrity_list(const char *dir_path, const char *list_path) {
    if (check_integrity_list_format(list_path) != 0) {
        fprintf(stderr, "Integrity list format is incorrect\n");
        return -1;
    }

    FILE *list_file = fopen(list_path, "r");
    if (!list_file) {
        perror("Error opening list file");
        syslog(LOG_ERR, "Error opening list file: %s", list_path);
        return -1;
    }

    char line[1024];
    unsigned char hash[SHA256_DIGEST_LENGTH];
    char expected_hash[SHA256_LENGTH + 1];
    int status = 0;

    char **expected_files = NULL;
    int expected_count = 0;
    int expected_capacity = 10;

    expected_files = malloc(expected_capacity * sizeof(char*));
    if (!expected_files) {
        perror("Error allocating memory");
        syslog(LOG_ERR, "Error allocating memory for expected files");
        fclose(list_file);
        return -1;
    }

    while (fgets(line, sizeof(line), list_file)) {
        line[strcspn(line, "\n")] = 0;

        char *file_path = strtok(line, " \t");
        char *hash_str = strtok(NULL, " \t");

        if (calculate_sha256(file_path, hash) == 0) {
            for (unsigned int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
                snprintf(&expected_hash[i * 2], 3, "%02x", hash[i]);
            }

            if (strcmp(hash_str, expected_hash) != 0) {
                fprintf(stderr, "Integrity check failed for file %s\n", file_path);
                syslog(LOG_ERR, "Integrity check failed for file %s", file_path);
                status = -1;
            }
        } else {
            fprintf(stderr, "Failed to calculate hash for file %s\n", file_path);
            syslog(LOG_ERR, "Failed to calculate hash for file %s", file_path);
            status = -1;
        }

        if (expected_count >= expected_capacity) {
            expected_capacity *= 2;
            expected_files = realloc(expected_files, expected_capacity * sizeof(char*));
            if (!expected_files) {
                perror("Error reallocating memory");
                syslog(LOG_ERR, "Error reallocating memory for expected files");
                fclose(list_file);
                return -1;
            }
        }
        expected_files[expected_count] = strdup(file_path);
        expected_count++;
        syslog(LOG_INFO, "File %s integrity verified", file_path);
    }

    fclose(list_file);

    DIR *dir = opendir(dir_path);
    if (!dir) {
        perror("Error opening directory");
        syslog(LOG_ERR, "Error opening directory: %s", dir_path);
        for (int i = 0; i < expected_count; i++) {
            free(expected_files[i]);
        }
        free(expected_files);
        return -1;
    }

    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_type == DT_REG) {
            char file_path[1024];
            snprintf(file_path, sizeof(file_path), "%s/%s", dir_path, entry->d_name);
            int found = 0;
            for (int i = 0; i < expected_count; i++) {
                if (strcmp(file_path, expected_files[i]) == 0) {
                    found = 1;
                    break;
                }
            }
            if (!found) {
                fprintf(stderr, "New file detected: %s\n", file_path);
                syslog(LOG_ERR, "New file detected: %s", file_path);
                status = -1;
            }
        }
    }

    closedir(dir);

    // Проверка на удалённые файлы
    for (int i = 0; i < expected_count; i++) {
        if (access(expected_files[i], F_OK) != 0) {
            fprintf(stderr, "File missing: %s\n", expected_files[i]);
            syslog(LOG_ERR, "File missing: %s", expected_files[i]);
            status = -1;
        }
        free(expected_files[i]);
    }
    free(expected_files);

    if (status == 0) {
        // целостность заверена
        printf("Integrity check passed\n");
        syslog(LOG_INFO, "Integrity check passed");
    } else {
        // нарушение контроля целостности
        printf("Integrity check failed\n");
        syslog(LOG_ERR, "Integrity check failed");
    }

    return status;
}
