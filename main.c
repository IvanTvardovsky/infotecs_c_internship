#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include "integrity.h"

void print_usage() {
    printf("Инструкция:\n");
    printf("  integrity_tool -g <directory_path> <list_path>  # Сгенерировать список контроля целостности\n");
    printf("  integrity_tool -v <directory_path> <list_path>  # Верифицировать список контроля целостности\n");
}

int main(int argc, char *argv[]) {
    openlog("integrity_tool", LOG_PID|LOG_CONS, LOG_USER);
    print_usage();

    if (argc < 4) {
        fprintf(stderr, "Usage: %s -g|-v <directory_path> <list_path>\n", argv[0]);
        syslog(LOG_ERR, "Invalid arguments. Usage: %s -g|-v <directory_path> <list_path>", argv[0]);
        return 1;
    }

    const char *mode = argv[1];
    const char *dir_path = argv[2];
    const char *list_path = argv[3];

    if (strcmp(mode, "-g") == 0) {
        int result = generate_integrity_list(dir_path, list_path);
        if (result == 0) {
            syslog(LOG_INFO, "Integrity list generated successfully for directory: %s", dir_path);
        }
        closelog();
        return result;
    } else if (strcmp(mode, "-v") == 0) {
        int result = verify_integrity_list(dir_path, list_path);
        if (result == 0) {
            syslog(LOG_INFO, "Integrity check passed for directory: %s", dir_path);
        } else {
            syslog(LOG_ERR, "Integrity check failed for directory: %s", dir_path);
        }
        closelog();
        return result;
    } else {
        fprintf(stderr, "Invalid mode: %s. Use -g to generate or -v to verify.\n", mode);
        syslog(LOG_ERR, "Invalid mode: %s. Use -g to generate or -v to verify.", mode);
        closelog();
        return 1;
    }
}
