#ifndef INTEGRITY_H
#define INTEGRITY_H

int check_integrity_list_format(const char *list_path);
int generate_integrity_list(const char *dir_path, const char *list_path);
int verify_integrity_list(const char *dir_path, const char *list_path);

#endif
