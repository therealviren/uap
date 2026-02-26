#ifndef UAP_UTIL_H
#define UAP_UTIL_H
#include <sys/types.h>
#include <stddef.h>
#include <stdint.h>
int file_exists(const char *path);
int path_exists(const char *path);
int read_field(const char *file, const char *key, char *out, size_t outlen);
int read_multi_field(const char *file, const char *key, char ***out_list, size_t *count);
void free_string_list(char **list, size_t count);
void expand_home(char *path, size_t len);
int mkdir_p(const char *path);
int rmdir_recursive(const char *path);
int copy_file(const char *src, const char *dst);
int copy_recursive(const char *src, const char *dst);
void list_packages(const char *path);
void print_file(const char *path);
uid_t get_nobody_uid(void);
gid_t get_nobody_gid(void);
int compute_file_sha256_hex(const char *path, char *out_hex, size_t out_len);
int safe_run_command(char *const argv[]);
int validate_package_name(const char *name);
char *join_path(const char *a, const char *b);
#endif