#define _GNU_SOURCE
#include "util.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <dirent.h>
#include <errno.h>
#include <pwd.h>
#include <ftw.h>
#include <openssl/evp.h>
#include <stdint.h>
#include <fcntl.h>
#include <sys/wait.h>
#include <ctype.h>
#include <limits.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/sendfile.h>
#include <unistd.h>

int file_exists(const char *path) {
    struct stat st;
    return stat(path, &st) == 0;
}

int path_exists(const char *path) {
    struct stat st;
    return stat(path, &st) == 0;
}

int read_field(const char *file, const char *key, char *out, size_t outlen) {
    FILE *f = fopen(file, "r");
    if (!f) return -1;
    char line[4096];
    int found = -1;
    size_t keylen = strlen(key);
    while (fgets(line, sizeof(line), f)) {
        char *p = line;
        while (*p == ' ' || *p == '\t') p++;
        if (*p == 0 || *p == '\n' || *p == '#') continue;
        char *eq = strchr(p, '=');
        if (!eq) continue;
        *eq = 0;
        char *k = p;
        char *v = eq + 1;
        char *nl = strchr(v, '\n');
        if (nl) *nl = 0;
        while (keylen > 0 && k[keylen] && k[keylen] == 0) break;
        size_t klen = strlen(k);
        while (klen > 0 && (k[klen-1] == ' ' || k[klen-1] == '\t')) k[--klen] = 0;
        while (*v == ' ' || *v == '\t') v++;
        if (strcmp(k, key) == 0) {
            strncpy(out, v, outlen - 1);
            out[outlen - 1] = 0;
            found = 0;
            break;
        }
    }
    fclose(f);
    return found;
}

int read_multi_field(const char *file, const char *key, char ***out_list, size_t *count) {
    *out_list = NULL;
    *count = 0;
    FILE *f = fopen(file, "r");
    if (!f) return -1;
    char line[4096];
    size_t cap = 0;
    while (fgets(line, sizeof(line), f)) {
        char *p = line;
        while (*p == ' ' || *p == '\t') p++;
        if (*p == 0 || *p == '\n' || *p == '#') continue;
        char *eq = strchr(p, '=');
        if (!eq) continue;
        *eq = 0;
        char *k = p;
        char *v = eq + 1;
        char *nl = strchr(v, '\n');
        if (nl) *nl = 0;
        size_t klen = strlen(k);
        while (klen > 0 && (k[klen-1] == ' ' || k[klen-1] == '\t')) k[--klen] = 0;
        while (*v == ' ' || *v == '\t') v++;
        if (strcmp(k, key) == 0) {
            if (*count + 1 > cap) {
                size_t newcap = cap ? cap * 2 : 8;
                char **tmp = realloc(*out_list, newcap * sizeof(char *));
                if (!tmp) { free_string_list(*out_list, *count); fclose(f); return -1; }
                *out_list = tmp;
                cap = newcap;
            }
            (*out_list)[*count] = strdup(v);
            if (!(*out_list)[*count]) { free_string_list(*out_list, *count); fclose(f); return -1; }
            (*count)++;
        }
    }
    fclose(f);
    return 0;
}

void free_string_list(char **list, size_t count) {
    if (!list) return;
    for (size_t i = 0; i < count; ++i) free(list[i]);
    free(list);
}

void expand_home(char *path, size_t len) {
    if (!path) return;
    if (path[0] != '~') return;
    const char *home = getenv("HOME");
    if (!home) {
        struct passwd *pw = getpwuid(getuid());
        if (pw) home = pw->pw_dir;
    }
    if (!home) home = "/tmp";
    char tmp[4096];
    snprintf(tmp, sizeof(tmp), "%s%s", home, path + 1);
    strncpy(path, tmp, len - 1);
    path[len - 1] = 0;
}

int mkdir_p(const char *path) {
    if (!path) return -1;
    char tmp[4096];
    snprintf(tmp, sizeof(tmp), "%s", path);
    size_t len = strlen(tmp);
    if (len == 0) return -1;
    if (tmp[len - 1] == '/') tmp[len - 1] = 0;
    for (char *p = tmp + 1; *p; ++p) {
        if (*p == '/') {
            *p = 0;
            if (mkdir(tmp, 0755) != 0 && errno != EEXIST) { *p = '/'; return -1; }
            *p = '/';
        }
    }
    if (mkdir(tmp, 0755) != 0 && errno != EEXIST) return -1;
    return 0;
}

static int remove_callback(const char *fpath, const struct stat *sb, int type, struct FTW *ftwbuf) {
    (void)sb;
    (void)type;
    (void)ftwbuf;
    remove(fpath);
    return 0;
}

int rmdir_recursive(const char *path) {
    if (!path) return -1;
    return nftw(path, remove_callback, 64, FTW_DEPTH | FTW_PHYS);
}

int copy_file(const char *src, const char *dst) {
    int in = open(src, O_RDONLY);
    if (in < 0) return -1;
    int out = open(dst, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (out < 0) { close(in); return -1; }
#if defined(__linux__)
    off_t offset = 0;
    struct stat st;
    if (fstat(in, &st) == 0 && S_ISREG(st.st_mode)) {
        while (offset < st.st_size) {
            ssize_t sent = sendfile(out, in, &offset, st.st_size - offset);
            if (sent <= 0) {
                if (errno == EINTR) continue;
                break;
            }
        }
    } else
#endif
    {
        char buf[8192];
        ssize_t r;
        while ((r = read(in, buf, sizeof(buf))) > 0) {
            ssize_t w = write(out, buf, r);
            if (w != r) { close(in); close(out); return -1; }
        }
        if (r < 0) { close(in); close(out); return -1; }
    }
    close(in);
    close(out);
    return 0;
}

int copy_recursive(const char *src, const char *dst) {
    struct stat st;
    if (lstat(src, &st) != 0) return -1;
    if (S_ISDIR(st.st_mode)) {
        if (mkdir_p(dst) != 0) return -1;
        DIR *d = opendir(src);
        if (!d) return -1;
        struct dirent *e;
        int rc = 0;
        while ((e = readdir(d))) {
            if (strcmp(e->d_name, ".") == 0 || strcmp(e->d_name, "..") == 0) continue;
            char *srcp = join_path(src, e->d_name);
            char *dstp = join_path(dst, e->d_name);
            if (!srcp || !dstp) { free(srcp); free(dstp); rc = -1; break; }
            if (copy_recursive(srcp, dstp) != 0) { rc = -1; free(srcp); free(dstp); break; }
            free(srcp);
            free(dstp);
        }
        closedir(d);
        return rc;
    } else if (S_ISLNK(st.st_mode)) {
        char target[4096];
        ssize_t len = readlink(src, target, sizeof(target)-1);
        if (len < 0) return -1;
        target[len] = 0;
        if (symlink(target, dst) != 0) return -1;
        return 0;
    } else if (S_ISREG(st.st_mode)) {
        if (copy_file(src, dst) != 0) return -1;
        return 0;
    }
    return -1;
}

void list_packages(const char *path) {
    char p[4096];
    strncpy(p, path, sizeof(p)-1);
    p[sizeof(p)-1] = 0;
    expand_home(p, sizeof(p));
    DIR *d = opendir(p);
    if (!d) return;
    struct dirent *e;
    while ((e = readdir(d))) {
        if (e->d_name[0] == '.') continue;
        printf("%s\n", e->d_name);
    }
    closedir(d);
}

void print_file(const char *path) {
    char p[4096];
    strncpy(p, path, sizeof(p)-1);
    p[sizeof(p)-1] = 0;
    expand_home(p, sizeof(p));
    FILE *f = fopen(p, "r");
    if (!f) return;
    char buf[1024];
    while (fgets(buf, sizeof(buf), f)) fputs(buf, stdout);
    fclose(f);
}

uid_t get_nobody_uid(void) {
    struct passwd *p = getpwnam("nobody");
    return p ? p->pw_uid : 65534;
}

gid_t get_nobody_gid(void) {
    struct passwd *p = getpwnam("nobody");
    return p ? p->pw_gid : 65534;
}

int compute_file_sha256_hex(const char *path, char *out_hex, size_t out_len) {
    unsigned char buf[8192];
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hashlen = 0;
    FILE *f = fopen(path, "rb");
    if (!f) return -1;
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) { fclose(f); return -1; }
    if (EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) != 1) { EVP_MD_CTX_free(ctx); fclose(f); return -1; }
    size_t r;
    while ((r = fread(buf, 1, sizeof(buf), f)) > 0) {
        if (EVP_DigestUpdate(ctx, buf, r) != 1) { EVP_MD_CTX_free(ctx); fclose(f); return -1; }
    }
    if (EVP_DigestFinal_ex(ctx, hash, &hashlen) != 1) { EVP_MD_CTX_free(ctx); fclose(f); return -1; }
    EVP_MD_CTX_free(ctx);
    fclose(f);
    if (hashlen == 0 || hashlen > (int)EVP_MAX_MD_SIZE) return -1;
    char tmp[EVP_MAX_MD_SIZE*2+1];
    for (unsigned int i = 0; i < hashlen; ++i) sprintf(tmp + i*2, "%02x", hash[i]);
    tmp[hashlen*2] = 0;
    if (strlen(tmp) + 1 > out_len) return -1;
    strcpy(out_hex, tmp);
    return 0;
}

int safe_run_command(char *const argv[]) {
    pid_t pid = fork();
    if (pid < 0) return 1;
    if (pid == 0) {
        execvp(argv[0], argv);
        _exit(127);
    }
    int status = 0;
    if (waitpid(pid, &status, 0) < 0) return 1;
    if (WIFEXITED(status)) return WEXITSTATUS(status);
    return 1;
}

int validate_package_name(const char *name) {
    if (!name) return 0;
    size_t n = strlen(name);
    if (n == 0 || n > 256) return 0;
    for (size_t i = 0; i < n; ++i) {
        unsigned char c = name[i];
        if (!(isalnum(c) || c == '.' || c == '_' || c == '-')) return 0;
    }
    return 1;
}

char *join_path(const char *a, const char *b) {
    if (!a || !b) return NULL;
    size_t la = strlen(a);
    size_t lb = strlen(b);
    int need_sep = (la > 0 && a[la-1] != '/');
    size_t totsz = la + lb + (need_sep ? 2 : 1);
    char *r = malloc(totsz);
    if (!r) return NULL;
    if (need_sep) snprintf(r, totsz, "%s/%s", a, b);
    else snprintf(r, totsz, "%s%s", a, b);
    r[totsz-1] = 0;
    return r;
}