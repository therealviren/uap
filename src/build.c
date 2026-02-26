#include "build.h"
#include "util.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>

static int add_to_archive(const char *dir, const char *name, char *list, size_t listlen) {
    char path[4096];
    if (snprintf(path, sizeof(path), "%s/%s", dir, name) >= (int)sizeof(path)) return 0;
    if (!path_exists(path)) return 0;
    if (list[0] != '\0') {
        size_t used = strlen(list);
        if (used + 1 < listlen) strncat(list, " ", listlen - used - 1);
    }
    strncat(list, name, listlen - strlen(list) - 1);
    return 1;
}

static int run_tar_create(const char *dir, const char *out, const char *items) {
    if (!dir || !out || !items) return 1;
    char *items_copy = strdup(items);
    if (!items_copy) return 1;
    char *tokens[64];
    size_t t = 0;
    char *tok = strtok(items_copy, " \t");
    while (tok && t + 6 < sizeof(tokens)/sizeof(tokens[0])) {
        tokens[t++] = strdup(tok);
        tok = strtok(NULL, " \t");
    }
    int argc = 5 + (int)t;
    char **argv = malloc((argc + 1) * sizeof(char *));
    if (!argv) {
        for (size_t i = 0; i < t; ++i) free(tokens[i]);
        free(items_copy);
        return 1;
    }
    argv[0] = "tar";
    argv[1] = "-C";
    argv[2] = (char *)dir;
    argv[3] = "-czf";
    argv[4] = (char *)out;
    for (size_t i = 0; i < t; ++i) argv[5 + i] = tokens[i];
    argv[5 + t] = NULL;
    int r = safe_run_command((char *const *)argv);
    free(argv);
    free(items_copy);
    return r;
}

static int run_openssl_sign(const char *keyfile, const char *input, const char *outbase64) {
    if (!keyfile || !input || !outbase64) return 1;
    char tmp_template[] = "/tmp/uap_sigXXXXXX";
    int fd = mkstemp(tmp_template);
    if (fd < 0) return 1;
    close(fd);
    char *argv1[] = {"openssl", "dgst", "-sha256", "-sign", (char *)keyfile, (char *)input, "-out", tmp_template, NULL};
    int r = safe_run_command((char *const*)argv1);
    if (r != 0) { unlink(tmp_template); return r; }
    char *argv2[] = {"openssl", "base64", "-A", "-in", tmp_template, "-out", (char *)outbase64, NULL};
    r = safe_run_command((char *const*)argv2);
    unlink(tmp_template);
    return r;
}

int cmd_build(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "Usage: uap build <dir> [--sign key.pem]\n");
        return 1;
    }
    const char *appdir = argv[1];
    const char *keyfile = NULL;
    for (int i = 2; i < argc; ++i) {
        if (strcmp(argv[i], "--sign") == 0 && i + 1 < argc) keyfile = argv[++i];
    }
    char meta[4096];
    if (snprintf(meta, sizeof(meta), "%s/meta/build.txt", appdir) >= (int)sizeof(meta)) {
        fprintf(stderr, "Error: path too long\n");
        return 1;
    }
    char pkgname[256] = {0};
    if (read_field(meta, "package_name", pkgname, sizeof(pkgname)) != 0) {
        fprintf(stderr, "Error: meta/build.txt or package_name missing\n");
        return 1;
    }
    if (!validate_package_name(pkgname)) {
        fprintf(stderr, "Invalid package_name\n");
        return 1;
    }
    char out[512];
    if (snprintf(out, sizeof(out), "%s.uap", pkgname) >= (int)sizeof(out)) {
        fprintf(stderr, "Error: output name too long\n");
        return 1;
    }
    char items[4096] = "";
    add_to_archive(appdir, "meta", items, sizeof(items));
    add_to_archive(appdir, "content", items, sizeof(items));
    add_to_archive(appdir, "license", items, sizeof(items));
    add_to_archive(appdir, "readme", items, sizeof(items));
    if (items[0] == '\0') {
        fprintf(stderr, "Nothing to archive\n");
        return 1;
    }
    int r = run_tar_create(appdir, out, items);
    if (r != 0) return r;
    if (keyfile) {
        char sig[512];
        if (snprintf(sig, sizeof(sig), "%s.sig", out) >= (int)sizeof(sig)) {
            unlink(out);
            return 1;
        }
        r = run_openssl_sign(keyfile, out, sig);
        if (r != 0) { unlink(out); return r; }
    }
    printf("Created: %s\n", out);
    return 0;
}