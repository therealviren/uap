#include "install.h"
#include "util.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <limits.h>
#include <errno.h>

static int verify_signature_base64(const char *archive, const char *pubkey) {
    char tmp_template[PATH_MAX];
    const char *tmp_base = getenv("TMPDIR");
    if (!tmp_base) tmp_base = "/tmp";
    mkdir_p(tmp_base);
    snprintf(tmp_template, sizeof(tmp_template), "%s/uap_sigXXXXXX", tmp_base);
    int fd = mkstemp(tmp_template);
    if (fd < 0) return 1;
    close(fd);

    char sigb64[PATH_MAX];
    snprintf(sigb64, sizeof(sigb64), "%s.sig", archive);

    char *argv1[] = {"openssl", "base64", "-d", "-in", sigb64, "-out", tmp_template, NULL};
    int r = safe_run_command((char *const*)argv1);
    if (r != 0) { unlink(tmp_template); return r; }

    char *argv2[] = {"openssl", "dgst", "-sha256", "-verify", (char *)pubkey, "-signature", tmp_template, (char *)archive, NULL};
    r = safe_run_command((char *const*)argv2);

    unlink(tmp_template);
    return r;
}

static int run_tar_extract(const char *dir, const char *archive) {
    char *argv[] = {"tar", "-C", (char *)dir, "-xzf", (char *)archive, NULL};
    return safe_run_command((char *const*)argv);
}

static int safe_make_install(const char *content_dir, const char *prefix, int jobs) {
    char jobs_str[32];
    snprintf(jobs_str, sizeof(jobs_str), "%d", jobs);

    pid_t pid = fork();
    if (pid < 0) return 1;
    if (pid == 0) {
        setenv("PREFIX", prefix, 1);
        execlp("make", "make", "-C", content_dir, "install", "PREFIX", prefix, "-j", jobs_str, (char *)NULL);
        _exit(127);
    }

    int status = 0;
    waitpid(pid, &status, 0);
    if (WIFEXITED(status)) return WEXITSTATUS(status);
    return 1;
}

static int run_custom_install_script(const char *script_path, const char *workdir) {
    pid_t pid = fork();
    if (pid < 0) return 1;
    if (pid == 0) {
        if (chdir(workdir) != 0) _exit(127);
        execlp(script_path, script_path, (char *)NULL);
        _exit(127);
    }

    int status = 0;
    waitpid(pid, &status, 0);
    if (WIFEXITED(status)) return WEXITSTATUS(status);
    return 1;
}

int cmd_install(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "Usage: uap install <file.uap> [--pubkey pub.pem]\n");
        return 1;
    }

    const char *file = argv[1];
    const char *pubkey = NULL;
    for (int i = 2; i < argc; ++i)
        if (strcmp(argv[i], "--pubkey") == 0 && i + 1 < argc) pubkey = argv[++i];

    if (!file_exists(file)) {
        fprintf(stderr, "Error: Archive %s not found\n", file);
        return 1;
    }

    if (pubkey && verify_signature_base64(file, pubkey) != 0) {
        fprintf(stderr, "Signature verification failed\n");
        return 1;
    }

    const char *tmp_base = getenv("TMPDIR");
    if (!tmp_base) tmp_base = "/tmp";
    mkdir_p(tmp_base);

    char tmp_template[PATH_MAX];
    snprintf(tmp_template, sizeof(tmp_template), "%s/uap_inst_XXXXXX", tmp_base);
    char *tmpdir = mkdtemp(tmp_template);
    if (!tmpdir) {
        fprintf(stderr, "Error: mkdtemp failed\n");
        return 1;
    }

    if (run_tar_extract(tmpdir, file) != 0) {
        fprintf(stderr, "Error: Failed to extract %s\n", file);
        rmdir_recursive(tmpdir);
        return 1;
    }

    char mpath[PATH_MAX];
    snprintf(mpath, sizeof(mpath), "%s/meta/build.txt", tmpdir);
    char name[256] = {0};
    if (read_field(mpath, "package_name", name, sizeof(name)) != 0 || strlen(name) == 0) {
        fprintf(stderr, "Error: meta/build.txt or package_name missing\n");
        rmdir_recursive(tmpdir);
        return 1;
    }

    if (!validate_package_name(name)) {
        fprintf(stderr, "Error: invalid package_name\n");
        rmdir_recursive(tmpdir);
        return 1;
    }

    char dest[PATH_MAX];
    snprintf(dest, sizeof(dest), "~/.uap/packages/%s", name);
    expand_home(dest, sizeof(dest));

    char dest_real[PATH_MAX];
    mkdir_p(dest);
    if (realpath(dest, dest_real) == NULL) {
        fprintf(stderr, "Error: cannot resolve destination path\n");
        rmdir_recursive(tmpdir);
        return 1;
    }

    char base_prefix[PATH_MAX];
    const char *home = getenv("HOME");
    if (!home) home = tmp_base;
    snprintf(base_prefix, sizeof(base_prefix), "%s/.uap/packages", home);
    mkdir_p(base_prefix);
    char prefix_real[PATH_MAX];
    if (realpath(base_prefix, prefix_real) == NULL) {
        fprintf(stderr, "Error: cannot resolve base prefix\n");
        rmdir_recursive(tmpdir);
        return 1;
    }

    if (strncmp(dest_real, prefix_real, strlen(prefix_real)) != 0) {
        fprintf(stderr, "Error: destination outside allowed prefix\n");
        rmdir_recursive(tmpdir);
        return 1;
    }

    if (path_exists(dest_real)) rmdir_recursive(dest_real);
    mkdir_p(dest_real);

    // --- FIX: copy content preserving 'content' subdir ---
    char src_content[PATH_MAX];
    snprintf(src_content, sizeof(src_content), "%s/content", tmpdir);

    char dest_content[PATH_MAX];
    snprintf(dest_content, sizeof(dest_content), "%s/content", dest_real);
    mkdir_p(dest_content);

    if (copy_recursive(src_content, dest_content) != 0) {
        fprintf(stderr, "Error: failed to copy content\n");
        rmdir_recursive(tmpdir);
        return 1;
    }

    char content_dir[PATH_MAX];
    snprintf(content_dir, sizeof(content_dir), "%s/content", dest_real);
    char makefile_path[PATH_MAX];
    snprintf(makefile_path, sizeof(makefile_path), "%s/Makefile", content_dir);

    char build_jobs_s[32] = "4";
    char jobsbuf[32] = {0};
    if (read_field(mpath, "parallel_jobs", jobsbuf, sizeof(jobsbuf)) == 0 && strlen(jobsbuf) > 0)
        strncpy(build_jobs_s, jobsbuf, sizeof(build_jobs_s) - 1);
    int jobs = atoi(build_jobs_s);

    if (file_exists(makefile_path)) {
        int rc = safe_make_install(content_dir, dest_real, jobs);
        if (rc != 0) {
            fprintf(stderr, "Error: make install failed\n");
            rmdir_recursive(tmpdir);
            return 1;
        }
        printf("Successfully installed %s\n", name);
    } else {
        char srcdir[PATH_MAX];
        snprintf(srcdir, sizeof(srcdir), "%s/src", content_dir);
        char binpath[PATH_MAX];
        snprintf(binpath, sizeof(binpath), "%s/%s", dest_real, name);

        char cflags[1024] = "-O2 -fstack-protector-strong -D_FORTIFY_SOURCE=2 -fPIC";
        read_field(mpath, "cflags", cflags, sizeof(cflags));

        char ldflags[1024] = "-Wl,--as-needed";
        read_field(mpath, "ldflags", ldflags, sizeof(ldflags));

        char cmdbuf[16384];
        snprintf(cmdbuf, sizeof(cmdbuf), "gcc %s/*.c %s -o %s %s", srcdir, cflags, binpath, ldflags);

        pid_t pid = fork();
        if (pid == 0) execlp("/bin/sh", "sh", "-c", cmdbuf, (char *)NULL), _exit(127);

        int st = 0;
        waitpid(pid, &st, 0);
        if (!WIFEXITED(st) || WEXITSTATUS(st) != 0) {
            fprintf(stderr, "Error: Compilation failed\n");
            rmdir_recursive(tmpdir);
            return 1;
        } else printf("Successfully installed %s\n", name);
    }

    char install_file[PATH_MAX] = {0};
    if (read_field(mpath, "install_file", install_file, sizeof(install_file)) == 0 && strlen(install_file) > 0) {
        char script_path[PATH_MAX];
        snprintf(script_path, sizeof(script_path), "%s/%s", tmpdir, install_file);
        if (file_exists(script_path)) run_custom_install_script(script_path, tmpdir);
    }

    rmdir_recursive(tmpdir);
    return 0;
}