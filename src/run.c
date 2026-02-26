#define _GNU_SOURCE
#include "run.h"
#include "util.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/resource.h>
#ifdef __linux__
#include <sched.h>
#include <sys/prctl.h>
#endif

static void apply_limits_and_drop(const char *meta_path) {
    char max_cpu[64];
    char max_mem[64];
    char run_as[128];
    int have_cpu = (read_field(meta_path, "sandbox_max_cpu_seconds", max_cpu, sizeof(max_cpu)) == 0);
    int have_mem = (read_field(meta_path, "sandbox_max_memory_bytes", max_mem, sizeof(max_mem)) == 0);
    if (read_field(meta_path, "sandbox_run_as", run_as, sizeof(run_as)) != 0) run_as[0] = 0;
    if (have_cpu) {
        struct rlimit rl;
        rl.rlim_cur = rl.rlim_max = (rlim_t)atoi(max_cpu);
        setrlimit(RLIMIT_CPU, &rl);
    }
    if (have_mem) {
        struct rlimit rl;
        rl.rlim_cur = rl.rlim_max = (rlim_t)atoll(max_mem);
        setrlimit(RLIMIT_AS, &rl);
    }
    if (run_as[0]) {
        uid_t uid = get_nobody_uid();
        gid_t gid = get_nobody_gid();
        setgid(gid);
        setuid(uid);
    }
}

int cmd_run(int argc, char **argv) {
    if (argc < 2) return 1;
    char path[4096], bin[4096];
    snprintf(path, sizeof(path), "~/.uap/packages/%s", argv[1]);
    expand_home(path, sizeof(path));
    snprintf(bin, sizeof(bin), "%s/%s", path, argv[1]);
    if (!file_exists(bin)) return 1;
    pid_t pid = fork();
    if (pid == 0) {
        chdir(path);
#ifdef __linux__
        char perm_path[4096];
        snprintf(perm_path, sizeof(perm_path), "%s/meta/permissions.txt", path);
        char net[64];
        if (read_field(perm_path, "network", net, sizeof(net)) != 0 || strcmp(net, "true") != 0) {
            unshare(CLONE_NEWNET);
        }
        apply_limits_and_drop(perm_path);
#endif
        char *args[64];
        int i = 0;
        args[i++] = bin;
        for (int j = 2; j < argc && i < 63; ++j) args[i++] = argv[j];
        args[i] = NULL;
        execv(bin, args);
        _exit(1);
    }
    int status;
    waitpid(pid, &status, 0);
    return 0;
}