#include "list_info_uninstall.h"
#include "util.h"
#include <stdio.h>
#include <string.h>

int cmd_list(int argc, char **argv) {
    (void)argc;
    (void)argv;
    char path[1024] = "~/.uap/packages";
    expand_home(path, sizeof(path));
    list_packages(path);
    return 0;
}

int cmd_info(int argc, char **argv) {
    if (argc < 2) return 1;
    char path[4096];
    snprintf(path, sizeof(path), "~/.uap/packages/%s/meta/build.txt", argv[1]);
    expand_home(path, sizeof(path));
    print_file(path);
    return 0;
}

int cmd_uninstall(int argc, char **argv) {
    if (argc < 2) return 1;
    char path[4096];
    snprintf(path, sizeof(path), "~/.uap/packages/%s", argv[1]);
    expand_home(path, sizeof(path));
    rmdir_recursive(path);
    printf("Uninstalled %s\n", argv[1]);
    return 0;
}