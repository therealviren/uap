#include "build.h"
#include "install.h"
#include "run.h"
#include "list_info_uninstall.h"
#include <string.h>
#include <stdio.h>

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "UAP Package Manager\nUsage: uap [build|install|uninstall|list|info|run]\n");
        return 1;
    }
    if (strcmp(argv[1], "build") == 0) return cmd_build(argc - 1, &argv[1]);
    if (strcmp(argv[1], "install") == 0) return cmd_install(argc - 1, &argv[1]);
    if (strcmp(argv[1], "uninstall") == 0) return cmd_uninstall(argc - 1, &argv[1]);
    if (strcmp(argv[1], "list") == 0) return cmd_list(argc - 1, &argv[1]);
    if (strcmp(argv[1], "info") == 0) return cmd_info(argc - 1, &argv[1]);
    if (strcmp(argv[1], "run") == 0) return cmd_run(argc - 1, &argv[1]);
    return 1;
}