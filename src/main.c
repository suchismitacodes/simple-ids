/*
 * simple-ids — Lightweight Network Intrusion Detection System
 * main.c — Entry point, argument parsing, startup
 *
 * Usage:
 *   sudo ./ids                         (defaults: eth0, rules/rules.conf)
 *   sudo ./ids -i wlan0 -r rules/rules.conf -l logs/ids.log -v
 */

#include "ids.h"

extern Config g_config;

static void usage(const char *prog) {
    fprintf(stderr,
        "Usage: sudo %s [OPTIONS]\n\n"
        "Options:\n"
        "  -i <iface>   Network interface to listen on (default: eth0)\n"
        "  -r <file>    Rules/config file             (default: rules/rules.conf)\n"
        "  -l <file>    Log file                      (default: logs/ids.log)\n"
        "  -v           Verbose mode\n"
        "  -h           Show this help\n\n"
        "Example:\n"
        "  sudo %s -i eth0 -r rules/rules.conf -v\n\n",
        prog, prog);
}

int main(int argc, char *argv[]) {
    char rules_file[256] = "rules/rules.conf";
    int  opt;

    /* ── defaults ── */
    strncpy(g_config.iface,    "eth0",         sizeof(g_config.iface)    - 1);
    strncpy(g_config.log_file, "logs/ids.log", sizeof(g_config.log_file) - 1);
    g_config.verbose = 0;

    while ((opt = getopt(argc, argv, "i:r:l:vh")) != -1) {
        switch (opt) {
            case 'i': strncpy(g_config.iface,    optarg, sizeof(g_config.iface)    - 1); break;
            case 'r': strncpy(rules_file,         optarg, sizeof(rules_file)        - 1); break;
            case 'l': strncpy(g_config.log_file, optarg, sizeof(g_config.log_file) - 1); break;
            case 'v': g_config.verbose = 1; break;
            case 'h': usage(argv[0]); return 0;
            default:  usage(argv[0]); return 1;
        }
    }

    if (geteuid() != 0) {
        fprintf(stderr, "\033[1;31m[ERROR]\033[0m Must run as root (raw sockets require CAP_NET_RAW)\n");
        return 1;
    }

    ids_init(rules_file);
    ids_run();
    ids_cleanup();
    return 0;
}
