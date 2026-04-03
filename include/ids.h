#ifndef IDS_H
#define IDS_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <signal.h>
#include <unistd.h>
#include <getopt.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <linux/if_ether.h>
#include <sys/types.h>

/* ─── Thresholds (overridable via rules.conf) ─── */
#define DEFAULT_PORT_SCAN_THRESHOLD   10    /* unique ports in window         */
#define DEFAULT_SYN_FLOOD_THRESHOLD   100   /* SYN packets in window          */
#define DEFAULT_ICMP_SWEEP_THRESHOLD  10    /* unique hosts pinged in window  */
#define DEFAULT_TIME_WINDOW           3     /* seconds for all counters       */

/* ─── Hash table size (power of 2) ─── */
#define HASH_SIZE   256

/* ─── Suspicious ports ─── */
#define MAX_SUSPICIOUS_PORTS 16
static const int SUSPICIOUS_PORTS[] = {
    4444, 1337, 31337, 6666, 6667, 9001, 9002, 8888, 1234, 12345,
    0xBEEF, 0xDEAD, 2222, 3333, 5555, 7777
};

/* ─── Alert types ─── */
typedef enum {
    ALERT_PORT_SCAN      = 0,
    ALERT_SYN_FLOOD      = 1,
    ALERT_ICMP_SWEEP     = 2,
    ALERT_SUSPICIOUS_PORT = 3
} AlertType;

static const char *ALERT_NAMES[] = {
    "PORT SCAN",
    "SYN FLOOD",
    "ICMP SWEEP",
    "SUSPICIOUS PORT"
};

static const char *ALERT_COLORS[] = {
    "\033[1;33m",   /* yellow  - port scan      */
    "\033[1;31m",   /* red     - syn flood      */
    "\033[1;35m",   /* magenta - icmp sweep     */
    "\033[1;36m"    /* cyan    - suspicious port*/
};

#define COLOR_RESET  "\033[0m"
#define COLOR_GREEN  "\033[1;32m"
#define COLOR_BOLD   "\033[1m"

/* ─── Per-IP tracking node ─── */
typedef struct IPNode {
    char        ip[INET_ADDRSTRLEN];

    /* port scan tracking */
    int         ports_hit[65536 / 32];  /* bitset of ports seen */
    int         unique_ports;
    time_t      port_window_start;

    /* syn flood tracking */
    int         syn_count;
    time_t      syn_window_start;

    /* icmp sweep tracking */
    char        pinged_ips[HASH_SIZE][INET_ADDRSTRLEN];
    int         pinged_count;
    time_t      icmp_window_start;

    struct IPNode *next;
} IPNode;

/* ─── Global config ─── */
typedef struct {
    int  port_scan_threshold;
    int  syn_flood_threshold;
    int  icmp_sweep_threshold;
    int  time_window;
    char log_file[256];
    char iface[64];
    int  verbose;
} Config;

/* ─── Function prototypes ─── */
void        ids_init(const char *rules_file);
void        ids_run(void);
void        ids_cleanup(void);
void        process_packet(unsigned char *buf, int len);

IPNode     *get_or_create_node(const char *ip);
void        check_port_scan(IPNode *node, int dport, const char *src_ip);
void        check_syn_flood(IPNode *node, const char *src_ip);
void        check_icmp_sweep(IPNode *node, const char *src_ip, const char *dst_ip);
void        check_suspicious_port(const char *src_ip, int dport);

void        fire_alert(AlertType type, const char *src_ip, const char *detail);
void        log_alert(AlertType type, const char *src_ip, const char *detail);

void        parse_rules(const char *path);
void        print_banner(void);
void        handle_signal(int sig);

/* Port bitset helpers */
static inline void port_set(int *bitset, int port) {
    bitset[port / 32] |= (1 << (port % 32));
}
static inline int port_get(int *bitset, int port) {
    return (bitset[port / 32] >> (port % 32)) & 1;
}

/* djb2 hash for IP strings */
static inline unsigned int ip_hash(const char *ip) {
    unsigned int h = 5381;
    while (*ip) h = ((h << 5) + h) ^ (unsigned char)*ip++;
    return h % HASH_SIZE;
}

#endif /* IDS_H */
