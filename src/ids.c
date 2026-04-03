/*
 * ids.c — Core IDS engine
 *
 * - Opens a raw socket (AF_PACKET / SOCK_RAW)
 * - Parses Ethernet → IP → TCP/UDP/ICMP headers
 * - Runs detection checks on every packet
 * - Fires colour-coded alerts to stdout + log file
 */

#include "ids.h"

/* ─── Globals ─── */
Config   g_config;
IPNode  *g_table[HASH_SIZE];   /* hash table of tracked IPs */
FILE    *g_logfp  = NULL;
int      g_sockfd = -1;
volatile int g_running = 1;

/* total alert counters */
static int g_total_alerts = 0;
static int g_alert_counts[4] = {0};

/* ═══════════════════════════════════════════════
 *  Initialisation
 * ═══════════════════════════════════════════════ */
void ids_init(const char *rules_file) {
    /* apply compiled-in defaults first */
    g_config.port_scan_threshold  = DEFAULT_PORT_SCAN_THRESHOLD;
    g_config.syn_flood_threshold  = DEFAULT_SYN_FLOOD_THRESHOLD;
    g_config.icmp_sweep_threshold = DEFAULT_ICMP_SWEEP_THRESHOLD;
    g_config.time_window          = DEFAULT_TIME_WINDOW;

    memset(g_table, 0, sizeof(g_table));

    /* open log file */
    g_logfp = fopen(g_config.log_file, "a");
    if (!g_logfp) {
        perror("fopen log");
        /* non-fatal — we just won't write to disk */
    }

    parse_rules(rules_file);
    signal(SIGINT,  handle_signal);
    signal(SIGTERM, handle_signal);

    print_banner();
}

/* ═══════════════════════════════════════════════
 *  Main packet-capture loop
 * ═══════════════════════════════════════════════ */
void ids_run(void) {
    unsigned char buffer[65536];
    ssize_t       len;

    /* AF_PACKET gives us full Ethernet frames */
    g_sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (g_sockfd < 0) {
        perror("socket");
        fprintf(stderr, COLOR_RESET "\033[1;31m[ERROR]\033[0m "
                "Failed to open raw socket. Are you running as root?\n");
        exit(EXIT_FAILURE);
    }

    printf(COLOR_GREEN "[*] Listening on interface: %s\033[0m\n\n", g_config.iface);

    while (g_running) {
        len = recvfrom(g_sockfd, buffer, sizeof(buffer), 0, NULL, NULL);
        if (len < 0) {
            if (!g_running) break;
            perror("recvfrom");
            continue;
        }
        process_packet(buffer, (int)len);
    }
}

/* ═══════════════════════════════════════════════
 *  Packet processor — parse headers, run checks
 * ═══════════════════════════════════════════════ */
void process_packet(unsigned char *buf, int len) {
    /* skip Ethernet header (14 bytes) */
    if (len < (int)(sizeof(struct ethhdr) + sizeof(struct iphdr)))
        return;

    struct iphdr *iph = (struct iphdr *)(buf + sizeof(struct ethhdr));
    int ip_hdr_len    = iph->ihl * 4;

    if (iph->version != 4) return;

    char src_ip[INET_ADDRSTRLEN], dst_ip[INET_ADDRSTRLEN];
    struct in_addr src_addr = { .s_addr = iph->saddr };
    struct in_addr dst_addr = { .s_addr = iph->daddr };
    inet_ntop(AF_INET, &src_addr, src_ip, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &dst_addr, dst_ip, INET_ADDRSTRLEN);

    IPNode *node = get_or_create_node(src_ip);
    if (!node) return;

    switch (iph->protocol) {

        case IPPROTO_TCP: {
            if (len < (int)(sizeof(struct ethhdr) + ip_hdr_len + sizeof(struct tcphdr)))
                break;
            struct tcphdr *tcph = (struct tcphdr *)(buf + sizeof(struct ethhdr) + ip_hdr_len);
            int dport = ntohs(tcph->dest);

            /* SYN only (no ACK) → potential SYN flood or scan */
            if (tcph->syn && !tcph->ack) {
                check_syn_flood(node, src_ip);
                check_port_scan(node, dport, src_ip);
            }
            check_suspicious_port(src_ip, dport);
            break;
        }

        case IPPROTO_UDP: {
            if (len < (int)(sizeof(struct ethhdr) + ip_hdr_len + sizeof(struct udphdr)))
                break;
            struct udphdr *udph = (struct udphdr *)(buf + sizeof(struct ethhdr) + ip_hdr_len);
            int dport = ntohs(udph->dest);
            check_port_scan(node, dport, src_ip);
            check_suspicious_port(src_ip, dport);
            break;
        }

        case IPPROTO_ICMP: {
            if (len < (int)(sizeof(struct ethhdr) + ip_hdr_len + sizeof(struct icmphdr)))
                break;
            struct icmphdr *icmph = (struct icmphdr *)(buf + sizeof(struct ethhdr) + ip_hdr_len);
            /* Echo Request = ping */
            if (icmph->type == ICMP_ECHO)
                check_icmp_sweep(node, src_ip, dst_ip);
            break;
        }
    }
}

/* ═══════════════════════════════════════════════
 *  Hash-table helpers
 * ═══════════════════════════════════════════════ */
IPNode *get_or_create_node(const char *ip) {
    unsigned int idx   = ip_hash(ip);
    IPNode      *node  = g_table[idx];

    while (node) {
        if (strcmp(node->ip, ip) == 0) return node;
        node = node->next;
    }

    /* allocate new node */
    node = calloc(1, sizeof(IPNode));
    if (!node) return NULL;

    strncpy(node->ip, ip, INET_ADDRSTRLEN - 1);
    time_t now = time(NULL);
    node->port_window_start = now;
    node->syn_window_start  = now;
    node->icmp_window_start = now;

    node->next   = g_table[idx];
    g_table[idx] = node;
    return node;
}

/* ═══════════════════════════════════════════════
 *  Detection: Port Scan
 * ═══════════════════════════════════════════════ */
void check_port_scan(IPNode *node, int dport, const char *src_ip) {
    time_t now = time(NULL);

    if (difftime(now, node->port_window_start) > g_config.time_window) {
        /* reset window */
        memset(node->ports_hit, 0, sizeof(node->ports_hit));
        node->unique_ports      = 0;
        node->port_window_start = now;
    }

    if (!port_get((int *)node->ports_hit, dport)) {
        port_set((int *)node->ports_hit, dport);
        node->unique_ports++;
    }

    if (node->unique_ports >= g_config.port_scan_threshold) {
        char detail[128];
        snprintf(detail, sizeof(detail), "Ports hit: %d (threshold: %d)",
                 node->unique_ports, g_config.port_scan_threshold);
        fire_alert(ALERT_PORT_SCAN, src_ip, detail);
        /* reset to avoid alert storm */
        memset(node->ports_hit, 0, sizeof(node->ports_hit));
        node->unique_ports      = 0;
        node->port_window_start = now;
    }
}

/* ═══════════════════════════════════════════════
 *  Detection: SYN Flood
 * ═══════════════════════════════════════════════ */
void check_syn_flood(IPNode *node, const char *src_ip) {
    time_t now = time(NULL);

    if (difftime(now, node->syn_window_start) > g_config.time_window) {
        node->syn_count        = 0;
        node->syn_window_start = now;
    }

    node->syn_count++;

    if (node->syn_count >= g_config.syn_flood_threshold) {
        char detail[128];
        snprintf(detail, sizeof(detail), "SYN count: %d in %ds (threshold: %d)",
                 node->syn_count, g_config.time_window, g_config.syn_flood_threshold);
        fire_alert(ALERT_SYN_FLOOD, src_ip, detail);
        node->syn_count        = 0;
        node->syn_window_start = now;
    }
}

/* ═══════════════════════════════════════════════
 *  Detection: ICMP Sweep
 * ═══════════════════════════════════════════════ */
void check_icmp_sweep(IPNode *node, const char *src_ip, const char *dst_ip) {
    time_t now = time(NULL);

    if (difftime(now, node->icmp_window_start) > g_config.time_window) {
        memset(node->pinged_ips, 0, sizeof(node->pinged_ips));
        node->pinged_count      = 0;
        node->icmp_window_start = now;
    }

    /* check if dst_ip already recorded */
    unsigned int idx = ip_hash(dst_ip) % HASH_SIZE;
    if (node->pinged_ips[idx][0] == '\0') {
        strncpy(node->pinged_ips[idx], dst_ip, INET_ADDRSTRLEN - 1);
        node->pinged_count++;
    }

    if (node->pinged_count >= g_config.icmp_sweep_threshold) {
        char detail[128];
        snprintf(detail, sizeof(detail), "Hosts pinged: %d in %ds (threshold: %d)",
                 node->pinged_count, g_config.time_window, g_config.icmp_sweep_threshold);
        fire_alert(ALERT_ICMP_SWEEP, src_ip, detail);
        memset(node->pinged_ips, 0, sizeof(node->pinged_ips));
        node->pinged_count      = 0;
        node->icmp_window_start = now;
    }
}

/* ═══════════════════════════════════════════════
 *  Detection: Suspicious Port
 * ═══════════════════════════════════════════════ */
void check_suspicious_port(const char *src_ip, int dport) {
    int n = (int)(sizeof(SUSPICIOUS_PORTS) / sizeof(SUSPICIOUS_PORTS[0]));
    for (int i = 0; i < n; i++) {
        if (dport == SUSPICIOUS_PORTS[i]) {
            char detail[128];
            snprintf(detail, sizeof(detail), "Port %d (common malware/C2 port)", dport);
            fire_alert(ALERT_SUSPICIOUS_PORT, src_ip, detail);
            return;
        }
    }
}

/* ═══════════════════════════════════════════════
 *  Alert: print + log
 * ═══════════════════════════════════════════════ */
void fire_alert(AlertType type, const char *src_ip, const char *detail) {
    g_total_alerts++;
    g_alert_counts[type]++;

    /* timestamp */
    time_t    now = time(NULL);
    struct tm *tm = localtime(&now);
    char ts[32];
    strftime(ts, sizeof(ts), "%Y-%m-%d %H:%M:%S", tm);

    const char *color = ALERT_COLORS[type];
    const char *name  = ALERT_NAMES[type];

    /* coloured stdout */
    printf("%s[ALERT #%d]%s [%s] %-18s | SRC: %-18s | %s\n",
           color, g_total_alerts, COLOR_RESET,
           ts, name, src_ip, detail);
    fflush(stdout);

    log_alert(type, src_ip, detail);
}

void log_alert(AlertType type, const char *src_ip, const char *detail) {
    if (!g_logfp) return;
    time_t    now = time(NULL);
    struct tm *tm = localtime(&now);
    char ts[32];
    strftime(ts, sizeof(ts), "%Y-%m-%d %H:%M:%S", tm);
    fprintf(g_logfp, "[%s] ALERT | %-20s | SRC: %-18s | %s\n",
            ts, ALERT_NAMES[type], src_ip, detail);
    fflush(g_logfp);
}

/* ═══════════════════════════════════════════════
 *  Rules parser — simple key=value format
 * ═══════════════════════════════════════════════ */
void parse_rules(const char *path) {
    FILE *fp = fopen(path, "r");
    if (!fp) {
        printf(COLOR_BOLD "[*] No rules file found at '%s', using defaults.\033[0m\n", path);
        return;
    }

    char line[256];
    while (fgets(line, sizeof(line), fp)) {
        /* strip comments and blank lines */
        char *p = strchr(line, '#');
        if (p) *p = '\0';
        if (line[0] == '\n' || line[0] == '\0') continue;

        char key[64], val[64];
        if (sscanf(line, " %63[^=]= %63s", key, val) != 2) continue;

        /* trim trailing whitespace from key */
        char *e = key + strlen(key) - 1;
        while (e > key && (*e == ' ' || *e == '\t')) *e-- = '\0';

        if      (strcmp(key, "port_scan_threshold")  == 0) g_config.port_scan_threshold  = atoi(val);
        else if (strcmp(key, "syn_flood_threshold")   == 0) g_config.syn_flood_threshold   = atoi(val);
        else if (strcmp(key, "icmp_sweep_threshold")  == 0) g_config.icmp_sweep_threshold  = atoi(val);
        else if (strcmp(key, "time_window")           == 0) g_config.time_window           = atoi(val);
        else if (strcmp(key, "log_file")              == 0) strncpy(g_config.log_file, val, sizeof(g_config.log_file)-1);
    }
    fclose(fp);
    printf(COLOR_GREEN "[*] Rules loaded from: %s\033[0m\n", path);
}

/* ═══════════════════════════════════════════════
 *  Cleanup & shutdown
 * ═══════════════════════════════════════════════ */
void ids_cleanup(void) {
    printf("\n" COLOR_BOLD "\n[*] IDS Shutdown Summary\n" COLOR_RESET);
    printf("    Total alerts fired : %d\n", g_total_alerts);
    printf("    Port Scan alerts   : %d\n", g_alert_counts[ALERT_PORT_SCAN]);
    printf("    SYN Flood alerts   : %d\n", g_alert_counts[ALERT_SYN_FLOOD]);
    printf("    ICMP Sweep alerts  : %d\n", g_alert_counts[ALERT_ICMP_SWEEP]);
    printf("    Suspicious Ports   : %d\n", g_alert_counts[ALERT_SUSPICIOUS_PORT]);

    if (g_sockfd >= 0) close(g_sockfd);
    if (g_logfp)       fclose(g_logfp);

    /* free hash table */
    for (int i = 0; i < HASH_SIZE; i++) {
        IPNode *node = g_table[i];
        while (node) {
            IPNode *next = node->next;
            free(node);
            node = next;
        }
    }
    printf(COLOR_GREEN "[*] Goodbye.\033[0m\n");
}

void handle_signal(int sig) {
    (void)sig;
    g_running = 0;
    printf("\n\033[1;33m[!] Caught signal — shutting down gracefully...\033[0m\n");
}

/* ═══════════════════════════════════════════════
 *  Banner
 * ═══════════════════════════════════════════════ */
void print_banner(void) {
    printf("\033[1;32m");
    printf("  ____  _                 _           ___ ____  ____  \n");
    printf(" / ___|(_)_ __ ___  _ __ | | ___     |_ _|  _ \\/ ___| \n");
    printf(" \\___ \\| | '_ ` _ \\| '_ \\| |/ _ \\    | || | | \\___ \\ \n");
    printf("  ___) | | | | | | | |_) | |  __/    | || |_| |___) |\n");
    printf(" |____/|_|_| |_| |_| .__/|_|\\___|   |___|____/|____/ \n");
    printf("                   |_|                                 \n");
    printf(COLOR_RESET);
    printf(COLOR_BOLD "  Lightweight Network Intrusion Detection System\n\n" COLOR_RESET);
    printf("  Interface : %s\n",   g_config.iface);
    printf("  Log file  : %s\n",   g_config.log_file);
    printf("  Verbose   : %s\n",   g_config.verbose ? "yes" : "no");
    printf("  Thresholds: PortScan=%d  SYNFlood=%d  ICMPSweep=%d  Window=%ds\n\n",
           g_config.port_scan_threshold, g_config.syn_flood_threshold,
           g_config.icmp_sweep_threshold, g_config.time_window);
}
