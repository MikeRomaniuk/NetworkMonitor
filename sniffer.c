#include "linux/kobject.h"
#include "linux/slab.h"
#include <linux/ip.h>
#include <linux/list.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/sysfs.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/in.h>
static int __init sniffer_init(void);
static void __exit sniffer_exit(void);

unsigned int hook_func(void *priv, struct sk_buff *skb,
                       const struct nf_hook_state *state);

void handle_packet(struct sk_buff *skb);

void check_addrs(struct sk_buff *skb, struct iphdr *iph);
void check_protocol(struct sk_buff *skb, struct iphdr *iph);
void check_ports(struct sk_buff *skb, struct iphdr *iph);

void print_udp_data(struct sk_buff *skb, struct iphdr *iph,
                    struct udphdr *udph);
void print_tcp_data(struct sk_buff *skb, struct iphdr *iph,
                    struct tcphdr *tcph);
void pkt_hex_dump(struct sk_buff *skb);

bool protocol_in_list(u8 protocol);
bool ports_in_list(u16 sport, u16 dport);
bool addrs_in_list(u32 saddr, u32 daddr);

void clear_watch_addrs(void);
void clear_watch_ports(void);
void clear_watch_protocols(void);

static struct nf_hook_ops nfho;

static LIST_HEAD(watch_ports);
static LIST_HEAD(watch_addrs);
static LIST_HEAD(watch_protocols);

struct watch_port {
    struct list_head list;
    u16 port;
};

struct watch_addr {
    struct list_head list;
    u32 addr;
};

struct watch_protocol {
    struct list_head list;
    u8 protocol;
};

void clear_watch_ports(void) {
    struct watch_port *entry, *tmp;
    list_for_each_entry_safe(entry, tmp, &watch_ports, list) {
        list_del(&entry->list);
        kfree(entry);
    }
}

void clear_watch_addrs(void) {
    struct watch_addr *entry, *tmp;
    list_for_each_entry_safe(entry, tmp, &watch_addrs, list) {
        list_del(&entry->list);
        kfree(entry);
    }
}

void clear_watch_protocols(void) {
    struct watch_protocol *entry, *tmp;
    list_for_each_entry_safe(entry, tmp, &watch_protocols, list) {
        list_del(&entry->list);
        kfree(entry);
    }
}

char settings_buffer[256];
static struct kobject *sniffer;

static ssize_t settings_store(struct kobject *kobj, struct kobj_attribute *attr,
                              const char *buf, size_t count) {
    strncpy(settings_buffer, buf, 256);
    return count;
}

static ssize_t settings_show(struct kobject *kobj, struct kobj_attribute *attr,
                             char *buf) {
    return sysfs_emit(buf, "%s\n", settings_buffer);
}

static struct kobj_attribute settings_attribute =
    __ATTR(settings_buffer, 0664, settings_show, settings_store);

bool protocol_in_list(u8 protocol) {
    struct watch_protocol *entry;
    list_for_each_entry(entry, &watch_protocols, list) {
        if (protocol == entry->protocol) {
            return true;
        }
    }
    return false;
}

bool addrs_in_list(u32 saddr, u32 daddr) {
    struct watch_addr *entry;
    list_for_each_entry(entry, &watch_addrs, list) {
        if ((saddr == entry->addr) || (daddr == entry->addr)) {
            return true;
        }
    }
    return false;
}

bool ports_in_list(u16 sport, u16 dport) {
    struct watch_port *entry;
    list_for_each_entry(entry, &watch_ports, list) {
        if ((sport == entry->port) || (dport == entry->port)) {
            return true;
        }
    }
    return false;
}

void handle_packet(struct sk_buff *skb) {
    struct iphdr *iph;

    iph = ip_hdr(skb);

    check_protocol(skb, iph);
}

void check_protocol(struct sk_buff *skb, struct iphdr *iph) {
    if (list_empty(&watch_protocols)) {
        check_addrs(skb, iph);
    } else {
        if (protocol_in_list(iph->protocol)) {
            check_addrs(skb, iph);
        }
    }
}

void check_addrs(struct sk_buff *skb, struct iphdr *iph) {
    u32 saddr, daddr;

    saddr = ntohl(iph->saddr);
    daddr = ntohl(iph->daddr);

    if (list_empty(&watch_addrs)) {
        check_ports(skb, iph);
    } else {
        if (addrs_in_list(saddr, daddr)) {
            check_ports(skb, iph);
        }
    }
}

void check_ports(struct sk_buff *skb, struct iphdr *iph) {
    u16 sport, dport;
    struct tcphdr *tcph;
    struct udphdr *udph;

    switch (iph->protocol) {
    case IPPROTO_TCP:
        tcph = tcp_hdr(skb);
        sport = ntohs(tcph->source);
        dport = ntohs(tcph->dest);
        if (ports_in_list(sport, dport)) {
            print_tcp_data(skb, iph, tcph);
        }
        break;
    case IPPROTO_UDP:
        udph = udp_hdr(skb);
        sport = ntohs(udph->source);
        dport = ntohs(udph->dest);
        if (ports_in_list(sport, dport)) {
            print_udp_data(skb, iph, udph);
        }
        break;
    default:
        pr_info("sniffer: Unsoported protocol %d", iph->protocol);
        break;
    }
}

void print_tcp_data(struct sk_buff *skb, struct iphdr *iph,
                    struct tcphdr *tcph) {
    u16 sport, dport;
    u32 saddr, daddr;

    saddr = ntohl(iph->saddr);
    daddr = ntohl(iph->daddr);
    sport = ntohs(tcph->source);
    dport = ntohs(tcph->dest);

    pr_info("sniffer: TCP: %pI4h:%d -> %pI4h:%d\n", &saddr, sport, &daddr,
            dport);

    pkt_hex_dump(skb);
}

void print_udp_data(struct sk_buff *skb, struct iphdr *iph,
                    struct udphdr *udph) {
    u16 sport, dport;
    u32 saddr, daddr;

    saddr = ntohl(iph->saddr);
    daddr = ntohl(iph->daddr);
    sport = ntohs(udph->source);
    dport = ntohs(udph->dest);

    pr_info("sniffer: UDP: %pI4h:%d -> %pI4h:%d\n", &saddr, sport, &daddr,
            dport);

    pkt_hex_dump(skb);
}

void pkt_hex_dump(struct sk_buff *skb) {
    size_t len;
    int rowsize = 16;
    int i, l, linelen, remaining;
    int li = 0;
    uint8_t *data, ch;

    pr_info("Packet hex dump:\n");
    data = (uint8_t *)skb_mac_header(skb);

    if (skb_is_nonlinear(skb)) {
        len = skb->data_len;
    } else {
        len = skb->len;
    }

    remaining = len;
    for (i = 0; i < len; i += rowsize) {
        pr_info("%06d\t", li);

        linelen = min(remaining, rowsize);
        remaining -= rowsize;

        for (l = 0; l < linelen; l++) {
            ch = data[l];
            pr_info(KERN_CONT "%02X ", (uint32_t)ch);
        }

        data += linelen;
        li += 10;

        pr_info(KERN_CONT "\n");
    }
}
unsigned int hook_func(void *priv, struct sk_buff *skb,
                       const struct nf_hook_state *state) {
    if (!skb)
        return NF_ACCEPT;

    handle_packet(skb);

    return NF_ACCEPT;
}

static int __init sniffer_init(void) {
    int res;

    nfho.hook = hook_func;              /* hook function */
    nfho.hooknum = NF_INET_PRE_ROUTING; /* received packets */
    nfho.pf = PF_INET;                  /* IPv4 */
    nfho.priority = NF_IP_PRI_FIRST;    /* max hook priority */

    // Example of possible setting.
    struct watch_port *port = kmalloc(sizeof(struct watch_port), GFP_KERNEL);
    if (port == NULL) {
        return -ENOMEM;
    }
    port->port = 443;
    list_add(&port->list, &watch_ports);

    res = nf_register_net_hook(&init_net, &nfho);
    if (res < 0) {
        pr_err("sniffer: error in nf_register_net_hook()\n");
        return res;
    }
    sniffer = kobject_create_and_add("sniffer", kernel_kobj);

    if (!sniffer)
        return -ENOMEM;

    res = sysfs_create_file(sniffer, &settings_attribute.attr);

    if (res) {
        kobject_put(sniffer);
        pr_info("sniffer: failed to create the settings file in "
                "/sys/kernel/sniffer\n");
    } else {
        pr_info("sniffer: loaded\n");
    }

    return res;
}

static void __exit sniffer_exit(void) {
    clear_watch_addrs();
    clear_watch_protocols();
    clear_watch_ports();

    nf_unregister_net_hook(&init_net, &nfho);

    kobject_put(sniffer);
    pr_info("sniffer: unloaded\n");
}

module_init(sniffer_init);
module_exit(sniffer_exit);

MODULE_AUTHOR("Me&&Co");
MODULE_DESCRIPTION("Module for sniffing packet data");
MODULE_LICENSE("GPL");
