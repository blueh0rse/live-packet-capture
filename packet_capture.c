#include <stdio.h>
#include <stdlib.h>
// Include packet capture
#include <pcap/pcap.h>
// Include IP header definitions
#include <netinet/ip.h>
// Include TCP header definitions
#include <netinet/tcp.h>
// Include IP address manipulation
#include <arpa/inet.h>
// Timestamp conversion
#include <time.h>

void display_packets(u_char *user_data, const struct pcap_pkthdr *pkthdr, const u_char *packet)
{
    // Extract IP and TCP headers from packet data
    // Skip ethernet header
    struct ip *ip_header = (struct ip *)(packet + 14);
    // Skip IP header
    struct tcphdr *tcp_header = (struct tcphdr *)(packet + 14 + (ip_header->ip_hl << 2));

    // Check if packet is TCP && has destination port of 80 or 443
    if (ip_header->ip_p == IPPROTO_TCP && (ntohs(tcp_header->th_dport) == 80 || ntohs(tcp_header->th_dport) == 443))
    {
        // Convert the timestamp to a human-readable format
        char timestamp_str[30];
        time_t timestamp_seconds = pkthdr->ts.tv_sec;
        struct tm *timestamp_info = localtime(&timestamp_seconds);
        strftime(timestamp_str, sizeof(timestamp_str), "%d/%m/%Y %Hh%Mmin %Ss", timestamp_info);

        // Print information about captured packet
        printf("Interface: %s\n", (const char *)user_data);
        printf("Timestamp: %s.%06ld\n", timestamp_str, pkthdr->ts.tv_usec);
        // Convert and print IP addresses
        printf("Source IP: %s\n", inet_ntoa(ip_header->ip_src));
        printf("Dest.  IP: %s\n", inet_ntoa(ip_header->ip_dst));
        printf("Packet Length: %d bytes\n", pkthdr->len);
        printf("--------------------------------\n");
    }
}

int main(int argc, char *argv[])
{
    // Error buffer for pcap functions
    char errbuf[PCAP_ERRBUF_SIZE];
    // Network device handle
    pcap_t *handle;

    // Network interface to capture
    char interface_name[] = "eth0";

    printf("Listening for packets...\n");

    // Open network device for packet capture
    handle = pcap_open_live(interface_name, 38, 1, 1000, errbuf);
    if (handle == NULL)
    {
        // Handle error if device cannot be opened (usually permissions)
        fprintf(stderr, "Error opening device %s: %s\n", interface_name, errbuf);
        return 1;
    }

    // Set filter to capture only packets with destination ports 80 or 443
    struct bpf_program fp;
    char filter_exp[] = "dst port 80 or dst port 443";
    if (pcap_compile(handle, &fp, filter_exp, 0, PCAP_NETMASK_UNKNOWN) == -1)
    {
        // Handle error if filter cannot be compiled
        fprintf(stderr, "Error compiling filter: %s\n", pcap_geterr(handle));
        return 1;
    }
    if (pcap_setfilter(handle, &fp) == -1)
    {
        // Handle error if filter cannot be set
        fprintf(stderr, "Error setting filter: %s\n", pcap_geterr(handle));
        return 1;
    }

    // Start packet capture loop for this interface
    pcap_loop(handle, 0, display_packets, (u_char *)interface_name);

    return 0;
}
