#include <iostream>
#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>

int main() {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *alldevs, *d;

    // Get list of devices
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        std::cerr << "Error finding devices: " << errbuf << std::endl;
        return 1;
    }

    // Choose first active IPv4 interface (skip macOS virtual interfaces)
    pcap_if_t* chosen = nullptr;
    for (d = alldevs; d != nullptr; d = d->next) {
        std::string name = d->name;

        // Skip useless macOS interfaces
        if (name == "ap1" || name == "awdl0" || name == "llw0" || name == "p2p0")
            continue;

        // Must have IPv4 address
        for (pcap_addr_t *addr = d->addresses; addr; addr = addr->next) {
            if (addr->addr && addr->addr->sa_family == AF_INET) {
                chosen = d;
                break;
            }
        }
        if (chosen) break;
    }

    if (!chosen) {
        std::cerr << "No suitable network interface found." << std::endl;
        pcap_freealldevs(alldevs);
        return 1;
    }

    std::cout << "Using device: " << chosen->name << std::endl;

    // Open the interface
    pcap_t *handle = pcap_open_live(chosen->name, BUFSIZ, 1, 1000, errbuf);
    if (!handle) {
        std::cerr << "Couldn't open device " << chosen->name
                  << ": " << errbuf << std::endl;
        return 1;
    }

    // Cleanup device list (not needed anymore)
    pcap_freealldevs(alldevs);

    // Packet capture loop
    struct pcap_pkthdr header;
    const u_char *packet;

    while ((packet = pcap_next(handle, &header)) != nullptr) {
        struct ip *ip_hdr = (struct ip *)(packet + 14); // skip Ethernet header
        if (ip_hdr->ip_p == IPPROTO_TCP) {
            struct tcphdr *tcp_hdr =
                (struct tcphdr *)(packet + 14 + ip_hdr->ip_hl * 4);

            std::cout << "Source IP: " << inet_ntoa(ip_hdr->ip_src) << "\n";
            std::cout << "Destination IP: " << inet_ntoa(ip_hdr->ip_dst) << "\n";
            std::cout << "Source Port: " << ntohs(tcp_hdr->th_sport) << "\n";
            std::cout << "Destination Port: " << ntohs(tcp_hdr->th_dport) << "\n";
            std::cout << "--------------------------------------\n";
        }
    }

    pcap_close(handle);
    return 0;
}
