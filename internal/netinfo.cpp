#include <iostream>
#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <unordered_map>
#include <unordered_set>
#include <chrono>
#include <ctime>
#include <iomanip>
#include <fstream>
#include <vector>
#include <sstream>

struct Stats {
    int packetCount = 0;
    std::unordered_set<int> ports;
    int connectionAttempts = 0;
    std::chrono::steady_clock::time_point lastReset = std::chrono::steady_clock::now();
};

struct LogEntry {
    std::string timestamp;
    std::string src;
    int sport;
    std::string dst;
    int dport;
    int packetSize;
    int flags;
    uint32_t seq;
    uint32_t ack;
    int window;
};

std::string nowString() {
    auto t = std::time(nullptr);
    std::stringstream ss;
    ss << std::put_time(std::localtime(&t), "%Y%m%d_%H%M%S");
    return ss.str();
}

int main() {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *alldevs, *d;

    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        std::cerr << "Error finding devices: " << errbuf << std::endl;
        return 1;
    }

    pcap_if_t* chosen = nullptr;

    for (d = alldevs; d != nullptr; d = d->next) {
        std::string name = d->name;
        if (name == "ap1" || name == "awdl0" || name == "llw0" || name == "p2p0")
            continue;

        for (pcap_addr_t* addr = d->addresses; addr; addr = addr->next) {
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

    pcap_t *handle = pcap_open_live(chosen->name, BUFSIZ, 1, 1000, errbuf);
    if (!handle) {
        std::cerr << "Couldn't open device " << chosen->name << ": " << errbuf << std::endl;
        return 1;
    }

    pcap_freealldevs(alldevs);

    std::unordered_map<std::string, Stats> ipStats;
    struct pcap_pkthdr header;
    const u_char *packet;

    std::vector<LogEntry> logBuffer;
    auto minuteStart = std::chrono::steady_clock::now();

    while (true) {
        packet = pcap_next(handle, &header);
        auto now = std::chrono::steady_clock::now();

        if (packet == nullptr)
            continue;

        struct ip* ip_hdr = (struct ip*)(packet + 14);
        if (ip_hdr->ip_p != IPPROTO_TCP)
            continue;

        struct tcphdr* tcp_hdr =
            (struct tcphdr*)(packet + 14 + ip_hdr->ip_hl * 4);

        std::string src = inet_ntoa(ip_hdr->ip_src);
        std::string dst = inet_ntoa(ip_hdr->ip_dst);
        int sport = ntohs(tcp_hdr->th_sport);
        int dport = ntohs(tcp_hdr->th_dport);

        auto t = std::time(nullptr);
        std::stringstream ts;
        ts << std::put_time(std::localtime(&t), "%Y-%m-%d %H:%M:%S");

        logBuffer.push_back({
            ts.str(),
            src,
            sport,
            dst,
            dport,
            static_cast<int>(header.len),
            tcp_hdr->th_flags,
            ntohl(tcp_hdr->th_seq),
            ntohl(tcp_hdr->th_ack),
            ntohs(tcp_hdr->th_win)
        });

        auto &s = ipStats[src];

        if (std::chrono::duration_cast<std::chrono::seconds>(now - s.lastReset).count() >= 1) {
            s.packetCount = 0;
            s.ports.clear();
            s.connectionAttempts = 0;
            s.lastReset = now;
        }

        s.packetCount++;
        s.ports.insert(dport);
        if (tcp_hdr->th_flags & TH_SYN)
            s.connectionAttempts++;

        std::cout << "[" << ts.str() << "] "
                  << src << ":" << sport << " -> "
                  << dst << ":" << dport << "\n";

        if (s.packetCount > 200) {
            std::cout << "ALERT FloodSuspected Source=" << src
                      << " PacketsPerSecond=" << s.packetCount << "\n";
        }

        if (s.ports.size() > 20) {
            std::cout << "ALERT PortScanSuspected Source=" << src
                      << " UniquePorts=" << s.ports.size() << "\n";
        }

        if (s.connectionAttempts > 50) {
            std::cout << "ALERT HighSynRate Source=" << src
                      << " SynCount=" << s.connectionAttempts << "\n";
        }

        std::cout << "-----------------------------\n";

        if (std::chrono::duration_cast<std::chrono::seconds>(now - minuteStart).count() >= 60) {
            std::string filename = "logs_" + nowString() + ".csv";
            std::ofstream out(filename);

            out << "timestamp,src_ip,src_port,dst_ip,dst_port,packet_size,tcp_flags,seq,ack,window\n";

            for (auto &e : logBuffer) {
                out << e.timestamp << ","
                    << e.src << ","
                    << e.sport << ","
                    << e.dst << ","
                    << e.dport << ","
                    << e.packetSize << ","
                    << e.flags << ","
                    << e.seq << ","
                    << e.ack << ","
                    << e.window << "\n";
            }

            out.close();
            logBuffer.clear();
            minuteStart = now;

            std::cout << "Saved 1-minute log to " << filename << std::endl;
        }
    }

    pcap_close(handle);
    return 0;
}
