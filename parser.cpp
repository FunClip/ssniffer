#include "parser.h"

Parser::Parser()
{

}

TableItem Parser::paserTableItem(pcap_pkthdr *header, const u_char *pktdata)
{
    TableItem pkt_display;
    ethernet_header *eth = (ethernet_header*)pktdata;


    switch (ntohs(eth->eth_type)) {
    case 0x0800:
        pkt_display.n_ptl = QString("IP");
        break;
    case 0x0806:
        pkt_display.n_ptl = QString("ARP");
        break;
    case 0x8035:
        pkt_display.n_ptl = QString("RARP");
        break;
    case 0x86dd:
        pkt_display.n_ptl = QString("IPv6");
        break;
    case 0x8864:
        pkt_display.n_ptl = QString("PPPoE");
        break;
    default:
        pkt_display.n_ptl = QString("UNKNOWN");
        break;
    }
    pkt_display.len = QString::number(header->len);
//    pkt_frag.tlen = header->len;

    //header should be large than 14 byte, otherwise drop it
    if(header->len >= 14) {

        ip_header *ip = (ip_header*)(pktdata+14);

//        pkt_frag.ip_id = ip->ip_id;
//        pkt_frag.ip_off = ip->ip_off;
//        pkt_frag.len = ip->ip_len;
//        for (int i = 0; i < 4; i++) {
//            pkt_frag.ip_src[i] = ip->ip_src[i];
//            pkt_frag.ip_dst[i] = ip->ip_dst[i];
//        }

        switch(ip->proto) {
        case IPPROTO_TCP:
            pkt_display.t_ptl = QString("TCP");
            break;

        case IPPROTO_UDP:
            pkt_display.t_ptl = QString("UDP");
            break;

        case IPPROTO_ICMP:
            pkt_display.t_ptl = QString("ICMP");
            break;

        case IPPROTO_IP:
            pkt_display.t_ptl = QString("IP");
            break;

        case IPPROTO_IGMP:
            pkt_display.t_ptl = QString("IGMP");
            break;

        default:
            pkt_display.t_ptl = QString("UNKNOWN");
            break;

        }

        pkt_display.src_ip = QString("%1.%2.%3.%4").arg(ip->saddr.bytes[0])
                .arg(ip->saddr.bytes[1]).arg(ip->saddr.bytes[2]).arg(ip->saddr.bytes[3]);
        pkt_display.des_ip = QString("%1.%2.%3.%4").arg(ip->daddr.bytes[0])
                .arg(ip->daddr.bytes[1]).arg(ip->daddr.bytes[2]).arg(ip->daddr.bytes[3]);


        /*ip-vhl contain version and head length infomation,
        use bytewise & operation to extract the needed data
        */
        int ip_size = (ip->ver_ihl & 0x0f) * 4;
//        pkt_frag.head_size = ip_size;
        if (ip->proto == IPPROTO_TCP) {
            tcp_header *tcp = (tcp_header *)(pktdata + 14 + ip_size);

            switch (tcp->dstport) {
            case 0x5000:
                pkt_display.a_ptl = QString("HTTP");
                break;
            case 0x1400:
            case 0x1500:
                pkt_display.a_ptl = QString("FTP");
                break;
            case 0x1700:
                pkt_display.a_ptl = QString("TELNET");
                break;
            case 0x1900:
                pkt_display.a_ptl = QString("SMTP");
                break;
            case 0x3500:
                pkt_display.a_ptl = QString("DNS");
                break;
            case 0x6e00:
                pkt_display.a_ptl = QString("POP3");
                break;
            case 0xbb01:
                pkt_display.a_ptl = QString("HTTPS");
                break;
            default:

                switch (tcp->srcport) {
                case 0x5000:
                    pkt_display.a_ptl = QString("HTTP");
                    break;
                case 0x1400:
                case 0x1500:
                    pkt_display.a_ptl = QString("FTP");
                    break;
                case 0x1700:
                    pkt_display.a_ptl = QString("TELNET");
                    break;
                case 0x1900:
                    pkt_display.a_ptl = QString("SMTP");
                break;
                case 0x3500:
                    pkt_display.a_ptl = QString("DNS");
                    break;
                case 0x6e00:
                    pkt_display.a_ptl = QString("POP3");
                    break;
                case 0xbb01:
                    pkt_display.a_ptl = QString("HTTPS");
                    break;
                default:
                    pkt_display.a_ptl = QString("UNKNOWN");
                    break;
                }
                break;
            }

        }
    }
    pkt_display.data = pktdata;
    return pkt_display;
}
