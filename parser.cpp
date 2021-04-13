#include "parser.h"
#include "util.h"

Parser::Parser()
{

}

TableItem Parser::paserTableItem(pcap_pkthdr *header, u_char *pktdata)
{
    TableItem pkt_display;
    ethernet_header *eth = (ethernet_header*)pktdata;

    pkt_display.time = getCurrentTime(header->ts.tv_sec);

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

    //header should be large than 14 byte, otherwise drop it
    if(pkt_display.n_ptl == "IP" && header->len >= 14) {

        ip_header *ip = (ip_header*)(pktdata+14);

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
    else if(pkt_display.n_ptl == "ARP" && header->len >= 14) {
        arp_header *arp = (arp_header *)(pktdata + 14);

        pkt_display.src_ip =  QString("%1.%2.%3.%4")
                                            .arg(arp->srcip.bytes[0])
                                            .arg(arp->srcip.bytes[1])
                                            .arg(arp->srcip.bytes[2])
                                            .arg(arp->srcip.bytes[3]) + "\n";

        pkt_display.des_ip =  QString("%1.%2.%3.%4")
                                            .arg(arp->dstip.bytes[0])
                                            .arg(arp->dstip.bytes[1])
                                            .arg(arp->dstip.bytes[2])
                                            .arg(arp->dstip.bytes[3]);
    }
    char *tmp = (char *)pktdata;
    pkt_display.data = QString::fromLatin1(tmp, header->len);
    free(pktdata);
    free(header);
    return pkt_display;
}

QString Parser::paserDetailItem(QString data)
{
    QString detail;
    QString protocol;

    detail.append("协议分析：\n");

    QByteArray tmp = data.toLatin1();
    unsigned char *pktdata = (unsigned char *)tmp.data();

    // 链路层
    detail.append("\t以太帧头部：\n");
    ethernet_header *eth = (ethernet_header*)pktdata;
    switch (ntohs(eth->eth_type)) {
    case 0x0800:
        // IP
        protocol = "IP";
        break;
    case 0x0806:
        // ARP
        protocol = "ARP";
        break;
    case 0x8035:
        // RARP
        protocol = "RARP";
        break;
    case 0x86dd:
        // IPv6
        protocol = "IPv6";
        break;
    case 0x8864:
        // PPPoE
        protocol = "PPPoE";
        break;
    default:
        // UNKNOWN
        protocol = "UNKNOWN";
        break;
    }
    auto smac = QString("%1:%2:%3:%4:%5:%6").arg(eth->srcaddr.bytes[0], 0, 16)
                                                       .arg(eth->srcaddr.bytes[1], 0, 16)
                                                       .arg(eth->srcaddr.bytes[2], 0, 16)
                                                       .arg(eth->srcaddr.bytes[3], 0, 16)
                                                       .arg(eth->srcaddr.bytes[4], 0, 16)
                                                       .arg(eth->srcaddr.bytes[5], 0, 16);

    auto dmac = QString("%1:%2:%3:%4:%5:%6").arg(eth->dstaddr.bytes[0], 0, 16)
                                                       .arg(eth->dstaddr.bytes[1], 0, 16)
                                                       .arg(eth->dstaddr.bytes[2], 0, 16)
                                                       .arg(eth->dstaddr.bytes[3], 0, 16)
                                                       .arg(eth->dstaddr.bytes[4], 0, 16)
                                                       .arg(eth->dstaddr.bytes[5], 0, 16);
    detail += "\t\t源MAC地址：" + smac + "\n";
    detail += "\t\t目的MAC地址：" + dmac + "\n";
    detail += "\t\t协议类型：" + QString("0x%1").arg(eth->eth_type, 0, 16)+ "(" + protocol + ")\n";

    //header should be large than 14 byte, otherwise drop it
    if(protocol == "IP" && data.length() >= 14) {

        ip_header *ip = (ip_header*)(pktdata+14);

        switch(ip->proto) {
        case IPPROTO_TCP:
            // TCP
            protocol = "TCP";
            break;

        case IPPROTO_UDP:
            // UDP
            protocol = "UDP";
            break;

        case IPPROTO_ICMP:
            // ICMP
            protocol = "ICMP";
            break;

        case IPPROTO_IP:
            // IP
            protocol = "IP";
            break;

        case IPPROTO_IGMP:
            // IGMP
            protocol = "IGMP";
            break;

        default:
            // UNKNOWN
            protocol = "UNKNOWN";
            break;

        }

        auto src_ip = QString("%1.%2.%3.%4").arg(ip->saddr.bytes[0])
                .arg(ip->saddr.bytes[1]).arg(ip->saddr.bytes[2]).arg(ip->saddr.bytes[3]);
        auto des_ip = QString("%1.%2.%3.%4").arg(ip->daddr.bytes[0])
                .arg(ip->daddr.bytes[1]).arg(ip->daddr.bytes[2]).arg(ip->daddr.bytes[3]);
        detail += "\tIP头部：\n";
        detail += "\t\t版本：" + QString("%1").arg(ip->ver_ihl >> 4) + "\n";
        detail += "\t\t报头长度：" + QString("%1").arg((ip->ver_ihl & 0x0f) * 4) + "\n";
        detail += "\t\t服务类型：" + QString("%1").arg(ip->tos) + "\n";
        detail += "\t\t总长度：" + QString("%1").arg(ip->tlen) + "\n";
        detail += "\t\t标识：" + QString("%1").arg(ip->identification) + "\n";
        detail += "\t\t标志位：" + QString("DF(%1) MF(%2)")
                .arg((ip->flags_fo & 0x4000) == 0 ? 0 : 1)
                .arg((ip->flags_fo & 0x2000) == 0 ? 0 : 1) + "\n";
        detail += "\t\t片偏移：" + QString("%1").arg(ip->flags_fo & 0x1fff) + "\n";
        detail += "\t\t生存周期：" + QString("%1").arg(ip->ttl) + "\n";
        detail += "\t\t协议：" + QString("%1(%2)").arg(ip->proto).arg(protocol) + "\n";
        detail += "\t\t头部校验和：" + QString("%1").arg(ip->crc, 0, 16) + "\n";
        detail += "\t\t源IP地址：" + src_ip + "\n";
        detail += "\t\t目的IP地址：" + des_ip + "\n";


        int ip_size = (ip->ver_ihl & 0x0f) * 4;
        if (ip->proto == IPPROTO_TCP) {
            tcp_header *tcp = (tcp_header *)(pktdata + 14 + ip_size);

            switch (tcp->dstport) {
            case 0x5000:
                protocol = "HTTP";
                break;
            case 0x1400:
            case 0x1500:
                protocol = QString("FTP");
                break;
            case 0x1700:
                protocol = QString("TELNET");
                break;
            case 0x1900:
                protocol = QString("SMTP");
                break;
            case 0x3500:
                protocol = QString("DNS");
                break;
            case 0x6e00:
                protocol = QString("POP3");
                break;
            case 0xbb01:
                protocol = QString("HTTPS");
                break;
            default:

                switch (tcp->srcport) {
                case 0x5000:
                    protocol = QString("HTTP");
                    break;
                case 0x1400:
                case 0x1500:
                    protocol = QString("FTP");
                    break;
                case 0x1700:
                    protocol = QString("TELNET");
                    break;
                case 0x1900:
                    protocol = QString("SMTP");
                break;
                case 0x3500:
                    protocol = QString("DNS");
                    break;
                case 0x6e00:
                    protocol = QString("POP3");
                    break;
                case 0xbb01:
                    protocol = QString("HTTPS");
                    break;
                default:
                    protocol = QString("UNKNOWN");
                    break;
                }
                break;
            }

            detail += "\tTCP包头部：\n";
            detail += "\t\t源端口：" + QString("%1").arg(tcp->srcport) + "\n";
            detail += "\t\t目的端口：" + QString("%1").arg(tcp->dstport) + "\n";
            detail += "\t\t顺序号：" + QString("%1").arg(tcp->seq) + "\n";
            detail += "\t\t确认号：" + QString("%1").arg(tcp->ack) + "\n";
            detail += "\t\tTCP头部长度：" + QString("%1").arg(tcp->headerlen_rsv_flags >> 12) + "\n";
            detail += "\t\t标志位：" + QString("URG(%1), ACK(%2), PSH(%3), RST(%4), SYN(%5), FIN(%6)")
                                        .arg((tcp->headerlen_rsv_flags & 0x0020) == 0 ? 0 : 1)
                                        .arg((tcp->headerlen_rsv_flags & 0x0010) == 0 ? 0 : 1)
                                        .arg((tcp->headerlen_rsv_flags & 0x0008) == 0 ? 0 : 1)
                                        .arg((tcp->headerlen_rsv_flags & 0x0004) == 0 ? 0 : 1)
                                        .arg((tcp->headerlen_rsv_flags & 0x0002) == 0 ? 0 : 1)
                                        .arg((tcp->headerlen_rsv_flags & 0x0001) == 0 ? 0 : 1) + "\n";
            detail += "\t\t窗口大小：" + QString("%1").arg(tcp->win_size) + "\n";
            detail += "\t\t校验和：" + QString("0x%1").arg(tcp->chksum, 0, 16) + "\n";
            detail += "\t\t紧急指针：" + QString("0x%1").arg(tcp->urg_ptr, 0, 16) + "\n";
        }
        else if(ip->proto == IPPROTO_UDP) {
            udp_header *udp = (udp_header *)(pktdata + 14 + ip_size);

            detail += "\tUDP包头部：\n";
            detail += "\t\t源端口：" + QString("%1").arg(udp->sport) + "\n";
            detail += "\t\t目的端口：" + QString("%1").arg(udp->dport) + "\n";
            detail += "\t\tUDP数据包长度：" + QString("%1").arg(udp->len) + "\n";
            detail += "\t\t校验和：" + QString("0x%1").arg(udp->crc, 0, 16) + "\n";
        }
        else if(ip->proto == IPPROTO_ICMP) {
            icmp_header *icmp = (icmp_header *)(pktdata + 14 + ip_size);

            detail += "\tICMP包头部：\n";
            detail += "\t\t类型：" + QString("%1").arg(icmp->type) + "\n";
            detail += "\t\t代码：" + QString("%1").arg(icmp->code) + "\n";
            detail += "\t\t校验和：" + QString("0x%1").arg(icmp->chksum, 0, 16) + "\n";
        }
        else if(ip->proto == IPPROTO_IGMP) {
            igmp_header *igmp = (igmp_header *)(pktdata + 14 + ip_size);

            detail += "\tIGMP包头部：\n";
            detail += "\t\t版本：" + QString("%1").arg(igmp->type >> 4) + "\n";
            detail += "\t\t类型：" + QString("%1").arg(igmp->type) + "\n";
            if((igmp->type >> 4) > 1)
                detail += "\t\t最大响应时间：" + QString("%1").arg(igmp->max_resp_time) + "\n";
            detail += "\t\t校验和：" + QString("%1").arg(igmp->checksum) + "\n";
            detail += "\t\t组地址：" + QString("%1.%2.%3.%4").arg(igmp->grp_address.bytes[0])
                            .arg(igmp->grp_address.bytes[1]).arg(igmp->grp_address.bytes[2]).arg(igmp->grp_address.bytes[3]) + "\n";

        }
    }
    else if(protocol == "ARP" && data.length() >= 14) {
        arp_header *arp = (arp_header *)(pktdata + 14);

        detail += "\tARP报文：\n";
        detail += "\t\t硬件类型：" + QString("%1").arg(arp->hwtype) + "\n";
        detail += "\t\t协议类型：" + QString("%1").arg(arp->ptype)  + "\n";
        detail += "\t\t硬件地址长度：" + QString("%1").arg(arp->hwlen)  + "\n";
        detail += "\t\t协议长度：" + QString("%1").arg(arp->plen)  + "\n";
        detail += "\t\t操作类型：" + QString("%1").arg(arp->opcode)  + "\n";
        detail += "\t\t发送方MAC地址：" + QString("%1:%2:%3:%4:%5:%6")
                                            .arg(arp->srcmac.bytes[0], 0, 16)
                                            .arg(arp->srcmac.bytes[1], 0, 16)
                                            .arg(arp->srcmac.bytes[2], 0, 16)
                                            .arg(arp->srcmac.bytes[3], 0, 16)
                                            .arg(arp->srcmac.bytes[4], 0, 16)
                                            .arg(arp->srcmac.bytes[5], 0, 16) + "\n";
        detail += "\t\t发送方IP地址：" + QString("%1.%2.%3.%4")
                                            .arg(arp->srcip.bytes[0])
                                            .arg(arp->srcip.bytes[1])
                                            .arg(arp->srcip.bytes[2])
                                            .arg(arp->srcip.bytes[3]) + "\n";
        detail += "\t\t接收方MAC地址：" + QString("%1:%2:%3:%4:%5:%6")
                                            .arg(arp->dstmac.bytes[0], 0, 16)
                                            .arg(arp->dstmac.bytes[1], 0, 16)
                                            .arg(arp->dstmac.bytes[2], 0, 16)
                                            .arg(arp->dstmac.bytes[3], 0, 16)
                                            .arg(arp->dstmac.bytes[4], 0, 16)
                                            .arg(arp->dstmac.bytes[5], 0, 16)  + "\n";
        detail += "\t\t接收方IP地址：" + QString("%1.%2.%3.%4")
                                            .arg(arp->dstip.bytes[0])
                                            .arg(arp->dstip.bytes[1])
                                            .arg(arp->dstip.bytes[2])
                                            .arg(arp->dstip.bytes[3]) + "\n";
    }
    return detail;
}

QString Parser::paserBytesDisplay(QString data)
{
    QByteArray tmp = data.toLatin1();
    unsigned char *buf = (unsigned char *)tmp.data();
    int buf_len = data.length();

    QString bytes;

    int i, j, mod = buf_len % 16;
    int n = 16 - mod;
    for (i = 0; i < buf_len; i++)
    {
        if (i % 16 == 0 && i != 0)
        {
            bytes += "\n";
        }
        bytes += QString::asprintf("%02x ", buf[i]);
        if ((i + 1) % 16 == 0)
        {
            bytes += "\t";
            for (j = i - 15; j <= i; j++)
            {
                if (j == i - 8)
                    bytes += " ";
                if (buf[j] >= 32 && buf[j] < 127)
                    bytes += QString::asprintf("%c", buf[j]);
                else
                    bytes += ".";
            }
        }
    }
    for (i = 0; i < n; i++)
        bytes += "   ";
    bytes += "\t";
    for (i = buf_len - mod; i < buf_len; i++)
    {
        if (i == buf_len - mod + 8)
            bytes += " ";
        if (buf[i] >= 32 && buf[i] < 127)
            QString::asprintf("%c", buf[i]);
        else
            bytes += ".";
    }
    return bytes;
}
