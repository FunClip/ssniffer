#ifndef HEADER_H
#define HEADER_H

#include <winsock.h>

/* 4字节的IP地址 */
typedef struct ip_address{
    u_char bytes[4];
}ip_address;

/* 6字节的MAC地址 */
typedef struct MAC_Address
{
    u_char		bytes[6];

}MAC_address;

/* 以太网头部 */
typedef struct Ethernet_Header
{
    MAC_address	dstaddr;				// 目的MAC地址
    MAC_address	srcaddr;				// 源MAC地址
    u_short		eth_type;				// 类型

}ethernet_header;

/* ARP头部 */
typedef struct ARP_Header
{
    u_short		hwtype;					// 硬件类型
    u_short		ptype;					// 协议类型
    u_char		hwlen;					// 硬件长度
    u_char		plen;					// 协议长度
    u_short		opcode;					// 操作码
    MAC_address	srcmac;					// 源MAC地址
    ip_address	srcip;					// 源IP地址
    MAC_address	dstmac;					// 目的MAC地址
    ip_address	dstip;					// 目的IP地址

}arp_header;

/* ICMP首部 */
typedef struct ICMP_Header
{
    u_char		type;					// 类型
    u_char		code;					// 代码
    u_short		chksum;					// 校验和
    u_int		others;					// 首部其他部分（由报文类型来确定相应内容）

}icmp_header;

/* IPv4 首部 */
typedef struct ip_header{
    u_char  ver_ihl;        // 版本 (4 bits) + 首部长度 (4 bits)
    u_char  tos;            // 服务类型(Type of service)
    u_short tlen;           // 总长(Total length)
    u_short identification; // 标识(Identification)
    u_short flags_fo;       // 标志位(Flags) (3 bits) + 段偏移量(Fragment offset) (13 bits)
    u_char  ttl;            // 存活时间(Time to live)
    u_char  proto;          // 协议(Protocol)
    u_short crc;            // 首部校验和(Header checksum)
    ip_address  saddr;      // 源地址(Source address)
    ip_address  daddr;      // 目的地址(Destination address)
    u_int   op_pad;         // 选项与填充(Option + Padding)
}ip_header;

/* UDP 首部*/
typedef struct udp_header{
    u_short sport;          // 源端口(Source port)
    u_short dport;          // 目的端口(Destination port)
    u_short len;            // UDP数据包长度(Datagram length)
    u_short crc;            // 校验和(Checksum)
}udp_header;

/* TCP首部 */
typedef struct TCP_Header
{
    u_short		srcport;				// 源端口
    u_short		dstport;				// 目的端口
    u_int		seq;					// 序号
    u_int		ack;					// 确认号
    u_short		headerlen_rsv_flags;	// 首部长度(4 bits) + 保留(6 bits) +
                                        // URG(1 bit) + ACK(1 bit) + PSH(1 bit) + RST(1 bit) + SYN(1 bit) + FIN(1 bit)
    u_short		win_size;				// 窗口大小
    u_short		chksum;					// 校验和
    u_short		urg_ptr;				// 紧急指针
    u_int		option;					// 选项

}tcp_header;

/* IGMP首部 */
typedef struct IGMP_Header
{
    u_char      type;                   // 类型
    u_char      max_resp_time;          // 最大响应时间
    u_short     checksum;               // 校验和
    ip_address  grp_address;            // 组播地址
}igmp_header;



#endif // HEADER_H
