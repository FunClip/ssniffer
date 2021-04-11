#ifndef PARSER_H
#define PARSER_H

#include <QString>
#include "header.h"
#include "pcap/Include/pcap.h"


class TableItem {
public:
    TableItem() {
        id = "";
        time = "";
        src_ip = "";
        des_ip = "";
        n_ptl = "";
        t_ptl = "";
        a_ptl = "";
        len = "";
    }
    QString id;
    QString time;
    QString src_ip;
    QString des_ip;
    QString n_ptl;
    QString t_ptl;
    QString a_ptl;
    QString len;
    const u_char* data;
};

class Parser
{
public:
    Parser();
    TableItem paserTableItem(pcap_pkthdr *,const u_char *);
    int paserTreeItem(const u_char *);
};

#endif // PARSER_H
