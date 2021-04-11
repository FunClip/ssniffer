#ifndef NPCAP_H
#define NPCAP_H

#include "pcap/Include/pcap.h"
#include <QDebug>
#include <QString>
#include <QStringList>
#include <map>

class Npcap
{
public:
    Npcap();
    ~Npcap();
    // 初始化
    int init();
    // 获取所有网卡
    int GetAllInterface();
    // 获取所有网卡的名字
    int GetInterfaceDescription();
    // 设置要抓取的网卡
    int SetInterface(QString if_des);
    // 设置过滤器
    pcap_t *SetPcapFilter(QString filter);
    // 获取所有网卡的名字字符串
    QStringList GetInterfaceString();

private:
    pcap_if_t *interfaces;  // 网卡
    pcap_if_t *current_if;  // 当前网卡
    pcap_t *adhandle;       //

    std::map<QString, QString> ifs;       // 网卡字符串

};

#endif // NPCAP_H
