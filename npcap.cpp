#include "npcap.h"
#include "util.h"
#include <winsock2.h>
#include <iphlpapi.h>
#include <QLibrary>
#include <stdlib.h>
#include <Qt>
#include <string>

typedef int (*MyGetInterfaceInfo)(PIP_ADAPTER_INFO, PULONG) ;

Npcap::Npcap()
{
    this->current_if = NULL;
}

Npcap::~Npcap()
{
    if(this->current_if)
        pcap_freealldevs(this->current_if);
}

int Npcap::init()
{
    this->GetAllInterface();

    this->GetInterfaceDescription();
    // TODO: debug

    return 0;
}

int Npcap::GetAllInterface()
{
    char err[PCAP_ERRBUF_SIZE];
    if(pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &interfaces, err) == -1){
        qDebug("Error in pcap_findalldevs_ex, info: %s\n", err);
        return 1;
    }
    return 0;
}

int Npcap::GetInterfaceDescription()
{
    QLibrary mylib("iphlpapi");
    if(mylib.load()) {
        qDebug("iphlpapi load success");
    }
    else {
        qDebug("iphlpapi load error");
        return 1;
    }

    MyGetInterfaceInfo func = (MyGetInterfaceInfo)mylib.resolve("GetAdaptersInfo");
    if(!func){
        qDebug("GetAdaptorsInfo load error");
        return 1;
    }

    PIP_ADAPTER_INFO pIpAdapterInfo = (IP_ADAPTER_INFO *) malloc(sizeof (IP_ADAPTER_INFO));
    //得到结构体大小,用于GetAdaptersInfo参数
    unsigned long stSize = sizeof(IP_ADAPTER_INFO);
    //调用GetAdaptersInfo函数,填充pIpAdapterInfo指针变量;其中stSize参数既是一个输入量也是一个输出量

    int nRel = func(pIpAdapterInfo,&stSize);
    if(nRel == ERROR_BUFFER_OVERFLOW) {
        free(pIpAdapterInfo);
        pIpAdapterInfo = (IP_ADAPTER_INFO *) malloc(stSize);
        nRel = func(pIpAdapterInfo,&stSize);
    }
    if(nRel != ERROR_SUCCESS) {
        qDebug("Error in GetAdaptorsInfo, error num: %d", nRel);
    }
    int i = 0;
    while(pIpAdapterInfo) {
        this->ifs[pIpAdapterInfo->Description] = pIpAdapterInfo->AdapterName;

        qDebug("No.%d: %s\t%s\n", i++, pIpAdapterInfo->AdapterName, pIpAdapterInfo->Description);
        pIpAdapterInfo = pIpAdapterInfo->Next;
    }

    return 0;
}

int Npcap::SetInterface(QString if_des)
{
    auto p = this->interfaces;
    while(p) {
        if(QString(p->name).contains(this->ifs[if_des], Qt::CaseInsensitive)) {
            this->current_if = p;
            qDebug("Choose interface: %s\n", p->name);
            return 0;
        }
        p = p->next;
    }
    qDebug() << "Can not find interface " << if_des;
    return 1;
}

pcap_t *Npcap::SetPcapFilter(QString filter)
{
    u_int netmask;
    struct bpf_program fcode;

    char errbuf[PCAP_ERRBUF_SIZE];
    /* 打开适配器 返回adhandle*/
    adhandle= pcap_open(
                current_if->name,  // 设备名
                65536,     // 要捕捉的数据包的部分
                // 65535保证能捕获到不同数据链路层上的每个数据包的全部内容
                PCAP_OPENFLAG_PROMISCUOUS,         // 混杂模式
                1000,      // 读取超时时间
                NULL,      // 远程机器验证
                errbuf     // 错误缓冲池
            );

    if (adhandle == NULL)
    {
        qDebug("\nUnable to open the adapter. %s is not supported by WinPcap\n",current_if->name);
        /* 释放设备列表 */
        pcap_freealldevs(current_if);
        return NULL;
    }

    /* 检查数据链路层，为了简单，我们只考虑以太网 */
    if(pcap_datalink(adhandle) != DLT_EN10MB)
    {
        qDebug("\nThis program works only on Ethernet networks.\n");
        /* 释放设备列表 */
        pcap_freealldevs(current_if);
        return NULL;
    }

    if(current_if->addresses != NULL)
        /* 获得接口第一个地址的掩码 */
        netmask=((struct sockaddr_in *)(current_if->addresses->netmask))->sin_addr.S_un.S_addr;
    else
        /* 如果接口没有地址，那么我们假设一个C类的掩码 */
        netmask=0xffffff;


    //编译过滤器 char packet_filter[] = "host 192.168.204.128";
    if (pcap_compile(adhandle, &fcode, filter.toStdString().c_str(), 1, netmask) <0 )
    {
        qDebug("\nUnable to compile the packet filter. Check the syntax.\n%s\n",filter.toStdString().c_str());
        /* 释放设备列表 */
        pcap_freealldevs(current_if);
        return NULL;
    }

    //设置过滤器
    if (pcap_setfilter(adhandle, &fcode)<0)
    {
        qDebug("\nError setting the filter.\n");
        /* 释放设备列表 */
        pcap_freealldevs(current_if);
        return NULL;
    }

    qDebug("\nlistening on %s...\n", current_if->description);

    return adhandle;
}

QStringList Npcap::GetInterfaceString()
{
    QStringList list;
    for(auto &in:this->ifs) {
        list.append(in.first);
    }
    return list;
}
