#include "worker.h"

Worker::Worker(QObject *parent) : QObject(parent)
{

}

void Worker::startWork()
{
    emit onStart(adhandle);
    qDebug("Starting");
    struct pcap_pkthdr *header;
    const u_char *pkt_data;
    int res;
    while ((res = pcap_next_ex(adhandle, &header,&pkt_data))>=0)
    {

        if(res == 0)
            continue;
        emit onPacketReceived(pkt_data);
    }
    if(res == -1)
    {
        qDebug("frame error: %s",pcap_geterr(adhandle));
    }

    emit onFinished();
}
