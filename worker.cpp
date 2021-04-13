#include "worker.h"

Worker::Worker(QObject *parent) : QObject(parent)
{
    isRunning = true;
}

void Worker::startWork()
{
    emit onStart(adhandle);
    qDebug("Starting");
    struct pcap_pkthdr *header;
    const u_char *pkt_data;
    int res = 0;
    while (isRunning && ((res = pcap_next_ex(adhandle, &header,&pkt_data))>=0))
    {

        if(res == 0)
            continue;
        unsigned char *tmp_data = NULL;
        tmp_data = (unsigned char *)malloc(header->len);
        memcpy(tmp_data, pkt_data, header->len);

        struct pcap_pkthdr *tmp_header = NULL;
        tmp_header = (struct pcap_pkthdr *)malloc(sizeof(struct pcap_pkthdr));
        memcpy(tmp_header, header, sizeof(struct pcap_pkthdr));

        emit onPacketReceived(tmp_header, tmp_data);
    }
    if(res == -1)
    {
        qDebug("frame error: %s",pcap_geterr(adhandle));
    }

    emit onFinished();
}
