#ifndef WORKER_H
#define WORKER_H

#include <QObject>
#include "pcap/Include/pcap.h"

class Worker : public QObject
{
    Q_OBJECT
public:
    explicit Worker(QObject *parent = nullptr);
    void setadhandle(pcap_t *con_adhandle){ adhandle = con_adhandle; }
public slots:
    void startWork();
signals:
    void onStart(pcap_t *);
    void onPacketReceived(pcap_pkthdr *,const u_char *);
    void onFinished();

private:
    pcap_t *adhandle;
};

#endif // WORKER_H
