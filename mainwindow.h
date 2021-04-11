#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QThread>

#include "worker.h"
#include "npcap.h"
#include "parser.h"


QT_BEGIN_NAMESPACE
namespace Ui { class MainWindow; }
QT_END_NAMESPACE

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    MainWindow(QWidget *parent = nullptr);
    ~MainWindow();
public slots:
    void CaptorStart();
    void SetTable(pcap_pkthdr *,const u_char *);
private:
    Ui::MainWindow *ui;
    Worker *worker;
    QThread *captor;
    Npcap npcap;
    Parser parser;
    int pkt_num;
};
#endif // MAINWINDOW_H
