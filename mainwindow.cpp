#include "mainwindow.h"
#include "ui_mainwindow.h"
#include <QThread>

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::MainWindow)
{
    ui->setupUi(this);
    ui->tableWidget->horizontalHeader()->setSectionResizeMode(QHeaderView::Stretch);
    ui->tableWidget->hideColumn(7);
    npcap.init();

    // 设置可选网卡
    auto list = npcap.GetInterfaceString();
    for(auto& str:list) {
        ui->comboBox->addItem(str);
    }

    // 初始化
    this->captor = new QThread();
    this->worker = new Worker();
    worker->moveToThread(this->captor);
    this->pkt_num = 0;

    // 事件绑定
    connect(ui->pushButton, &QPushButton::clicked, this, &MainWindow::CaptorStart);
    connect(captor, SIGNAL(started()), worker, SLOT(startWork()));

    connect(worker, &Worker::onPacketReceived, this, &MainWindow::SetTable);
}

MainWindow::~MainWindow()
{
    delete ui;
    delete worker;
}

void MainWindow::CaptorStart()
{
    this->npcap.SetInterface(ui->comboBox->currentText());

    QString filter = ui->lineEdit->text();

    pcap_t *adhandle = npcap.SetPcapFilter(filter);

    worker->setadhandle(adhandle);

    captor->start();
}

void MainWindow::SetTable(pcap_pkthdr *header, const u_char *pktdata)
{
    qDebug() << "SetTable....\n";
    auto pkt = parser.paserTableItem(header, pktdata);
    pkt.id = pkt_num;
    ui->tableWidget->insertRow(pkt_num);
//    ui->tableWidget->setItem(pkt_num, 0, new QTableWidgetItem(pkt.id));
    ui->tableWidget->setItem(pkt_num, 1, new QTableWidgetItem(pkt.time));
    ui->tableWidget->setItem(pkt_num, 2, new QTableWidgetItem(pkt.src_ip));
    ui->tableWidget->setItem(pkt_num, 3, new QTableWidgetItem(pkt.des_ip));
    ui->tableWidget->setItem(pkt_num, 4, new QTableWidgetItem(pkt.n_ptl));
    ui->tableWidget->setItem(pkt_num, 5, new QTableWidgetItem(pkt.t_ptl));
    ui->tableWidget->setItem(pkt_num, 6, new QTableWidgetItem(pkt.a_ptl));
    ui->tableWidget->setItem(pkt_num, 7, new QTableWidgetItem(pkt.len));
    pkt_num++;
}

