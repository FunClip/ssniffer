#include "mainwindow.h"
#include "ui_mainwindow.h"
#include <QThread>
#include <QMessageBox>

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::MainWindow)
{
    ui->setupUi(this);
    ui->tableWidget->horizontalHeader()->setSectionResizeMode(QHeaderView::Stretch);
    ui->tableWidget->setSelectionBehavior (QAbstractItemView::SelectRows); //设置选择行为，以行为单位
    ui->tableWidget->setSelectionMode (QAbstractItemView::SingleSelection); //设置选择模式，选择单行
    ui->tableWidget->setEditTriggers(QAbstractItemView::NoEditTriggers);
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
    ui->pushButton_2->setDisabled(true);
    ui->pushButton_3->setDisabled(true);

    // 事件绑定
    connect(ui->pushButton, &QPushButton::clicked, this, &MainWindow::CaptorStart);
    connect(captor, SIGNAL(started()), worker, SLOT(startWork()));
    connect(ui->tableWidget, &QTableWidget::cellClicked, this, &MainWindow::SetDetail);

    connect(worker, &Worker::onPacketReceived, this, &MainWindow::SetTable);
    connect(ui->pushButton_2, &QPushButton::clicked, this, &MainWindow::CaptorStop);
    connect(ui->pushButton_3, &QPushButton::clicked, this, &MainWindow::Reset);
    connect(captor, &QThread::finished, this, &MainWindow::CaptorFinished);

}

MainWindow::~MainWindow()
{
    connect(captor, &QThread::finished, worker, &QObject::deleteLater);
    if(captor->isRunning()){
        captor->quit();
        captor->wait();
    }
    else {
        delete worker;
    }
    delete ui;
}

void MainWindow::CaptorStart()
{
    this->npcap.SetInterface(ui->comboBox->currentText());

    QString filter = ui->lineEdit->text();

    pcap_t *adhandle = npcap.SetPcapFilter(filter);

    if(adhandle == NULL) {
        QMessageBox::information(this, tr("Error"), "过滤条件错误！", QMessageBox::Ok);
    }
    else {
        worker->setadhandle(adhandle);
        worker->isRunning = true;

        ui->pushButton->setDisabled(true);
        ui->comboBox->setDisabled(true);
        ui->lineEdit->setDisabled(true);
        ui->pushButton_2->setEnabled(true);
        ui->pushButton_3->setDisabled(true);

        captor->start();
    }
}

void MainWindow::SetTable(pcap_pkthdr *header, u_char *pktdata)
{
    qDebug() << "SetTable....\n";
    auto pkt = parser.paserTableItem(header, pktdata);
    pkt.id = pkt_num;
    ui->tableWidget->insertRow(pkt_num);
//    ui->tableWidget->setItem(pkt_num, 0, new QTableWidgetItem(pkt.id));
    ui->tableWidget->setItem(pkt_num, 0, new QTableWidgetItem(pkt.time));
    ui->tableWidget->setItem(pkt_num, 1, new QTableWidgetItem(pkt.src_ip));
    ui->tableWidget->setItem(pkt_num, 2, new QTableWidgetItem(pkt.des_ip));
    ui->tableWidget->setItem(pkt_num, 3, new QTableWidgetItem(pkt.n_ptl));
    ui->tableWidget->setItem(pkt_num, 4, new QTableWidgetItem(pkt.t_ptl));
    ui->tableWidget->setItem(pkt_num, 5, new QTableWidgetItem(pkt.a_ptl));
    ui->tableWidget->setItem(pkt_num, 6, new QTableWidgetItem(pkt.len));
    ui->tableWidget->setItem(pkt_num, 7, new QTableWidgetItem(pkt.data));
    pkt_num++;
}

void MainWindow::SetDetail(int row, int)
{
    disconnect(ui->tableWidget, &QTableWidget::cellClicked, this, &MainWindow::SetDetail);

    auto data = ui->tableWidget->item(row, 7)->text();
    auto detail = parser.paserDetailItem(data);
    ui->plainTextEdit->setPlainText(detail);

    auto bytes = parser.paserBytesDisplay(data);
    ui->plainTextEdit_2->setPlainText(bytes);

    connect(ui->tableWidget, &QTableWidget::cellClicked, this, &MainWindow::SetDetail);
}

void MainWindow::CaptorStop()
{
    ui->pushButton_2->setDisabled(true);
    worker->isRunning = false;
    captor->quit();
    captor->wait();
}

void MainWindow::CaptorFinished()
{
    ui->pushButton->setEnabled(true);
    ui->pushButton_3->setEnabled(true);
    ui->comboBox->setEnabled(true);
    ui->lineEdit->setEnabled(true);
}

void MainWindow::Reset()
{
    pkt_num = 0;
    ui->lineEdit->clear();
    ui->plainTextEdit->clear();
    ui->plainTextEdit_2->clear();
    ui->tableWidget->clearContents();
    ui->tableWidget->setRowCount(pkt_num);
}


