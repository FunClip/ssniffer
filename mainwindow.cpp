#include "mainwindow.h"
#include "ui_mainwindow.h"
#include <QThread>

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::MainWindow)
{
    ui->setupUi(this);
    ui->tableWidget->horizontalHeader()->setSectionResizeMode(QHeaderView::Stretch);
    npcap.init();

    // 设置可选网卡
    auto list = npcap.GetInterfaceString();
    for(auto str:list) {
        ui->comboBox->addItem(str);
    }

    // 初始化
    this->captor = new QThread();
    this->worker = new Worker();
    worker->moveToThread(this->captor);

    // 事件绑定
    //connect(ui->pushButton, &QPushButton::clicked, this, )
}

MainWindow::~MainWindow()
{
    delete ui;
    delete worker;
    delete captor;
}

