#include "util.h"

QString utf82gbk(QString str)
{
    QTextCodec *utf8 = QTextCodec::codecForName("UTF-8");

    QTextCodec::setCodecForLocale(utf8);

    QTextCodec* gbk = QTextCodec::codecForName("gbk");


    //utf8 -> gbk

    //1. utf8 -> unicode

    QString strUnicode= utf8->toUnicode(str.toLocal8Bit().data());

    //2. unicode -> gbk, 得到QByteArray

    QByteArray gb_bytes= gbk->fromUnicode(strUnicode);

    return QString::fromLocal8Bit(gb_bytes);
}

QString utf82gb2312(QString str)
{
    QTextCodec *utf8 = QTextCodec::codecForName("UTF-8");

    QTextCodec::setCodecForLocale(utf8);

    QTextCodec* gbk = QTextCodec::codecForName("gb2312");

    QString strUnicode= utf8->toUnicode(str.toLocal8Bit().data());

    QByteArray gb_bytes= gbk->fromUnicode(strUnicode);

    return QString::fromLocal8Bit(gb_bytes);
}
