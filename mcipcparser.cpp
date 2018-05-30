#include "mcipcparser.h"
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonArray>
#include <QVariant>
#include <QDebug>

MCIPCParser::MCIPCParser(QObject *parent) : QObject(parent)
{

}


bool MCIPCParser::parsePacket(const QByteArray & packet)
{
	quint32 type = 0;
	type += ((unsigned char)packet.at(0)) << 24;
	type += ((unsigned char)packet.at(1)) << 16;
	type += ((unsigned char)packet.at(2)) << 8;
	type += ((unsigned char)packet.at(3)) << 0;
	if (type == 1)
	{
		//Auth message
		QJsonDocument doc = QJsonDocument::fromJson(packet.mid(4));
		QJsonObject topobject = doc.object();
		emit jsonPacketReceived(topobject);
	}
	else if (type == 3)
	{
		QJsonDocument doc = QJsonDocument::fromJson(packet.mid(16));
		QJsonObject subobj = doc.object();
		QString subname = subobj.value("name").toString();
		emit subscribeMessage(subname);
	}
	else if (type == 7)
	{
		//Subscribe
		QJsonDocument doc = QJsonDocument::fromJson(packet.mid(16));
		QJsonObject pubobj = doc.object();
		QString pubname = pubobj.value("name").toString();
		QByteArray pubmsg = pubobj.value("payload").toVariant().toByteArray();
		emit publishMessage(pubname,pubmsg);
	}
	else if (type == 0x0B)
	{
		//PTP message
		quint32 targetlen = 0;
		targetlen += ((unsigned char)packet.at(8)) << 24;
		targetlen += ((unsigned char)packet.at(9)) << 16;
		targetlen += ((unsigned char)packet.at(10)) << 8;
		targetlen += ((unsigned char)packet.at(11)) << 0;
		QString targetstr = packet.mid(12,targetlen);

		quint32 senderlen = 0;
		senderlen += ((unsigned char)packet.at(12+targetlen)) << 24;
		senderlen += ((unsigned char)packet.at(13+targetlen)) << 16;
		senderlen += ((unsigned char)packet.at(14+targetlen)) << 8;
		senderlen += ((unsigned char)packet.at(15+targetlen)) << 0;
		QString senderstr = packet.mid(16+targetlen,senderlen);
		QByteArray payload = packet.mid(16+targetlen+senderlen);
		emit ptpMessageReceived(targetstr,senderstr,payload);

	}
	else if (type == 2)
	{
		//JSON
		//return parseJsonPacket(packet.mid(4));
		QJsonDocument doc = QJsonDocument::fromJson(packet.mid(16));
		QJsonObject topobject = doc.object();
		emit jsonPacketReceived(topobject);

		return true;
	}
	else
	{
		qDebug() << "Unknown type returned:" << type;
	}
	return false;

}
bool MCIPCParser::parseJsonPacket(const QByteArray &packet)
{
	QJsonDocument doc = QJsonDocument::fromJson(packet);
	QJsonObject topobject = doc.object();
	return true;

}
