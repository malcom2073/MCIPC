#include "mcipcparser.h"
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonArray>
#include <QVariant>
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
		QJsonDocument doc = QJsonDocument::fromJson(packet.mid(4));
		QJsonObject subobj = doc.object();
		QString subname = subobj.value("name").toString();
		emit subscribeMessage(subname);
	}
	else if (type == 7)
	{
		//Subscribe
		QJsonDocument doc = QJsonDocument::fromJson(packet.mid(4));
		QJsonObject pubobj = doc.object();
		QString pubname = pubobj.value("name").toString();
		QByteArray pubmsg = pubobj.value("payload").toVariant().toByteArray();
		emit publishMessage(pubname,pubmsg);
	}
	if (type == 2)
	{
		//JSON
		//return parseJsonPacket(packet.mid(4));
		QJsonDocument doc = QJsonDocument::fromJson(packet.mid(4));
		QJsonObject topobject = doc.object();
		emit jsonPacketReceived(topobject);

		return true;
	}
	return false;

}
bool MCIPCParser::parseJsonPacket(const QByteArray &packet)
{
	QJsonDocument doc = QJsonDocument::fromJson(packet);
	QJsonObject topobject = doc.object();
	return true;

}
