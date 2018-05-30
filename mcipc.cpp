#include "mcipc.h"
#include <QDateTime>
#include <QTcpSocket>
#include <QTcpServer>
#include <QJsonDocument>
#include <QJsonArray>
#include <QJsonObject>
#include "mcipcparser.h"

MCIPC::MCIPC(QString key, QObject *parent) : QObject(parent)
{
	m_parser = new MCIPCParser(this);
	connect(m_parser,SIGNAL(jsonPacketReceived(QJsonObject)),this,SIGNAL(si_jsonPacketReceived(QJsonObject)));
	connect(m_parser,SIGNAL(publishMessage(QString,QByteArray)),this,SIGNAL(si_publishMessage(QString,QByteArray)));
	connect(m_parser,SIGNAL(subscribeMessage(QString)),this,SIGNAL(si_subscribeMessage(QString)));
	connect(m_parser,SIGNAL(ptpMessageReceived(QString,QString,QByteArray)),this,SIGNAL(si_ptpMessageReceived(QString,QString,QByteArray)));
	m_key = key;
	m_ipcDataStore = new MCIPCDataStore();
}
void MCIPC::setName(QString key)
{
	m_key = key;
}

MCIPC::MCIPC(QTcpSocket *socket, QObject *parent) : QObject(parent)
{
	m_parser = new MCIPCParser(this);
	connect(m_parser,SIGNAL(jsonPacketReceived(QJsonObject)),this,SIGNAL(si_jsonPacketReceived(QJsonObject)));
	connect(m_parser,SIGNAL(publishMessage(QString,QByteArray)),this,SIGNAL(si_publishMessage(QString,QByteArray)));
	connect(m_parser,SIGNAL(subscribeMessage(QString)),this,SIGNAL(si_subscribeMessage(QString)));
	connect(m_parser,SIGNAL(ptpMessageReceived(QString,QString,QByteArray)),this,SIGNAL(si_ptpMessageReceived(QString,QString,QByteArray)));
	m_socket = socket;
	connect(m_socket,SIGNAL(readyRead()),this,SLOT(socketReadyRead()));
	//connect(m_socket,SIGNAL(connected()),this,SLOT(socketConnected()));
	connect(m_socket,SIGNAL(disconnected()),this,SLOT(socketDisconnected()));
	m_ipcDataStore = new MCIPCDataStore();
}


void MCIPC::connectToHost(QString address, int portNum)
{
	m_socket = new QTcpSocket(this);
	connect(m_socket,SIGNAL(readyRead()),this,SLOT(socketReadyRead()));
	connect(m_socket,SIGNAL(connected()),this,SLOT(socketConnected()));
	connect(m_socket,SIGNAL(disconnected()),this,SLOT(socketDisconnected()));
	m_socket->connectToHost(QHostAddress(address),portNum);
}
void MCIPC::socketReadyRead()
{
	qDebug() << "ServerReadyRead";
	m_socketBuffer.append(m_socket->readAll());
	qDebug() << "Buffer size:" << m_socketBuffer.size();
	checkBuffer();
}

void MCIPC::socketConnected()
{
	QTcpSocket *socket = qobject_cast<QTcpSocket*>(sender());

	QByteArray message = generateAuthMessage(m_key);
	QByteArray packet = generateCorePacket(message);
	socket->write(packet);

	emit si_connected();
}

void MCIPC::socketDisconnected()
{
	//We have been disconnected, emit disconnected, and get rid of the socket.
	emit si_disconnected();
	m_socket->deleteLater();
	m_socket = 0;
}
void MCIPC::checkBuffer()
{
	if (m_packetBuffer.size() > 0)
	{
		QByteArray buf = m_packetBuffer.at(0);
		m_packetBuffer.removeAt(0);
		m_parser->parsePacket(buf);
	}
	if (m_socketBuffer.size() <= 11)
	{
		//Not large enough for auth
		qDebug() << "Not enough for auth:" << m_socketBuffer.size();
		return;
	}
	if (m_socketBuffer.at(0) == 0x01 && m_socketBuffer.at(1) == 0x02 && m_socketBuffer.at(2) == 0x03)
	{
		//Start byte! Read length
		quint32 length = 0;
		length += ((unsigned char)m_socketBuffer.at(3)) << 24;
		length += ((unsigned char)m_socketBuffer.at(4)) << 16;
		length += ((unsigned char)m_socketBuffer.at(5)) << 8;
		length += ((unsigned char)m_socketBuffer.at(6)) << 0;
		qDebug() << "Length:" << length;
		if (m_socketBuffer.size() >= length+11)
		{
			//We have a full packet! Should be an auth packet, so download and verify!
			qDebug() << "Buffer size before:" << m_socketBuffer.size();
			QByteArray packet = m_socketBuffer.mid(7,length);
			qDebug() << "JSON:" << packet;
			m_socketBuffer.remove(0,length+11);
			m_packetBuffer.append(packet);
			qDebug() << "Buffer size after:" << m_socketBuffer.size();
			checkBuffer();
			return;
		}
		else
		{
			qDebug() << "Bad length";
			return;
		}
	}
	qDebug() << "Bad packet:" << m_socketBuffer.toHex();
	return;
}

void MCIPC::sendJsonMessage(QString target, QJsonObject object)
{
	QByteArray jsonpacket = makeJsonPacket(object);
	m_socket->write(jsonpacket);
}
QByteArray MCIPC::makeJsonPacket(QJsonObject message)
{
	QJsonDocument doc(message);
	QByteArray jsonbytes = doc.toBinaryData();


	QByteArray retval;
	//Header
	retval.append(0x01);
	retval.append(0x02);
	retval.append(0x03);

	//Length
	retval.append(((unsigned char)(jsonbytes.length() >> 24)) & 0xFF);
	retval.append(((unsigned char)(jsonbytes.length() >> 16)) & 0xFF);
	retval.append(((unsigned char)(jsonbytes.length() >> 8)) & 0xFF);
	retval.append(((unsigned char)(jsonbytes.length() >> 0)) & 0xFF);


	//Message type, JSON
	retval.append((char)0x00);
	retval.append((char)0x00);
	retval.append((char)0x00);
	retval.append((char)0x02);

	//Checksum
	retval.append((char)0x00);
	retval.append((char)0x00);
	retval.append((char)0x00);
	retval.append((char)0x00);

	return retval;
}
void MCIPC::publishMessage(QString messageName,QByteArray content)
{
	QByteArray message = generatePublishMessage(messageName,content);
	QByteArray packet = generateCorePacket(message);
	m_socket->write(packet);
}
void MCIPC::sendMessage(QString target,QByteArray content,QString sender)
{
	if (sender == "")
	{
		sender = m_key;
	}
	QByteArray message = generateSendMessage(target,sender,content);
	QByteArray packet = generateCorePacket(message);
	m_socket->write(packet);
}
QByteArray MCIPC::generateSendMessage(QString target,QString sender,QByteArray payload)
{
	QByteArray retval;

	//Message type, PTP message
	retval.append((char)0x00);
	retval.append((char)0x00);
	retval.append((char)0x00);
	retval.append((char)0x0B);

	//Message Flags
	retval.append((char)0x00);
	retval.append((char)0x00);
	retval.append((char)0x00);
	retval.append((char)0x00);

	//Length Of Target
	retval.append(((unsigned char)(target.length() >> 24)) & 0xFF);
	retval.append(((unsigned char)(target.length() >> 16)) & 0xFF);
	retval.append(((unsigned char)(target.length() >> 8)) & 0xFF);
	retval.append(((unsigned char)(target.length() >> 0)) & 0xFF);

	retval.append(target);


	//Length Of sender
	retval.append(((unsigned char)(sender.length() >> 24)) & 0xFF);
	retval.append(((unsigned char)(sender.length() >> 16)) & 0xFF);
	retval.append(((unsigned char)(sender.length() >> 8)) & 0xFF);
	retval.append(((unsigned char)(sender.length() >> 0)) & 0xFF);

	retval.append(sender);



	retval.append(payload);

	return retval;
}

void MCIPC::subscribeMessage(QString messageName)
{
	QByteArray message = generateSubscribeMessage(messageName);
	QByteArray packet = generateCorePacket(message);
	m_socket->write(packet);
}
QByteArray MCIPC::generateSubscribeMessage(QString messageName)
{
	QJsonObject messageobj;
	messageobj.insert("name",messageName);
	QJsonDocument doc(messageobj);

	QByteArray retval;

	//Message type, subscribe request
	retval.append((char)0x00);
	retval.append((char)0x00);
	retval.append((char)0x00);
	retval.append((char)0x03);

	//Message Flags
	retval.append((char)0x00);
	retval.append((char)0x00);
	retval.append((char)0x00);
	retval.append((char)0x00);

	//Targetlen
	retval.append((char)0x00);
	retval.append((char)0x00);
	retval.append((char)0x00);
	retval.append((char)0x00);

	//senderlen
	retval.append((char)0x00);
	retval.append((char)0x00);
	retval.append((char)0x00);
	retval.append((char)0x00);



	retval.append(doc.toJson());

	return retval;
}
QByteArray MCIPC::generateAuthMessage(QString key)
{
//QString package = "{\"type\":\"auth\",\"key\":\"" + m_key + "\"}";
	QJsonObject messageobj;
	messageobj.insert("type","auth");
	messageobj.insert("key",key);
	QJsonDocument doc(messageobj);
	QByteArray retval;

	//Message type, auth request
	retval.append((char)0x00);
	retval.append((char)0x00);
	retval.append((char)0x00);
	retval.append((char)0x01);

	//No message flags

	retval.append(doc.toJson());
	return retval;
}

QByteArray MCIPC::generatePublishMessage(QString messageName,QByteArray payload)
{
	QJsonObject messageobj;
	messageobj.insert("name",messageName);
	messageobj.insert("payload",QJsonValue::fromVariant(QVariant::fromValue(payload)));
	QJsonDocument doc(messageobj);

	QByteArray retval;

	//Message type, subscribe request
	retval.append((char)0x00);
	retval.append((char)0x00);
	retval.append((char)0x00);
	retval.append((char)0x07);


	//Message Flags
	retval.append((char)0x00);
	retval.append((char)0x00);
	retval.append((char)0x00);
	retval.append((char)0x00);

	//Targetlen
	retval.append((char)0x00);
	retval.append((char)0x00);
	retval.append((char)0x00);
	retval.append((char)0x00);

	//senderlen
	retval.append((char)0x00);
	retval.append((char)0x00);
	retval.append((char)0x00);
	retval.append((char)0x00);




	retval.append(doc.toJson());

	return retval;
}
\

QByteArray MCIPC::generateCorePacket(QByteArray messageBytes)
{
	QByteArray retval;
	//Header
	retval.append(0x01);
	retval.append(0x02);
	retval.append(0x03);

	//Length
	retval.append(((unsigned char)(messageBytes.length() >> 24)) & 0xFF);
	retval.append(((unsigned char)(messageBytes.length() >> 16)) & 0xFF);
	retval.append(((unsigned char)(messageBytes.length() >> 8)) & 0xFF);
	retval.append(((unsigned char)(messageBytes.length() >> 0)) & 0xFF);

	//Message
	retval.append(messageBytes);

	//Checksum
	retval.append((char)0x00);
	retval.append((char)0x00);
	retval.append((char)0x00);
	retval.append((char)0x00);

	return retval;
}
