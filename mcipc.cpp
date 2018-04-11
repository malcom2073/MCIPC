#include "mcipc.h"

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
	m_key = key;
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
	m_socket = socket;
	connect(m_socket,SIGNAL(readyRead()),this,SLOT(socketReadyRead()));
	//connect(m_socket,SIGNAL(connected()),this,SLOT(socketConnected()));
	connect(m_socket,SIGNAL(disconnected()),this,SLOT(socketDisconnected()));
}

void MCIPC::startServer(int portNum)
{
	m_server = new QTcpServer(this);
	connect(m_server,SIGNAL(newConnection()),this,SLOT(serverNewConnection()));
	m_server->listen(QHostAddress::LocalHost,portNum);
	qDebug() << "Server Started";
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
	QByteArray prebuf;
	prebuf.append(0x01);
	prebuf.append(0x02);
	prebuf.append(0x03);


	QByteArray postbuf;
	postbuf.append((char)0x00);
	postbuf.append((char)0x00);
	postbuf.append((char)0x00);
	postbuf.append((char)0x00);
	QString package = "{\"type\":\"auth\",\"key\":\"" + m_key + "\"}";
	prebuf.append(((unsigned char)((package.length()+4) >> 24)) & 0xFF);
	prebuf.append(((unsigned char)((package.length()+4) >> 16)) & 0xFF);
	prebuf.append(((unsigned char)((package.length()+4) >> 8)) & 0xFF);
	prebuf.append(((unsigned char)((package.length()+4) >> 0)) & 0xFF);
	prebuf.append((char)0x00);
	prebuf.append((char)0x00);
	prebuf.append((char)0x00);
	prebuf.append(0x01);
	socket->write(prebuf);
	socket->write(package.toLatin1());
	socket->write(postbuf);
	emit si_connected();
}

void MCIPC::socketDisconnected()
{
	//We have been disconnected, emit disconnected, and get rid of the socket.
	emit si_disconnected();
	m_socket->deleteLater();
	m_socket = 0;
}
void MCIPC::serverNewConnection()
{
	qDebug() << "Incoming connection";
	QTcpSocket *socket = m_server->nextPendingConnection();
	m_serverSocketListPreAuth.append(socket);
	m_serverSocketBuffer.insert(socket,QByteArray());
	connect(socket,SIGNAL(readyRead()),this,SLOT(serverReadyRead()));
	connect(socket,SIGNAL(disconnected()),this,SLOT(serverDisconnected()));
}
void MCIPC::serverReadyRead()
{
	qDebug() << "ServerReadyRead";
	m_socketBuffer.append(m_socket->readAll());
	qDebug() << "Buffer size:" << m_socketBuffer.size();
	checkBuffer();
/*

	QByteArray packet;
	while (decodePacket(&m_serverSocketBuffer[socket],&packet))
	{
		m_parser->parsePacket(m_socketServerNameMap[socket],packet);
	}*/
	//emit incomingMessage(packet);
}
void MCIPC::serverDisconnected()
{

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
		}
	}
	qDebug() << "Bad packet:" << m_socketBuffer.toHex();
	return;
}

bool MCIPC::decodePacket(QByteArray *buffer,QByteArray *packet)
{
	if (buffer->size() <= 11)
	{
		//Not large enough for auth
		qDebug() << "Not enough for auth:" << buffer->size();
		return false;
	}
	if (buffer->at(0) == 0x01 && buffer->at(1) == 0x02 && buffer->at(2) == 0x03)
	{
		//Start byte! Read length
		quint32 length = 0;
		length += ((unsigned char)buffer->at(3)) << 24;
		length += ((unsigned char)buffer->at(4)) << 16;
		length += ((unsigned char)buffer->at(5)) << 8;
		length += ((unsigned char)buffer->at(6)) << 0;
		qDebug() << "Length:" << length;
		if (buffer->size() >= length+11)
		{
			//We have a full packet! Should be an auth packet, so download and verify!
			qDebug() << "Buffer size before:" << buffer->size();
			*packet = buffer->mid(7,length);
			qDebug() << "JSON:" << *packet;
			buffer->remove(0,length+11);
			qDebug() << "Buffer size after:" << buffer->size();
			return true;
		}
		else
		{
			qDebug() << "Bad length";
		}
	}
	qDebug() << "Bad packet:" << buffer->toHex();
	return false;
}

bool MCIPC::checkAuth(QTcpSocket *socket,QByteArray *buffer)
{
	QByteArray packet;
	if (!decodePacket(buffer,&packet))
	{
		//Nothing found!
		qDebug() << "Auth failure";
		return false;
	}

	QJsonDocument doc = QJsonDocument::fromJson(packet);
	QJsonObject topobject = doc.object();
	if (topobject.contains("type") && topobject.value("type").toString() == "auth")
	{
		if (topobject.contains("key"))
		{
			QString key = topobject.value("key").toString();
			m_serverSocketMap[key] = socket;
			m_socketServerNameMap[socket] = key;
			qDebug() << "Good auth";
			return true;
		}

	}
	return false;
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
