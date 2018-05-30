#ifndef MCIPC_H
#define MCIPC_H



/*

Subscribe is what a client does when it wants to receive publish events for a message
Publish is what a client does whne it wants to send out a message to all subscribers
Send Message sends a message to a specific client
Unsubscribe removes a client from the subscription list of a message.


Wire structure, checksum is not included for TCP/UDP, header is not included for UDP
Header and length are missing for UDP
| Header |  Length   |  Payload  | Checksum  |
|01|02|03|AA|BB|CC|DD|B1|B2|B3|BN|EE|FF|GG|HH|

Payload structure:
|   Type    |   Flags   | TargetLen |  Target   | SenderLen |  Sender   |  Message  |
|T1|T2|T3|T4|F1|F2|F3|F4|B1|B2|B3|B4|B1|B2|B3|BN|B1|B2|B3|B4|B1|B2|B3|BN|B1|B2|B3|BN|

TargetLen and senderlen are always included, but if zero there is no target or sender.
Only type 0x0000000B has a target, since is a PTP directed message. Any messages can have a sender, but
it is not required. (Should it be?)

Message Types from client to core:

|00|00|00|01| - Register message, contains register string
|00|00|00|03| - Subscribe Message
JSON payload should have the message name to subscribe to
|00|00|00|05| - Unsubscribe
|00|00|00|07| - Publish message
|00|00|00|0B| - Point-To-Point directed message
|00|00|00|0D| -
|00|00|00|0F| -

All messaages from server->client have a timestamp:

|    Unix timestmap     |  Payload  |
|11|22|33|44|55|66|77|88|B1|B2|B3|BN|

Message types from server to client
|00|00|00|02| - Auth reply, JSON reply giving server information
|00|00|00|04| - Subscribe reply, contains list of providers
|00|00|00|06| - UnSubscribe reply
|00|00|02|04| - Someone subscribed message
|00|00|02|08| - Publish message


On Client, to notify the core that you have a message to advertize:

MCIPC::advertizeMessage(QString message)
-calls: generateAdvertizeRequest(QString) : QByteArray
--Adds message structure message type to the front of the message
-calls: generateCorePacket(QByteArray) : QByteArray
--Wraps header, length, checksum, etc
-calls: socket->write(QByteArray)
--Sends message out the socket

On Client, subscribe to a recieve a message whenever a new one is published:
MCIPC::subscribeToMessage(QString message)
-calls: generateSubscribeRequest(QString) : QByteArray
--Adds message structure message type to the front of the message
-calls: generateCorePacket(QByteArray) : QByteArray
--Adds a header, length, and checksum if needed
-calls: socket->write(QByteArray)
--Sends message out the socket

On client, recieve thread:
MCIPC::onDataReady()
-Adds incoming bytes to buffer
-calls: parsePackets(QByteArray) on the buffer
--Scans through the buffer for any packets
--Parses header, length, and grabs single packet
--calls: parseSingle(QByteArray)
---checks message type, fires appropriate event.


On Server:
MCIPC::readyRead()
Adds bytes to a per-client buffer
calls parseBuffer(QTcpSocket*)

MCIPC::parseBuffer(QTcpSocket*)
Figures out if there is a whole message in the buffer,
if so, take it out of the buffer and add it to the processing queue.
Trigger the next queue hop.

MCIPC::processQueue(QTcpSocket*)
Process message queue.
If it's a subscribe message, add to subscriber queue
If it's a advertize message, add to the advertize queue
etc


Binary blob multi part. First 4 bytes are index, second 4 are total, then the rest are the blob.
Eg:
|Packet Num |Total packets|Binary bytes|
|L1|L2|L3|L4|T1|T2|T3| T4 |B1|B2|BN-8|


One core running per machine

Multiple cores per net

Client connects to core, authenticates, sends subscribe, advertize, and broadcast requests
Cores tell each other which clients are connected, which advertizes, and which subscribers needed
Cores can also transmit broadcast requests depending on the netmask

Core networks set up like dbus

A media library machine would have a core with the name:
/local/media/library
Then some clients, with the names:
/local/media/library/media_scanner
/local/media/library/media_metadata
/local/media/library/media_internet_info

When you broadcast out to /local/media, then everyone on /local/media would get it
You could broadcast out to /local, or /, and then everyone on local, or globally, would get it.



*/


#include <QObject>
#include <QMap>
#include "mcipcparser.h"
#include "mcipcdatastore.h"

class QTcpSocket;
class QTcpServer;

class MCIPC : public QObject
{
	Q_OBJECT
public:
	explicit MCIPC(QString key, QObject *parent = 0);
	MCIPC(QTcpSocket *socket, QObject *parent = 0);
	void connectToHost(QString address, int portNum);
	MCIPCParser *parser() { return m_parser; }
	void sendJsonMessage(QString target, QJsonObject object);

	void sendMessage(QString target,QByteArray content,QString sender = QString());
	void subscribeMessage(QString messageName);
	void publishMessage(QString messageName,QByteArray content);
	QByteArray generateCorePacket(QByteArray messageBytes);
	void setName(QString key);
	const QString & name() { return m_key; }
private:
	MCIPCDataStore *m_ipcDataStore;
	QByteArray generateSubscribeMessage(QString messageName);
	QByteArray generatePublishMessage(QString messageName,QByteArray payload);
	QByteArray generateSendMessage(QString target,QString sender,QByteArray payload);
	QTcpSocket *m_socket;
	QTcpServer *m_server;
	QString m_key;

	//These sockets have connected and authenticated.
	QMap<QString,QTcpSocket*> m_serverSocketMap;
	QMap<QTcpSocket*,QString> m_socketServerNameMap;

	//These sockets have connected, but not authenticated.
	QByteArray m_socketBuffer;
	QList<QTcpSocket*> m_serverSocketListPreAuth;
	MCIPCParser *m_parser;
	QMap<QTcpSocket*,QByteArray> m_serverSocketBuffer;
	QByteArray makeJsonPacket(QJsonObject message);
	void checkBuffer();
	QByteArray generateAuthMessage(QString key);

	QList<QByteArray> m_packetBuffer;
signals:
	void si_incomingMessage(QByteArray message);
	void si_incomingSubscribedMessage(QString id, QByteArray message);
	void si_connected();
	void si_disconnected();
	void si_jsonPacketReceived(QJsonObject message);
	void si_subscribeMessage(QString message);
	void si_publishMessage(QString name, QByteArray payload);
	void si_ptpMessageReceived(QString target,QString sender,QByteArray payload);
	void si_ptpMessageReceived(QByteArray payload);
public slots:
private slots:
	void socketReadyRead();
	void socketConnected();
	void socketDisconnected();
};

#endif // MCIPC_H
