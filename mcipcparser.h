#ifndef MCIPCPARSER_H
#define MCIPCPARSER_H

#include <QObject>
#include <QJsonObject>

class MCIPCParser : public QObject
{
	Q_OBJECT
public:
	explicit MCIPCParser(QObject *parent = 0);
	bool parsePacket(const QByteArray & packet);
	bool parseJsonPacket(const QByteArray &packet);

signals:
	void jsonPacketReceived(QJsonObject message);
	void subscribeMessage(QString message);
	void publishMessage(QString name, QByteArray payload);
	void ptpMessageReceived(QString target,QString sender,QByteArray payload);
public slots:
};

#endif // MCIPCPARSER_H
