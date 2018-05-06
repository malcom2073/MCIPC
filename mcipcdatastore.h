#ifndef MCIPCDATASTORE_H
#define MCIPCDATASTORE_H

#include <QString>
#include <QByteArray>
#include <QMap>
#include <QList>
class MCIPCDataStore
{
public:
	MCIPCDataStore();
	void addMessage(QString messagename,QByteArray messagepayload);
private:
	QMap<QString,QList<QByteArray> > m_messageMap;
};

#endif // MCIPCDATASTORE_H
