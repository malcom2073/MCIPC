#include "mcipcdatastore.h"

MCIPCDataStore::MCIPCDataStore()
{

}
void MCIPCDataStore::addMessage(QString messagename,QByteArray messagepayload)
{
	if (!m_messageMap.contains(messagename))
	{
		m_messageMap.insert(messagename,QList<QByteArray>());
	}
	m_messageMap[messagename].append(messagepayload);
}
