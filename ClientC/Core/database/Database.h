#include "Node.h"

#ifndef DATABASEH
#define DATABASEH

namespace database {
	class Database
	{
	public:
		Database();
		~Database();

	private:
		Database::Node* firstNode;
		void Database::addData(char* sender, unsigned char* content, int type, long timestamp);
	};
}

#endif // !DATABASEH