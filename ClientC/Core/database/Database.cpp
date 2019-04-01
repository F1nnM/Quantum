#include "Database.h"
#include "Node.h"

namespace database {

	Node *firstNode;

	Database::Database() {
		firstNode = 0;
	}

	void Database::addData(char* sender, unsigned char* content, int type, long timestamp) {
		if (firstNode == 0) {
			firstNode = new Node(sender, content, type, timestamp);
		}
		else {
			firstNode->insert(new Node(sender, content, type, timestamp));
		}
	}

	Database::~Database() {

	}
}