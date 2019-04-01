#include "Node.h"

namespace database {

	Node* firstSuccessor; //Smaller timestamp
	Node* secondSuccessor; //Bigger timestamp

	char* sender;
	unsigned char* data;
	int type;
	long timestamp;

	Node::Node(char* _sender, unsigned char* _data, int _type, long _timestamp)
	{
		firstSuccessor = 0;
		secondSuccessor = 0;

		sender = _sender;
		data = _data;
		type = _type;
		timestamp = _timestamp;
	}

	void Node::insert(Node* toInsert) {
		if (toInsert->getTimestamp() < timestamp) {
			if (firstSuccessor == 0) {
				firstSuccessor = toInsert;
			}
			else {
				firstSuccessor->insert(toInsert);
			}
		}
		else {
			if (secondSuccessor == 0)
			{
				secondSuccessor = toInsert;
			}
			else {
				secondSuccessor->insert(toInsert);
			}
		}
	}

	long Node::getTimestamp() {
		return timestamp;
	}

	Node* Node::find(long _timestamp) {
		if (_timestamp < timestamp) {
			if (firstSuccessor == 0) return 0;
			else return firstSuccessor->find(timestamp);
		}
		else if (_timestamp > timestamp) {
			if (secondSuccessor == 0) return 0;
			else return secondSuccessor->find(timestamp);
		}
		else {
			return this;
		}
	}

	Node::~Node()
	{
		delete(sender);
		delete(data);
	}
}