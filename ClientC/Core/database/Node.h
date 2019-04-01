#pragma once
#ifndef NODEH
#define NODEH

namespace database {
	class Node
	{
	public:
		Node(char* _sender, unsigned char* _data, int _type, long _timestamp);
		long getTimestamp();
		void insert(Node* toInsert);
		Node* find(long _timestamp);
		~Node();

	private:
		Node* firstSuccessor;
		Node* secondSuccessor;

		char* sender;
		unsigned char* data;
		int type;
		long timestamp;
	};
}

#endif // !NODEH
