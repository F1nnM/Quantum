package util;

import java.sql.Timestamp;

public class Message {

    private String sender;
    private Timestamp timestamp;
    private byte[] data;
    private type type;

    public Message(String sender, Timestamp timestamp, byte[] data, type type) {
        this.sender = sender;
        this.timestamp = timestamp;
        this.data = data;
        this.type = type;
    }

    enum type {
        TEXT((byte) 0x1),
        IMAGE((byte) 0x2),
        FILE((byte) 0x3);

        private Byte value;

        private type(Byte value) {
            this.value = value;
        }

        public Byte getValue() {
            return value;
        }
    }
}
