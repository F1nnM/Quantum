package util;

import com.google.common.primitives.Bytes;
import com.google.common.primitives.Longs;
import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Base64;

import java.sql.Timestamp;

public class Message {

    private String sender;
    private Timestamp timestamp;
    private byte[] data;
    private type _type;

    public Message(String sender, Timestamp timestamp, byte[] data, type type) {
        this.sender = sender;
        this.timestamp = timestamp;
        this.data = data;
        this._type = type;
    }

    public Message(byte[] input) throws DecoderException {
        byte[][] tmp = Util.split(Base64.decodeBase64(input));
        sender = new String(Base64.decodeBase64(tmp[0]));
        timestamp = new Timestamp(Longs.fromByteArray(Base64.decodeBase64(tmp[1])));
        data = Base64.decodeBase64(tmp[2]);
        _type = type.fromByte(tmp[3][0]);
    }

    public byte[] toByteArray() {
        return Base64.encodeBase64(Bytes.concat(Base64.encodeBase64(sender.getBytes()), Util.delimiterA, Base64.encodeBase64(Longs.toByteArray(timestamp.getTime())), Util.delimiterA, Base64.encodeBase64(data), Util.delimiterA, _type.getAsByteArray()));
    }

    enum type {
        TEXT((byte) 0x1),
        IMAGE((byte) 0x2),
        FILE((byte) 0x3);

        private Byte value;

        type(Byte value) {
            this.value = value;
        }

        public static type fromByte(Byte b) {
            switch (b) {
                case 0x1:
                    return TEXT;
                case 0x2:
                    return IMAGE;
                case 0x3:
                    return FILE;
                default:
                    return null;
            }
        }

        public Byte getValue() {
            return value;
        }

        public byte[] getAsByteArray() {
            return new byte[]{value};
        }
    }
}
