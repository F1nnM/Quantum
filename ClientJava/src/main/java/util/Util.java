package util;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;

public class Util {

    public static final byte[] delimiterA = new byte[]{0x0};
    public static final byte delimiter = 0x0;
    public static final byte ok = 0x1;
    public static final byte initConnection = 0x2;
    public static final byte restartConnection = 0x3;
    public static final byte wrongPassword = 0x4;
    public static final byte sendTo = 0x5;
    public static final byte endConnection = 0x6;
    public static final byte error = 0x7;

    public static byte[] addCommand(byte command, byte[] toAddTo) throws IOException {
        return concat(new byte[]{command}, toAddTo);
    }

    public static byte[] concat(byte[]... byteArrays) throws IOException {
        ByteArrayOutputStream byteOs = new ByteArrayOutputStream();
        for (byte[] arr : byteArrays) {
            byteOs.write(arr);
        }

        byteOs.flush();
        byte[] tmp = byteOs.toByteArray();
        byteOs.close();

        return tmp;
    }

    public static boolean contains(Byte b, byte[] bytes) {
        for (Byte b1 : bytes) {
            if (b.equals(b1)) {
                return true;
            }
        }
        return false;
    }

    /**
     * splits a byte array by the delimiter 0x0
     *
     * @param input the array to split
     * @return the resulting byte arrays
     */
    public static byte[][] split(byte[] input) {
        ArrayList<byte[]> tmp = new ArrayList<>();
        int lastDelimiter = 0;
        for (int i = 0; i < input.length; i++) {
            if (((Byte) input[i]).equals(delimiter)) {
                tmp.add(Arrays.copyOfRange(input, lastDelimiter, i));
                lastDelimiter = i + 1;
            }
        }

        if (lastDelimiter != input.length) {
            tmp.add(Arrays.copyOfRange(input, lastDelimiter, input.length));
        }

        //Convert ArrayList to Array
        byte[][] res = new byte[tmp.size()][];
        for (int i = 0; i < tmp.size(); i++) {
            res[i] = tmp.get(i);
        }

        return res;
    }

    public static Result<Byte, byte[]> getCode(byte[] input) {
        byte code = input[0];
        byte[] tmp = Arrays.copyOfRange(input, 1, input.length);

        return new Result<Byte, byte[]>() {
            @Override
            public Byte getKey() {
                return code;
            }

            @Override
            public byte[] getValue() {
                return tmp;
            }
        };
    }

    public static byte[] generateChecksum(byte[] in) {
        MessageDigest md = null;
        try {
            md = MessageDigest.getInstance("MD5");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace(); //Should not be thrown
        }
        assert md != null;
        md.update(in);
        return md.digest();
    }
}