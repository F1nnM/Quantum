package networking;

import com.google.common.primitives.Bytes;
import encryption.AESEncryption;
import encryption.RSAEncryption;
import main.Main;
import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;
import util.Result;
import util.Util;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.Random;

public class Client {

    private AESEncryption enc;

    public Client(Socket socket) {
        enc = null;
        try {
            init(socket);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private void init(Socket socket) throws Exception {
        DataInputStream in = new DataInputStream(socket.getInputStream());
        DataOutputStream out = new DataOutputStream(socket.getOutputStream());

        byte[] rec = new byte[in.readInt()];
        in.readFully(rec);

        rec = Main.rsaEncryption.decryptByte(rec);
        Result<Byte, byte[]> res = Util.getCode(rec);

        if (res.getKey().equals(Util.initConnection)) {
            System.out.println("Starting first connect");
            firstConnect(res.getValue(), out, in, socket);
        } else if (res.getKey().equals(Util.restartConnection)) {
            restartConnection(res.getValue(), out, in, socket);
        } else {
            //TODO Abort connection
        }
    }

    private void firstConnect(byte[] rsaKey, DataOutputStream out, DataInputStream in, Socket socket) throws GeneralSecurityException, IOException, DecoderException, InterruptedException {
        AESEncryption aesEncryption = new AESEncryption();

        System.out.println("Sending AES key");
        System.out.println("Checksum " + Hex.encodeHexString(Util.generateChecksum(rsaKey)));
        byte[] send = new RSAEncryption(rsaKey, null).encryptByte(Bytes.concat(aesEncryption.getKey(), aesEncryption.getIv(), Util.generateChecksum(rsaKey)));
        out.writeInt(send.length);
        out.write(send);
        out.flush();

        System.out.println(Hex.encodeHexString(aesEncryption.getKey()));

        //while (in.available() <= 0) Thread.sleep(1);
        byte[] rec = new byte[in.readInt()];
        in.readFully(rec);
        rec = aesEncryption.decryptByte(rec);

        System.out.println("Sending integer");
        send = aesEncryption.encrypt(String.valueOf(Integer.parseInt(new String(rec, StandardCharsets.UTF_8)) * 2));
        out.writeInt(send.length);
        out.write(send);

        enc = aesEncryption;

        rec = new byte[in.readInt()];
        in.readFully(rec);
        rec = enc.decryptByte(rec);

        byte[][] tmp = Util.split(rec);

        if (tmp.length == 2) { //Got username and password only
            //TODO Check username and password combo
            byte[] sid = new byte[12], did = new byte[12];
            //TODO Send real sid and did
            Random r = new Random();
            r.nextBytes(sid);
            r.nextBytes(did);

            send = enc.encryptByte(Bytes.concat(new byte[]{Util.ok}, sid, Util.delimiterA, did));
            out.writeInt(send.length);
            out.write(send);
            System.out.println("Sending sid " + Hex.encodeHexString(sid) + " and did " + Hex.encodeHexString(did));
        } else {//Got username, password and deviceID
            //TODO Check username, password and deviceID combo
            byte[] sid = new byte[12];
            Random r = new Random();
            r.nextBytes(sid);

            send = enc.encryptByte(Bytes.concat(new byte[]{Util.ok}, sid));
            out.writeInt(send.length);
            out.write(send);
            System.out.println("Sending sid");
        }

        rec = new byte[in.readInt()];
        in.readFully(rec);
        rec = enc.decryptByte(rec);
        if (!((Byte) rec[0]).equals(Util.ok)) {
            out.close();
            in.close();
            socket.close();
            enc = null;
            return;
        }

        out.flush();
        System.out.println("handshake done");
    }

    private void restartConnection(byte[] sessionID, DataOutputStream out, DataInputStream in, Socket socket) throws IOException {
        //TODO check if session id is valid
        byte[] send = new byte[]{Util.ok};
        out.writeInt(send.length);
        out.write(send);
        out.flush();

        //TODO get Encryption
        byte[] rec = new byte[in.readInt()];
        in.readFully(rec);        //TODO check if login data is correct

        send = new byte[]{Util.ok};
        out.writeInt(send.length);
        out.write(send);
        out.flush();
    }
}