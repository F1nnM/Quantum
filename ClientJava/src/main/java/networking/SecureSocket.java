package networking;

import com.google.common.primitives.Bytes;
import com.google.common.primitives.Longs;
import encryption.AESEncryption;
import encryption.RSAEncryption;
import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;
import org.springframework.security.crypto.bcrypt.BCrypt;
import util.Message;
import util.Result;
import util.Util;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.spec.InvalidKeySpecException;
import java.sql.Timestamp;
import java.util.Arrays;
import java.util.Random;

public class SecureSocket extends Socket {

    public static final int OK = 0;
    public static final int WRONG_PASSWORD = 1;
    public static final int CONNECTION_FAILED = 2;
    private AESEncryption enc;
    private RSAEncryption serverEnc;
    private String username, password;
    private byte[] sessionID, deviceID;
    private String rsaKey = "30820822300d06092a864886f70d01010105000382080f003082080a0282080100904bc213f149426ff1c5520132e8ebc7e582b3f3c97275f49989f83ecdad539ab7c6717360e1bd568df23cdebe74cbcd4f487d429d3bb89705b65154dffdbe52704ae5404f7acd2a283a07ba851e6286418bb2b76459916e347373c6ced9ccb396939a66ca7dbb2e57eeff0edbca0c51bce4dbafbeaee91506a114887bcb36edae048b3f07f2122585768b4b1367abeab403ac58737a6b67c6eb3c7cdb7976bb7a5e9cf64ded4debbc6d47e881053d210491eca550b7a07ff0c829d92477236d85f7c0394e0cc1b348f5d6915d051cac551e7f1a6836090620865cd0c60df90da3172ae80eea3587ad7fd883e79d1f7d27b8d1389f9828347301ec227deaa286d428333105173c2f672ec2ce8f5abff632b870480a21d192c64c45c1d8f302840c5e311466b45392eea034fbd7cf0fab950f7e93592a47c79772071f828f33a148045d9784358e7d2eb10937254ec0b3964b2a36b9deb9b8a6bb7537631724c756b19ec41f4aadc7ee0c92c108db8b951e315f00abdacb95a296933a9a2c481c0d96e6e5b0304e5d2ea1f41e4e4f3a0bdd2f2f2e31d546124896dd2a8163c9a1a933706246d179384bc488e385c607b5f4d5318a7a240d477f1ade2ead799f2ee3dd8cf63d5a8494a7a9967976ef7bd51df11fd9635c1d3155717872b69d4f4d81d09fd545ae67ee1d1dc1b7a18e6b4240724f147e2a95e3600b5610e47bd5f10e35731278fc87e2c49baee1fad3d83e50e1614e054a7498be7913dbc0c568b89f36443dcb57cb4d2474cf50278be858b9e1df10e8c30e4d601226727aca14b6d8cd06eaaecd5188739fa492f4c36095e9808d363562bb16a5a7401e0858da3f483e7f7f6ac93978828f1a687ffa8863318da44eee1103f2ed631b52d09e22945c3f7e611cc6dcfbf5ddb5a4f727908756fbea5fddde5a4c29e15c7695bfe7552677ae80d23b751bef7c01689e4b2158e8c89348224230339cc5259c8e8448f4f4cde1c6e5a3cd887ae1bcb141e4a5268cb45e5c5471db8eac1fbcd1ab7f8508ea8275a9dc4cff30e6d826454df02101b4740683e4ae5e25a6fe272b146da6d80a2a00f0acb25d8b02ddc6f19df5af3b2e5cc07dd07227d2398c39c74431e1ec9c098ca72b72c37313730f832adb538c46db62cf78b973891354452a0e04368f423a608da635205732e09d5c8ce0d6db2a7405c5636fcdde21294636ad333d926ab41b1eb0962aa75728652c9fade717f0d1fab0e217a82026c94817037eb78d6266df7c665397414996c4cb6819969df6b37b54a3898e20075f0127f58cec758a30524a5911f27586ebadaa6d62269927eee0d435b9bafec41117acc74d49fa85d8cf01a99bcc4ec8f032526fd4e52c5c24aee654e2a3572d0acd4bfaf155e514d396a55c0c4d66ad6509cd2e06143fcf4822b841f652739f783a1a58787f11135d210cfbc65172fd6e4eb5929195c4aab31f192bd99021fe2907186ddd9cd46e27b39bc19ffdd1e74f9188994b7dd356c2c1c82126947d5d96faaad6d12450313b4bab906d885856995a3c16665bc65d68b760ef1aeee9ad7f32b4dd9aa526126ae3d23ae5ff4a100a31312ae2a5915113daafa0b3d1efd70ac2d7dc4729d780e2c8c249789985fbbad32705f7e7e23e4153488b87151da5bdfde717a87fd2d26105320def96babb369376788db3362b67ecc7023a8d672f97cf99387da88050dfe6707241eb5781e297d8321690eb55767b4167a71ef88eb9bba00feded1421acc7e16692d485214111c4d407493a7150677426223ce29a209fc844f383ca6759c5957f7811eb42b422a1632a3131dccbb96bb0996f5de9cb3d3a30f805e1b466a23a798ff61991a7d499d0c3b3c65c02e3ea79b1f5ec87c8e236b3dcc618f9c873d1664859bcf6ba5b02b89c8243a65551d7e01eb37488a90e2bc859c51883fbe0157eccbe1a4b9759e9637e60b95b935e71c77a9e4b9a0c44af8db9a5f8cae9af4683775424b8a8fc00096ec398ea7f6b56b791d603aeeeee2999a2252eda144aa41decde90cce02c4071462361a411f9f77111806fbf8fc538c1aa9b9cf5fd3b46c6f9270ca07c54964c1b1a7af1f70a98e8f3ba23d980337895276f1315a643b9cf7e60fd71f4c37797550ac4ab6e1666379076d138b051001f09c488ebb338db703fcd09a04b3252c9ae4adb644cb47413da4f5061922aa53806929854f4d9b97b7c79740c835efc058396f49cb914d67340442f5de82dd8f0ea5a21416e2acce670dd9fc6f3ca91786915a0e43262e67f5ccca7a758ce68546d763afb72ed355ce58923c2ebcd294698032bb11b66bb2a989edbd2db078e3935ca9e50b526180bd7ebe3c15ccb51f03c7947f27e2a0371cdcc40b270fff982ca562e9a6939ea6c78c0c2abe633b8f47a57d6475e3c231bc0e76824afe6dd36ad764cf0b79288f4d5fc4ade2677705482b3ac63884ef6fd0a0f093e145ff3829278b44b3ddec0f41e8963c01e9e7cc65d44d7a86675996b72cf8d0bcbe4f046335b92034fb24163f1fb527f6c70122c57947b05af1004a2003e111c7efc10bec556c6ab2c8465251ecfff71f253ca555a6c039beffad7046c70a203166f18c4f1524a1ef7342ab9e3a338a6b8fb7f1a58c711aef97f64bb6613236f014a21e57b574829e70c796ee2132c16222cf0e77c1a3d383a1ad61f64c9c58ddf842935f52471154c02c389c167b2a54a59de3ee52e56654d5c413d0bd76d8cea2c6e3962616afff551b75c4509829f02d7a16e3ae25c1d343d71efcbb3e8ed3206b115f1bb542238a64af02ea595f9536de197f7bd1dc27dcfe3657fad45464431d90099e77c8d10494726934140b5624dbba4913db829ef41d1631fa4dbb8f9f9e1a393d2030203010001";
    private DataOutputStream out;
    private DataInputStream in;
    private boolean run;
    private Thread t;

    /**
     * @param deviceID      the ID of this Device, may be null
     * @param sessionID     the ID of this session, may be null
     * @param username,     the name of the user to log in
     * @param password      the password of the user to log in
     * @param aesEncryption an instance of AESEncryption class, may be null
     */
    public SecureSocket(byte[] deviceID, byte[] sessionID, String username, String password, AESEncryption aesEncryption) {
        super();
        run = false;
        try {
            serverEnc = new RSAEncryption(rsaKey.getBytes(StandardCharsets.UTF_8), null);
        } catch (InvalidKeySpecException | DecoderException e) {
            e.printStackTrace(); //TODO something's broken
        }

        enc = aesEncryption;

        this.deviceID = deviceID;
        this.sessionID = sessionID;
        this.username = username;
        this.password = password;
    }

    public void connect() throws IOException, InterruptedException, GeneralSecurityException {
        if (enc == null || sessionID == null || deviceID == null) {
            for (int i = 0; i < 10; i++) {
                firstConnect();
                if (enc != null) break;
                Thread.sleep(1000);
            }
        } else {
            reconnect();
            if (enc == null || sessionID == null || deviceID == null) connect();
        }

        run = true;

        t = new Thread(() -> {
            byte[] rec;
            while (run) {
                try {
                    rec = new byte[in.readInt()];
                    in.readFully(rec);
                    rec = enc.decryptByte(rec);
                    //TODO notify about new messages
                } catch (IOException | GeneralSecurityException e) {
                    e.printStackTrace();
                }

                try {
                    Thread.sleep(10);
                } catch (InterruptedException e) {
                    e.printStackTrace();
                }
            }
        });

        t.start();
    }

    public int sendMessage(String user, byte[] message) throws IOException, GeneralSecurityException {
        byte[] tmp = enc.encryptByte(Bytes.concat(new byte[]{Util.sendTo}, user.getBytes(), Util.delimiterA, message));
        out.writeInt(tmp.length);
        out.write(tmp);

        tmp = new byte[in.readInt()];
        in.readFully(tmp);
        tmp = enc.decryptByte(tmp);

        switch (tmp[0]) {
            case Util.ok:
                return 0;//Everything ok
            case Util.error:
                return -1;//Something went wrong
            default:
                return -2;//Blow up your house (not recommended)
        }
    }

    public Message[] getMessages(Timestamp timestamp) throws GeneralSecurityException, IOException, DecoderException {
        byte[] tmp;
        if (timestamp != null) {
            tmp = enc.encryptByte(Bytes.concat(new byte[]{Util.getMessages}, Longs.toByteArray(timestamp.getTime())));//Get all new Messages after this timestamp
        } else {
            tmp = enc.encryptByte(Bytes.concat(new byte[]{Util.getMessages}, Longs.toByteArray(-1)));//Get all new Messages since the Big Bang
        }
        out.writeInt(tmp.length);
        out.write(tmp);
        out.flush();

        tmp = new byte[in.readInt()];
        in.readFully(tmp);
        tmp = enc.decryptByte(tmp);

        Result<Byte, byte[]> res = Util.getCode(tmp);
        tmp = res.getValue();

        switch (res.getKey()) {
            case Util.getMessages: {
                byte[][] msgb = Util.split(tmp);
                Message[] msg = new Message[msgb.length];

                for (int i = 0; i < msgb.length; i++) {
                    msg[i] = new Message(msgb[i]);
                }

                return msg;
            }
            case Util.getMessagesZip: {
                tmp = Util.unzip(tmp);
                byte[][] msgb = Util.split(tmp);
                Message[] msg = new Message[msgb.length];

                for (int i = 0; i < msgb.length; i++) {
                    msg[i] = new Message(msgb[i]);
                }

                return msg;
            }
            case Util.noNewMessages:
                return new Message[0];
            default:
                return null;
        }
    }

    private void reconnect() throws IOException, GeneralSecurityException, InterruptedException {
        this.connect(new InetSocketAddress("localhost", 1234)); //TODO add port and ip

        out = new DataOutputStream(this.getOutputStream());
        in = new DataInputStream(this.getInputStream());

        System.out.println("Connected");

        System.out.println("Sending Session id");
        byte[] send = serverEnc.encryptByte(Bytes.concat(new byte[]{Util.restartConnection}, sessionID));
        out.writeInt(send.length);
        out.write(send); //Send command to restart the connection and the sessionID
        out.flush();

        byte[] rec = new byte[in.readInt()];
        in.readFully(rec);

        if (!((Byte) rec[0]).equals(Util.ok)) { //Check if Server accepts this connection
            this.close();
            out.close();
            in.close();
            enc = null;
            firstConnect();
            return;
        }

        System.out.println("Sending login data");
        send = enc.encryptByte(Bytes.concat(deviceID, Util.delimiterA, username.getBytes(), Util.delimiterA, password.getBytes()));
        out.writeInt(send.length);
        out.write(send);//Authenticate by sending the device ID and the user's username and password
        out.flush();

        rec = new byte[in.readInt()];
        in.readFully(rec);

        if (!((Byte) enc.decryptByte(rec)[0]).equals(Util.ok)) { //Check if Server accepts this connection
            this.close();
            out.close();
            in.close();
            enc = null;
            firstConnect();
        }

        System.out.println("Handshake successful");
    }

    /**
     * Initialize the connection by exchanging keys, testing the encryption and exchanging login data, must be called every day once and at every program startup
     *
     * @throws IOException              a
     * @throws InterruptedException     a
     * @throws GeneralSecurityException a
     */
    private int firstConnect() throws IOException, InterruptedException, GeneralSecurityException {
        RSAEncryption rsaEncryption = new RSAEncryption(); //Initialize the RSA Encryption class in new thread for improved performance
        Thread thread = new Thread(() -> rsaEncryption.init(2048));
        thread.start();

        this.connect(new InetSocketAddress("localhost", 1234)); //TODO add port and ip
        System.out.println("Connected");
        out = new DataOutputStream(this.getOutputStream());
        in = new DataInputStream(this.getInputStream());

        thread.join(); //Wait for the thread to finish

        System.out.println("Sending RSA Key");
        byte[] send = serverEnc.encryptByte(Util.addCommand(Util.initConnection, rsaEncryption.getPublicKey()));
        out.writeInt(send.length); //Write length of byte array
        out.write(send); //Send the own RSA Public Key
        out.flush();

        byte[] rec = new byte[in.readInt()];
        in.readFully(rec);
        System.out.println(rec.length);
        rec = rsaEncryption.decryptByte(rec); //Receive the AES key, the AES iv, and the hash of the own RSA Public Key

        System.out.println("Got AES key and iv");

        //Copy Arrays with key, iv and hash of the RSA Public Key
        byte[] key = Arrays.copyOf(rec, 32);
        byte[] iv = Arrays.copyOfRange(rec, 32, 48);
        byte[] hash = Arrays.copyOfRange(rec, 48, rec.length);

        //TODO Hash doesn't work

        //System.out.println(hash.length);

        //System.out.println(Hex.encodeHexString(Util.generateChecksum(rsaEncryption.getPublicKey())));
        //System.out.println(Hex.encodeHexString(hash));

        // Check if the hash of the RSA Public key equals the received hash
        /*if (!Arrays.equals(hash, Util.generateChecksum(rsaEncryption.getPublicKey()))) { //Close everything if the answer was incorrect
            enc = null;
            out.close();
            in.close();
            this.close();
            System.gc();
            return;
        }*/

        System.out.println("Hash was correct");

        enc = new AESEncryption(key, iv); //Init aesEnc class

        //Test connection by sending a random number and checking if it was multiplied by 2 by the Server
        int testInt = new Random().nextInt(10000);

        send = enc.encryptByte(String.valueOf(testInt).getBytes(StandardCharsets.UTF_8));
        out.writeInt(send.length);
        out.write(send);
        out.flush();

        rec = new byte[in.readInt()];
        in.readFully(rec);
        rec = enc.decryptByte(rec);

        if (Integer.parseInt(new String(rec, StandardCharsets.UTF_8)) != (testInt * 2)) { //Close everything if the answer was incorrect
            out.close();
            in.close();
            this.close();
            enc = null;
            return CONNECTION_FAILED;
        } else System.out.println("Answer was correct");

        if (deviceID != null) //TODO add option for wrong username and password combo
            send = Bytes.concat(username.getBytes(), Util.delimiterA, BCrypt.hashpw(password, BCrypt.gensalt()).getBytes(), Util.delimiterA, deviceID);
        else
            send = Bytes.concat(username.getBytes(), Util.delimiterA, BCrypt.hashpw(password, BCrypt.gensalt()).getBytes());

        send = enc.encryptByte(send);
        out.writeInt(send.length);
        out.write(send); //Send username, password and device id, if known
        out.flush();

        rec = new byte[in.readInt()];
        in.readFully(rec);
        rec = enc.decryptByte(rec);//Receive session ID and device ID, if needed

        Result<Byte, byte[]> res = Util.getCode(rec);
        rec = res.getValue();

        if (res.getKey().equals(Util.wrongPassword)) {
            //TODO Wrong Password
            out.close();
            in.close();
            this.close();
            return WRONG_PASSWORD;
        }

        if (deviceID == null) { //Store session and device ID
            byte[][] dsid = Util.split(rec);
            sessionID = dsid[0];
            deviceID = dsid[1];
            System.out.println("Got SessionID " + Hex.encodeHexString(sessionID) + " and deviceID " + Hex.encodeHexString(deviceID));
        } else {
            sessionID = rec;
            System.out.println("Got Session ID " + new String(sessionID));
        }

        send = enc.encryptByte(new byte[]{Util.ok});
        out.writeInt(send.length);
        out.write(send);
        out.flush();
        out.flush();

        System.out.println("Handshake successful");
        return OK;
    }

    public byte[] getDeviceID() {
        return deviceID;
    }

    public byte[] getSessionID() {
        return sessionID;
    }

    public void disconnect() throws IOException, GeneralSecurityException, InterruptedException {//TODO close automatically
        run = false;
        t.join(4000);
        if (t.isAlive()) t.interrupt();
        out.writeInt(1);
        out.write(enc.encryptByte(new byte[]{Util.endConnection}));
        out.flush();
        out.close();
        in.close();
        this.close();
    }
}