package encryption;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;

public class AESEncryption {

    public static final int KEYLENGTH_128BIT = 16;
    private SecretKeySpec secretKeySpec;
    private Cipher cipher;
    private byte[] key;
    private byte[] iv;
    private IvParameterSpec ivSpec;

    /**
     * Init the AES Encryption class and generate a new key and iv
     */
    public AESEncryption() {
        byte[] bytes = new byte[32];
        SecureRandom random = new SecureRandom();
        random.nextBytes(bytes);
        key = bytes;
        bytes = new byte[32];
        random.nextBytes(bytes);
        iv = bytes;
        ivSpec = new IvParameterSpec(Arrays.copyOf(iv, 16));
        byte[] sha = generateSHA(key);
        sha = Arrays.copyOf(sha, 32);
        secretKeySpec = new SecretKeySpec(sha, "AES");
        try {
            cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
            // Should not be thrown
            e.printStackTrace();
        }
    }

    /**
     * Init the AES Encryption class with given key and iv
     *
     * @param key the key
     * @param iv  the iv
     */
    public AESEncryption(byte[] key, byte[] iv) {
        this.iv = iv;
        this.key = key;
        ivSpec = new IvParameterSpec(Arrays.copyOf(iv, 16));
        byte[] sha = generateSHA(key);
        sha = Arrays.copyOf(sha, 32);
        secretKeySpec = new SecretKeySpec(sha, "AES");
        try {
            cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
            // Should not be thrown
            e.printStackTrace();
        }
    }

    /**
     * generate a SHA key from another key
     *
     * @param key the key to generate the SHA from
     * @return the SHA key as byte array
     */
    public static byte[] generateSHA(byte[] key) {
        MessageDigest sha = null;
        try {
            sha = MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            // Should not be thrown
            e.printStackTrace();
        }
        assert sha != null;
        key = sha.digest(key);

        return key;
    }

    /**
     * get the key
     *
     * @return the key as byte array
     */
    public byte[] getKey() {
        return key;
    }

    /**
     * get the iv
     *
     * @return the iv as byte array
     */
    public byte[] getIv() {
        return iv;
    }

    /**
     * encrypt a String
     *
     * @param input the String (will be formatted as UTF-8) to encrypt
     * @return the resulting array of bytes
     * @throws GeneralSecurityException thrown if the key or the iv is invalid (e.g. invalid key or iv length)
     */
    public byte[] encrypt(String input) throws GeneralSecurityException {
        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, ivSpec);
        return cipher.doFinal(input.getBytes(StandardCharsets.UTF_8));
    }

    /**
     * decrypt bytes and return them as a UTF-8 formatted String
     *
     * @param input the input array of bytes
     * @return the decrypted String
     * @throws GeneralSecurityException thrown if the key or the iv is invalid or the input data is corrupted
     */
    public String decrypt(byte[] input) throws GeneralSecurityException {
        cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, ivSpec);
        return new String(cipher.doFinal(input), StandardCharsets.UTF_8);
    }

    /**
     * encrypt a byte array
     *
     * @param input the byte array to encrypt
     * @return an array of encrypted bytes
     * @throws GeneralSecurityException thrown if the key or the iv is invalid
     */
    public byte[] encryptByte(byte[] input) throws GeneralSecurityException {
        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, ivSpec);
        return cipher.doFinal(input);
    }

    /**
     * decrypt an array of bytes
     *
     * @param input the byte array to decrypt
     * @return an array of decrypted bytes
     * @throws GeneralSecurityException thrown if the key or the iv is invalid or the input data is corrupted
     */
    public byte[] decryptByte(byte[] input) throws GeneralSecurityException {
        cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, ivSpec);
        return cipher.doFinal(input);
    }
}