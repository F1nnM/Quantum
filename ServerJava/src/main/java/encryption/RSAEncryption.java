package encryption;

import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

/**
 * A class for RSA Encryption
 * Apache commons codec must be included in order to use this class
 */
public class RSAEncryption {

    private static RSAEncryption rsaEncryption = null;
    private Cipher cipher;
    private PublicKey publicKey;
    private PrivateKey privateKey;

    /**
     * Init the RSA Encryption with a given public or private Key
     * One key may be null, but both keys must not be null at the same time
     *
     * @param publicKeyBytes  the bytes of the public key as Hexadecimal, may be null
     * @param privateKeyBytes the bytes of the private key as Hexadecimal, may be null
     * @throws InvalidKeySpecException thrown if the key is invalid
     * @throws DecoderException        thrown if the Hexadecimal cannot be converted
     */
    public RSAEncryption(byte[] publicKeyBytes, byte[] privateKeyBytes) throws InvalidKeySpecException, DecoderException {
        KeyFactory kf = null;
        try {
            cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
            kf = KeyFactory.getInstance("RSA");
        } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
            // Should not be thrown
            e.printStackTrace();
        }
        assert kf != null;

        if (publicKeyBytes != null) {
            X509EncodedKeySpec spec = new X509EncodedKeySpec(Hex.decodeHex(new String(publicKeyBytes, StandardCharsets.UTF_8)));
            publicKey = kf.generatePublic(spec);
        }

        if (privateKeyBytes != null) {
            PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(Hex.decodeHex(new String(privateKeyBytes, StandardCharsets.UTF_8)));
            privateKey = kf.generatePrivate(spec);
        }
    }

    /**
     * Init the RSA Encryption class and generate a new key pair
     *
     * @param keySize the size of the key to generate
     */
    public RSAEncryption(int keySize) {
        init(keySize);
    }

    public RSAEncryption() {
        cipher = null;
        privateKey = null;
        publicKey = null;
    }

    /**
     * get an Instance of the RSA Encryption class
     *
     * @return an Instance of the RSA Encryption class
     */
    public static RSAEncryption getInstance() {
        if (rsaEncryption == null) {
            createRSAEncryption();
        }

        return rsaEncryption;
    }

    /**
     * Generate an Instance of the RSA Encryption class
     */
    public static void createRSAEncryption() {
        rsaEncryption = new RSAEncryption(4096);
    }

    public void init(int keySize) {
        KeyPairGenerator keyGen = null;
        try {
            keyGen = KeyPairGenerator.getInstance("RSA");
            cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
        } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
            // Should not be thrown
            e.printStackTrace();
        }
        assert keyGen != null;
        keyGen.initialize(keySize);
        KeyPair keyPair = keyGen.generateKeyPair();
        publicKey = keyPair.getPublic();
        privateKey = keyPair.getPrivate();
    }

    /**
     * get the public key encoded as a Hexadecimal
     *
     * @return the public key bytes
     */
    public byte[] getPublicKey() {
        return Hex.encodeHexString(publicKey.getEncoded()).getBytes(StandardCharsets.UTF_8);
    }

    /**
     * get the private key encoded as a Hexadecimal
     *
     * @return the private key bytes
     */
    public byte[] getPrivateKey() {
        return Hex.encodeHexString(privateKey.getEncoded()).getBytes(StandardCharsets.UTF_8);
    }

    /**
     * get the public key encoded as a Hexadecimal string
     *
     * @return the public key as a string
     */
    public String getPublicKeyHex() {
        return Hex.encodeHexString(publicKey.getEncoded());
    }

    /**
     * get the private key encoded as a Hexadecimal string
     *
     * @return the private key as as string
     */
    public String getPrivateKeyHex() {
        return Hex.encodeHexString(privateKey.getEncoded());
    }

    /**
     * encrypt a String
     *
     * @param input the String (will be formatted as UTF-8) to encrypt
     * @return the encrypted String as bytes
     * @throws GeneralSecurityException if the key or the input data (length of data MUST be less than keysize - 11 bytes) is invalid
     */
    public byte[] encrypt(String input) throws GeneralSecurityException {
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        return cipher.doFinal(input.getBytes(StandardCharsets.UTF_8));
    }

    /**
     * decrypt bytes and return the result as a UTF-8 formatted String
     *
     * @param input the encrypted bytes
     * @return the decrypted String
     * @throws GeneralSecurityException if the key or the input data is invalid
     */
    public String decrypt(byte[] input) throws GeneralSecurityException {
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        return new String(cipher.doFinal(input), StandardCharsets.UTF_8);
    }

    /**
     * encrypt bytes
     *
     * @param input a byte array to encrypt
     * @return the encrypted bytes as byte array
     * @throws GeneralSecurityException if the key or the input data is invalid
     */
    public byte[] encryptByte(byte[] input) throws GeneralSecurityException {
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        return cipher.doFinal(input);
    }

    /**
     * decrypt bytes
     *
     * @param input an array of bytes to decrypt
     * @return an array of decrypted bytes
     * @throws GeneralSecurityException if the key or the input data is invalid
     */
    public byte[] decryptByte(byte[] input) throws GeneralSecurityException {
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        return cipher.doFinal(input);
    }
}