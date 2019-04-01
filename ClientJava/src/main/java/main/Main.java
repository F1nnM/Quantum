package main;

import networking.SecureSocket;
import org.apache.commons.codec.binary.Hex;
import util.Util;

import java.io.IOException;
import java.security.GeneralSecurityException;

public class Main {

    public static void main(String[] args) throws GeneralSecurityException, InterruptedException, IOException {
        System.out.println(Hex.encodeHexString(Util.generateChecksum("abcdeg".getBytes())));
        SecureSocket s = new SecureSocket(null, null, "abc", "avc", null);
        s.connect();
    }
}
