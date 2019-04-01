package networking;

import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.concurrent.Executors;
import java.util.concurrent.ThreadPoolExecutor;

public class SSocket {

    public static void start() throws IOException {
        ServerSocket serverSocket = new ServerSocket(1234);
        System.out.println("Server started");
        ThreadPoolExecutor executor = (ThreadPoolExecutor) Executors.newCachedThreadPool();
        while (true) {
            Socket s = serverSocket.accept();
            System.out.println("Got connection from: " + s.getInetAddress().getHostAddress());
            executor.execute(() -> new Client(s));
        }
    }
}
