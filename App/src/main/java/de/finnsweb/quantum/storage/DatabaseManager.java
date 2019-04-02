package de.finnsweb.quantum.storage;

import androidx.room.Room;
import de.finnsweb.quantum.App;

public class DatabaseManager {

    private static volatile QuantumData quantumData;
    private static volatile ChatDAO chatDAO;
    private static volatile MessageDAO messageDAO;

    public static ChatDAO chatDAO() {
        if (chatDAO == null) {
            if (quantumData == null)
                synchronized (DatabaseManager.class){
                    if (quantumData == null)
                        quantumData = Room.databaseBuilder(App.getContext(), QuantumData.class, "Quantum").fallbackToDestructiveMigration().build();
                }
            chatDAO = quantumData.chatDAO();
        }
        return chatDAO;
    }

    public static MessageDAO messageDAO() {
        if (messageDAO == null) {
            if (quantumData == null)
                synchronized (DatabaseManager.class){
                    if (quantumData == null)
                        quantumData = Room.databaseBuilder(App.getContext(), QuantumData.class, "Quantum").fallbackToDestructiveMigration().build();
                }
            messageDAO = quantumData.messageDAO();
        }
        return messageDAO;
    }


}
