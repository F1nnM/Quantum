package de.finnsweb.quantum.storage;

import androidx.room.Database;
import androidx.room.RoomDatabase;
import androidx.room.TypeConverters;

@TypeConverters({de.finnsweb.quantum.storage.TypeConverters.class})
@Database(entities = {Message.class, Chat.class}, version = 2)
public abstract class QuantumData extends RoomDatabase {
    public abstract ChatDAO chatDAO();
    public abstract MessageDAO messageDAO();
}
