package de.finnsweb.quantum.storage;

import java.util.List;

import androidx.room.Dao;
import androidx.room.Insert;
import androidx.room.OnConflictStrategy;
import androidx.room.Query;

@Dao
public interface MessageDAO {
    @Insert(onConflict = OnConflictStrategy.REPLACE)
    long insert(Message msg);

    @Query("SELECT * FROM Message WHERE chatid = :chatId")
    List<Message> getAllMessagesFromChat(long chatId);

    @Query("DELETE FROM Message")
    void deleteAll();
}
