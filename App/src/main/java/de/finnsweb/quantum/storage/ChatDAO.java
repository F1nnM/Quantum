package de.finnsweb.quantum.storage;

import java.util.List;

import androidx.room.Dao;
import androidx.room.Ignore;
import androidx.room.Insert;
import androidx.room.OnConflictStrategy;
import androidx.room.Query;

@Dao
public interface ChatDAO {

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    long insert(Chat chat);

    @Query("SELECT * FROM Chat")
    List<Chat> getAllChats();

    @Query("DELETE FROM Chat")
    void deleteAll();

}
