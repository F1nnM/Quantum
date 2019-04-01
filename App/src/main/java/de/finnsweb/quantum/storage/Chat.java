package de.finnsweb.quantum.storage;

import androidx.annotation.NonNull;
import androidx.room.Entity;
import androidx.room.PrimaryKey;

@Entity
public class Chat {

    @PrimaryKey(autoGenerate = true)
    public long id;
    public String lastMessage;
    public String title;

}
