package de.finnsweb.quantum.storage;

import androidx.annotation.NonNull;
import androidx.room.Entity;
import androidx.room.PrimaryKey;

@Entity
public class Message {


    @PrimaryKey(autoGenerate = true)
    public long id;

    public String content;
    public long timestamp;
    public long chatid;
    public Direction direction;

    public enum Direction{
        SENT, RECEIVED
    }

    public String toString(){
        return ""+(direction==Direction.SENT?"<<<":">>>")+" "+timestamp+": "+content;
    }

}
