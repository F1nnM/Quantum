package de.finnsweb.quantum.storage;

import androidx.room.TypeConverter;

public class TypeConverters {

    @TypeConverter
    public static boolean fromDirection(Message.Direction d){
        return (d == Message.Direction.SENT);
    }

    @TypeConverter
    public static Message.Direction toDirection(boolean b){
        return (b?Message.Direction.SENT:Message.Direction.RECEIVED);
    }
}
