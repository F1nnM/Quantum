package util;

public interface Result<K, V> {
    K getKey();

    V getValue();
}
