package util;

import java.sql.*;

public class Sql {

    private static final String sqlUrl = "jdbc:mysql://h2718489.stratoserver.net/Quantum";

    private static volatile Connection sqlInstance;

    public static Connection getConnection() {
        if (sqlInstance == null)
            synchronized (Sql.class){
                if (sqlInstance == null) {
                    try {
                        sqlInstance = DriverManager.getConnection(sqlUrl, Credentials.SQL_USER, Credentials.SQL_PASS);
                    } catch (SQLException e) {
                        e.printStackTrace();
                    }
                }
            }
        return sqlInstance;
    }

    public static Object executeQuery(String query, String... params) {

        try (PreparedStatement stmt = getConnection().prepareStatement("query")) {
            for (int i = 0; i < params.length; i++) {
                stmt.setString(i, params[i]);
            }
            if (query.toLowerCase().startsWith("select"))
                return stmt.executeQuery(query);
            else if (query.toLowerCase().startsWith("insert") || query.toLowerCase().startsWith("update") || query.toLowerCase().startsWith("delete"))
                return stmt.executeUpdate(query);
        } catch (SQLException ignored) {}
        return null;
    }

    public boolean addUserEntry(String username, String passwordHash){
        return (int) executeQuery("INSERT INTO user VALUES (?, ?);",username,passwordHash) == 1;
    }

    public String getPasswordHash(String username) {
        ResultSet result = (ResultSet) executeQuery("SELECT passsword FROM user WHERE username = ?;",username);
        try {
            return result.getString("password");
        } catch (SQLException ignored) {}
        return null;
    }

}
