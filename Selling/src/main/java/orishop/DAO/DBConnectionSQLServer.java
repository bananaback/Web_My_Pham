package orishop.DAO;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.sql.Connection;
import java.sql.DriverManager;
import java.util.Properties;

public class DBConnectionSQLServer {

    public static Connection getConnectionW() throws Exception {
        Properties prop = new Properties();
        try (InputStream input = DBConnectionSQLServer.class.getClassLoader().getResourceAsStream("config.properties")) {
            if (input == null) {
                throw new FileNotFoundException("config.properties file not found in classpath");
            }
            prop.load(input);
        } catch (IOException ex) {
            ex.printStackTrace();
            throw new Exception("Failed to load config.properties");
        }
        

        String serverName = prop.getProperty("serverName");
        String dbName = prop.getProperty("dbName");
        String portNumber = prop.getProperty("portNumber");
        String instance = prop.getProperty("instance");
        String userID = prop.getProperty("userID");
        String password = prop.getProperty("password");

        String url = "jdbc:sqlserver://" + serverName + ":" + portNumber + "\\" + instance + ";databaseName=" + dbName + ";encrypt=true" + ";trustServerCertificate=true";
        if (instance == null || instance.trim().isEmpty())
            url = "jdbc:sqlserver://" + serverName + ":" + portNumber + ";databaseName=" + dbName + ";encrypt=true" + ";trustServerCertificate=true";
        Class.forName("com.microsoft.sqlserver.jdbc.SQLServerDriver");
        return DriverManager.getConnection(url, userID, password);
    }

    public static void main(String[] args) {
        try {
            System.out.println(DBConnectionSQLServer.getConnectionW());
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}

