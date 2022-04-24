package com.yutao.day3;

import java.sql.Connection;
import java.sql.DriverManager;

public class jdbccoon {
    public static void main(String[] args) {

        try {
            String CLASS_NAME = "com.mysql.jdbc.Driver";
            String URL = "jdbc:mysql://localhost:3306/mysql";
            String USERNAME = "root";
            String PASSWORD = "root";

            Class.forName(CLASS_NAME);// 注册JDBC驱动类
            Connection connection = DriverManager.getConnection(URL, USERNAME, PASSWORD);
        } catch (Exception e) {
            System.out.println("aaaaaaaaa");
            e.printStackTrace();
        }

    }
}
