package com.yutao.day3;


import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.URL;
import java.net.URLConnection;


public class urltest {
    public static void main(String[] args) {
        try {
            URL url = new URL("https://www.baidu.com");
//            请求参数
            URLConnection conn = url.openConnection();
            conn.setRequestProperty("user-agent", "firefox");
            conn.setConnectTimeout(1000);
            conn.setReadTimeout(1000);
//            建立连接
            conn.connect();
//            获取响应头字段信息列表
            conn.getHeaderFields();
//            获取响应
            conn.getInputStream();

            StringBuilder response = new StringBuilder();
            BufferedReader in = new BufferedReader(
                    new InputStreamReader(conn.getInputStream()));
            String line;

            while ((line = in.readLine()) != null) {
                response.append("/n").append(line);
            }

            System.out.print(response.toString());


        } catch (Exception e) {
            e.printStackTrace();
        }


    }
}
