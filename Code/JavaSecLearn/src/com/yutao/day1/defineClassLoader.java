package com.yutao.day1;


public class defineClassLoader {

    public static void main(String[] args) throws Exception {
        // 指定类加载器加载调用
        try {
            myClassLoader classLoader = new myClassLoader();
            classLoader.loadClass("User").getMethod("user").invoke(null);
        } catch (Exception e) {
            System.out.println(e.toString());
        }

    }
}
