package com.yutao.day1;

public class User {

    private String name;

    public String getName() {
        return name;
    }

    public static void main(String[] args) {
        System.out.println("User类已成功加载运行！");
        ClassLoader classLoader = User.class.getClassLoader();
        System.out.println("加载我的classLoader：" + classLoader);
        System.out.println("classLoader.parent：" + classLoader.getParent());
    }
}

