package com.yutao.day2;

public class refl {
    public static void main(String[] args) throws ClassNotFoundException {

        Class cl1 = refl.class;
        System.out.println(cl1.getClass());
        System.out.println(cl1.getName());

        refl fl = new refl();
        Class cl2 = fl.getClass();
        System.out.println(cl2.getClass());
        System.out.println(cl2.getName());

        Class cl3 = Class.forName("com.yutao.day2.refl");
        System.out.println(cl3.getClass());
        System.out.println(cl3.getName());
        Class cl4 = ClassLoader.getSystemClassLoader().loadClass("com.yutao.day2.refl");
        System.out.println(cl4.getClass());
        System.out.println(cl4.getName());
    }
}
