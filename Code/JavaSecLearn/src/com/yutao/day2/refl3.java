package com.yutao.day2;

import java.lang.reflect.Method;
import java.util.zip.CheckedOutputStream;

public class refl3 {
    public void funPublic() {
        System.out.println("Public Fun");
    }

    public void funPublic1(String str) {
        System.out.println("Public Fun" + str);
    }

    protected void funProtect() {
        System.out.println("Protect Fun");
    }

    private void funPrivate() {
        System.out.println("Private Fun");
    }

    void funNan() {
        System.out.println("Nan Fun");
    }

    public static void main(String[] args) {
        try {
            Class testClass = Class.forName("com.yutao.day2.refl3");

            Method[] mtharr = testClass.getMethods();
            for (Method m : mtharr) {
                System.out.println(m);
            }
            System.out.println("____________________-");
            Method[] mtharr1 = testClass.getDeclaredMethods();
            for (Method m : mtharr1) {
                System.out.println(m);
            }
            System.out.println("____________________");
            Method m1 = testClass.getMethod("funPublic1", String.class);
            System.out.println(m1);
            System.out.println("____________________");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
