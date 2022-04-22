package com.yutao.day2;


import java.lang.reflect.Field;

public class refl2 {
    public String namePublic = "name123";
    protected String nameProtect = "name456";
    private String namePrivate = "name789";
    String nameNan = "name000";

    public static void main(String[] args) {
        try {
            Class testClass = Class.forName("com.yutao.day2.refl2");

            Field[] fArr1 = testClass.getDeclaredFields();
            Field[] fArr2 = testClass.getFields();
            System.out.println("getDeclaredFields():");
            System.out.println(fArr1);
            for (Field f : fArr1) {
                System.out.printf("%s ", f);
                System.out.println(f.getName());
            }
            System.out.println("getFields():");
            System.out.println(fArr2);
            for (Field f : fArr2) {
                System.out.printf("%s ", f);
                System.out.println(f.getName());
            }
            System.out.println("_________________________");
            Field f1 = testClass.getField("namePublic");
            System.out.printf("%s %s\n", f1, f1.getName());

            Field f2 = testClass.getDeclaredField("namePrivate");
            System.out.printf("%s %s\n", f2, f2.getName());
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

}
