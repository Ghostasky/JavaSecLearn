package com.yutao.day2;

import java.lang.reflect.Constructor;
import java.lang.reflect.Method;

public class refl4 {
    public void testFun() {
        System.out.println("test seccess!");
    }

    public static void main(String[] args) {
        try {
            Class cls = Class.forName("com.yutao.day2.refl4");
            Object ob = cls.newInstance();//创建实例对象
            Method md = cls.getMethod("testFun");//获取方法
            md.invoke(ob);//调用类实例对象的方法

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
