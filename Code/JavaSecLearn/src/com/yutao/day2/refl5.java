package com.yutao.day2;


import java.lang.Runtime;

import java.lang.reflect.Constructor;
import java.lang.Process;
import java.lang.ProcessBuilder;

public class refl5 {
    public static void main(String[] args) {
        try {
//            Class clazz = Class.forName("java.lang.Runtime");
//            clazz.getMethod("exec", String.class).invoke(clazz.getMethod("getRuntime").invoke(clazz), "calc.exe");


            Class cls = Class.forName("java.lang.Runtime");
            cls.getMethod("exec", String.class).invoke(cls.getMethod("getRuntime").invoke(cls), "calc");
          
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
