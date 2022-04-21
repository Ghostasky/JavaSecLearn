package com.yutao.day1;

public class execcalc {
    public execcalc() {
        System.out.println("Test success!!!");
        try {
            Runtime.getRuntime().exec("cmd /c calc.exe");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
//E:\github\JavaSecLearn\Code\JavaSecLearn\src\com\yutao\day1