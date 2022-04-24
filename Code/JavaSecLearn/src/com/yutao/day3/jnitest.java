package com.yutao.day3;

public class jnitest {
    public static native String exec(String cmd);

    public static void main(String[] args) {
        System.load("E:\\github\\JavaSecLearn\\Code\\JavaSecLearn\\src\\com\\yutao\\day3\\cmd.so");
        jnitest.exec("asdf");
    }
}
