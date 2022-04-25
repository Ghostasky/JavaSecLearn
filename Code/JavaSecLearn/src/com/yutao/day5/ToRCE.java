package com.yutao.day5;

import java.io.*;

class RCE implements java.io.Serializable {
    public String cmd;

    private void readObject(java.io.ObjectInputStream in) throws IOException, ClassNotFoundException, IOException {
        in.defaultReadObject();
        Runtime.getRuntime().exec(cmd);
    }
}

public class ToRCE {
    public static void main(String[] args) throws IOException, ClassNotFoundException {
        RCE testClass = new RCE();
        testClass.cmd = "calc";

        FileOutputStream fileoutputstream = new FileOutputStream("RCE.ser");
        ObjectOutputStream outputstream = new ObjectOutputStream(fileoutputstream);
        outputstream.writeObject(testClass);
        outputstream.close();


        FileInputStream fileinputstream = new FileInputStream("RCE.ser");
        ObjectInputStream inputstream = new ObjectInputStream(fileinputstream);
        RCE obj = (RCE) inputstream.readObject();
        inputstream.close();
    }
}