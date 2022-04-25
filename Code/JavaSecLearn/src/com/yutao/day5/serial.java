package com.yutao.day5;

import java.io.*;


public class serial {
    public static void main(String[] args) throws Exception {
        Person person = new Person("qqq", 123);
        FileOutputStream fos = new FileOutputStream("1.txt");
        ObjectOutputStream oops = new ObjectOutputStream(fos);
        oops.writeObject(person);
        oops.close();
        fos.close();
        FileInputStream fis = new FileInputStream("1.txt");

        ObjectInputStream ois = new ObjectInputStream(fis);
        Person s = (Person) ois.readObject();
        System.out.println("done");
        ois.close();
        fis.close();

    }
}
