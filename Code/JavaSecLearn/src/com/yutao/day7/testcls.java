package com.yutao.day7;

import java.io.*;

public class testcls {

    public static void main(String[] args) throws IOException, ClassNotFoundException {
        Person person = new Person("name123", 123);
        FileOutputStream fos = new FileOutputStream("person.ser");
        ObjectOutputStream ois = new ObjectOutputStream(fos);
        ois.writeObject(person);

        FileInputStream fis = new FileInputStream("person.ser");
        ObjectInputStream oos = new ObjectInputStream(fis);
        Person test = (Person) oos.readObject();
    }
}
