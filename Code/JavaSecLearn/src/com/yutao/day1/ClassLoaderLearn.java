package com.yutao.day1;

import java.io.File;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URL;
import java.net.URLClassLoader;

public class ClassLoaderLearn {
    public static void main(String[] args) throws ClassNotFoundException, NullPointerException, InstantiationException, IllegalAccessException, MalformedURLException {
        File file = new File("E:\\github\\JavaSecLearn\\Code\\JavaSecLearn\\src\\com\\yutao\\day1\\");
        URI uri = file.toURI();
        URL url = uri.toURL();

        URLClassLoader classLoader = new URLClassLoader(new URL[]{url});
        Class clazz = classLoader.loadClass("com.yutao.day1.execcalc");
        clazz.newInstance();

    }
}
