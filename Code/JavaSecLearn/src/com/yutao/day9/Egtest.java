package com.yutao.day9;

import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Proxy;
import java.util.HashMap;
import java.util.Map;

public class Egtest {
    public static void main(String[] args) {
        InvocationHandler ih = new ExampleInvocationHandler(new HashMap());
        Map proxymap = (Map) Proxy.newProxyInstance(Map.class.getClassLoader(), new Class[]{Map.class}, ih);
        proxymap.put("123", "456");
        String result = (String) proxymap.get("123");
        System.out.println(result);

    }
}
