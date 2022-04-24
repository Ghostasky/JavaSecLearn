package com.yutao.day3;

import java.lang.reflect.Proxy;
import java.lang.reflect.InvocationHandler;

public class ProxyTest {
    public static void main(String[] args) {
        UserService us = new UserServiceImpl();
        UserService proxy = new UserServiceProxy(us);
        proxy.select();
        proxy.update();

    }
}
