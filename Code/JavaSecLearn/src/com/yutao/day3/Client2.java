package com.yutao.day3;

import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Proxy;

public class Client2 {
    public static void main(String[] args) {
//        创建被代理的对象
        UserServiceImpl usi = new UserServiceImpl();

        ClassLoader cl = usi.getClass().getClassLoader();

//        获取所有接口的class，这里UserServiceImpl只实现了一个接口
        Class[] inf = usi.getClass().getInterfaces();
        for (Class c : inf)
            System.out.println(c);


        InvocationHandler ih = new ProxyTest2(usi);

        UserService proxy = (UserService) Proxy.newProxyInstance(cl, inf, ih);
        proxy.select();
        proxy.select();
    }
}
