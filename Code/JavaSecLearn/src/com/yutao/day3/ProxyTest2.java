package com.yutao.day3;

import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;

public class ProxyTest2 implements InvocationHandler {
    private Object target;

    public ProxyTest2(Object target) {
        this.target = target;
    }

    @Override
    public Object invoke(Object proxy, Method method, Object[] args) throws Throwable {
        before();
        Object re = method.invoke(target, args);
        after();

        return re;
    }

    public void select() {
        System.out.println("select");
    }

    public void before() {
        System.out.println("before");
    }

    public void after() {
        System.out.println("after");
    }
}
