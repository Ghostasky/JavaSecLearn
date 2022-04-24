package com.yutao.day3;

public class UserServiceProxy implements UserService {
    private UserService target;//被代理的对象

    public UserServiceProxy(UserService target) {
        this.target = target;

    }

    @Override
    public void select() {
        before();
        target.select();
        after();
    }

    @Override
    public void update() {
        before();
        target.update();
        after();
    }

    private void before() {     // 在执行方法之前执行
        System.out.println("berfore");
    }

    private void after() {      // 在执行方法之后执行
        System.out.println("after");
    }

}
