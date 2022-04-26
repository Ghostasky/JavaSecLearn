package com.yutao.day6.rmi;

import java.rmi.RemoteException;
import java.rmi.server.UnicastRemoteObject;

public class rmtHelloImpl extends UnicastRemoteObject implements rmtHello {
    public rmtHelloImpl() throws RemoteException {
    }

    @Override
    public String hello() throws RemoteException {
        System.out.println("test success");
        return "im ok";
    }
}
