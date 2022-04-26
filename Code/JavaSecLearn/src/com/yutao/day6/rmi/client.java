package com.yutao.day6.rmi;

import java.net.MalformedURLException;
import java.rmi.Naming;
import java.rmi.NotBoundException;
import java.rmi.RemoteException;
import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;

public class client {
    public static void main(String[] args) throws RemoteException, NotBoundException, MalformedURLException {
//        Registry reg = LocateRegistry.getRegistry("127.0.0.1", 1099);
//        rmtHello rmthello1 = (rmtHello) reg.lookup("hello");

        rmtHello rmthello = (rmtHello) Naming.lookup("rmi://127.0.0.1/hello");

        System.out.println(rmthello.hello());
    }
}
