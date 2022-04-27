package com.yutao.day6.rmi;

import java.io.ObjectOutputStream;
import java.net.MalformedURLException;
import java.rmi.AlreadyBoundException;
import java.rmi.Naming;
import java.rmi.RemoteException;
import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;


public class server {


    public static void main(String[] args) throws RemoteException, MalformedURLException, AlreadyBoundException {
        ObjectOutputStream a;
//        rmtHello rmthello = new rmtHelloImpl();
//        Registry registry = LocateRegistry.createRegistry(1099);
//        registry.rebind("hello", rmthello);
        rmtHello rmthello = new rmtHelloImpl();
        LocateRegistry.createRegistry(1099);
        Naming.bind("rmi://127.0.0.1/hello", rmthello);

    }
}
