package com.yutao.day6.rmi;

import java.rmi.Remote;
import java.rmi.RemoteException;

public interface rmtHello extends Remote {
    String hello() throws RemoteException;
}
