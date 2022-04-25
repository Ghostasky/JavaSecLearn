package com.yutao.day5;

import sun.misc.Unsafe;

import java.lang.reflect.Constructor;
import java.lang.reflect.Field;

class unsafetest {
    private unsafetest() {
        System.out.println("success");
    }
}

public class unsafe {
    public static void main(String[] args) throws Exception {
        Class<?> cls = Class.forName("sun.misc.Unsafe");
        Field theUnsafe = cls.getDeclaredField("theUnsafe");
        theUnsafe.setAccessible(true);
        Unsafe uf = (Unsafe) theUnsafe.get(null);
        unsafetest ust = (unsafetest) uf.allocateInstance(unsafetest.class);
        System.out.println(ust);

    }
}
