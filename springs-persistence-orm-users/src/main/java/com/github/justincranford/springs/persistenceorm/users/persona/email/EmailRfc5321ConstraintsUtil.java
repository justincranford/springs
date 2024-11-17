package com.github.justincranford.springs.persistenceorm.users.persona.email;

import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;

@SuppressWarnings({"unused"})
public class EmailRfc5321ConstraintsUtil {
    public static EmailRfc5321ConstraintsUtil proxy() {
        return (EmailRfc5321ConstraintsUtil) Proxy.newProxyInstance(
            EmailRfc5321ConstraintsUtil.class.getClassLoader(),
            new Class[] { EmailRfc5321Constraints.class },
            new InvocationHandler() {
                @Override
                public Object invoke(Object proxy, Method method, Object[] args) throws Throwable {
                    switch (method.getName()) {
                        default:
                            throw new RuntimeException("Method " + method.getName() + " + proxy is missing");
                    }
                }
            }
        );
    }
}
