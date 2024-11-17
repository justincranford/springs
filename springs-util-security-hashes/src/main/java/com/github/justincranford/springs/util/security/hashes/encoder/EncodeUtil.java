package com.github.justincranford.springs.util.security.hashes.encoder;

import com.github.justincranford.springs.util.basic.ThreadUtil;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Future;

public class EncodeUtil {
    public static List<String> encode(final PasswordEncoder encoder, final List<String> values) {
        final List<Future<String>> futureEncodedPasswords = new ArrayList<>(values.size());
        for (final String password : values) {
            futureEncodedPasswords.add(ThreadUtil.supplyAsync(() -> encoder.encode(password)));
        }
        final List<String> encodedPasswords = new ArrayList<>(values.size());
        try {
            for (final Future<String> futureEncodedPassword : futureEncodedPasswords) {
                encodedPasswords.add(futureEncodedPassword.get());
            }
        } catch (InterruptedException | ExecutionException e) {
            throw new RuntimeException("Failed to encode passwords", e);
        }
        return encodedPasswords;
    }

}
