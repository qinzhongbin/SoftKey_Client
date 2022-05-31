package com.qasky.softkey_client.util;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;

/**
 * bytes 相关的工具类
 *
 * @author Zhu Jinping
 */
public class BytesUtils {

    public static final int HEX_LENGTH = 2;
    public static final int HEX_RADIX = 16;

    /**
     * 工具类私有构造函数
     */
    private BytesUtils() {
    }

    /**
     * 转换byte数组到十六进制字符串
     *
     * @param data 数组
     * @return 十六进制字符串
     */
    public static String bytes2String(byte[] data) {
        StringBuilder sb = new StringBuilder("(");
        sb.append(data.length);
        sb.append(") ");
        String str;
        char zero = "0".charAt(0);
        for (int i = 0; i < data.length; i++) {
            int v = data[i] & 0xFF;
            str = Integer.toHexString(v);
            if (str.length() < 2) {
                sb.append(zero);
            }
            sb.append(str);
        }
        return sb.toString();
    }

    /**
     * 把数组转换为长整型
     *
     * @param raw 数组
     * @return 长整型
     */
    public static long getLong(byte[] raw) {
        ByteBuffer buffer = ByteBuffer.allocate(8);
        buffer.put(raw, 0, raw.length);
        buffer.flip();
        return buffer.getLong();
    }

    /**
     * 把长整型转换为数组
     *
     * @param data 长整型
     * @return 数组
     */
    public static byte[] getBytes(long data) {
        ByteBuffer buffer = ByteBuffer.allocate(8);
        buffer.putLong(data);
        return buffer.array();
    }

    /**
     * 合并两个数组
     *
     * @param a
     * @param b
     * @return
     */
    public static byte[] combine(byte[] a, byte[] b) {
        if (null == a) {
            return b;
        }

        if (null == b) {
            return a;
        }

        byte[] bytes = new byte[a.length + b.length];
        System.arraycopy(a, 0, bytes, 0, a.length);
        System.arraycopy(b, 0, bytes, a.length, a.length);
        return bytes;
    }

    /**
     * 十六进制字符转数组
     *
     * @param hexString
     * @return
     */
    public static byte[] hex2bytes(String hexString) {
        if (hexString.length() % HEX_LENGTH != 0) {
            hexString = "0" + hexString;
        }
        byte[] ret = new byte[(hexString.length() + 1) / HEX_LENGTH];
        for (int i = 0; i < ret.length; i++) {
            ret[i] = (byte) (Integer.parseInt(hexString.substring(i * HEX_LENGTH, i * HEX_LENGTH + HEX_LENGTH), HEX_RADIX) & 0xFF);
        }

        return ret;
    }

    /**
     * 从字符串中获取UTF8字节流
     *
     * @param utf8Str
     * @return
     */
    public static byte[] utf8String2bytes(String utf8Str) {
        return utf8Str.getBytes(StandardCharsets.UTF_8);
    }
}
