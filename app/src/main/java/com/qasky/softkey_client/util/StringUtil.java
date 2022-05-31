package com.qasky.softkey_client.util;

/**
 * 字符串处理工具类
 *
 * @author Zhu Jinping
 */
public class StringUtil {
    private StringUtil() {
    }

    /**
     * 替换字符
     */
    private static String REPLACEABLE = "[\r\n]";
    private static String REPLACEMENT = "";

    /**
     * 格式化日志字串
     *
     * @param object 要格式化的对象
     * @return 格式化之后的字串
     */
    public static String formatString(Object object) {
        return (null == object ? null : object.toString().replaceAll(REPLACEABLE, REPLACEMENT));
    }

    /**
     * 判断字符串是否为空
     *
     * @param str
     * @return
     */
    public static boolean isEmpty(Object str) {
        return str == null || "".equals(str);
    }
}
