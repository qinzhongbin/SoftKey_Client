package com.qasky.softkey_client.util;

import java.util.Date;

/**
 * 时间工具类
 *
 * @author Zhu Jinping
 */

public class DatetimeUtil {
    private DatetimeUtil(){}
    private static final long PRECISION = 1000L;
    private static final long SECONDS_IN_HOUR = 60 * 60L;

    /**
     * Calculate a date in hours (suitable for the PKIX profile - RFC 5280)
     *
     * @param hoursInFuture hours ahead of now, may be negative.
     * @return a Date set to now + (hoursInFuture * 60 * 60) seconds
     */
    public static Date calculateDate(int hoursInFuture) {
        long secs = System.currentTimeMillis() / PRECISION;
        final long time = (secs + (hoursInFuture * SECONDS_IN_HOUR)) * PRECISION;
        return new Date(time);
    }
}
