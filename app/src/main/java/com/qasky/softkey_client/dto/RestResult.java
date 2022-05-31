package com.qasky.softkey_client.dto;

/**
 * Copyright © 2009 Qasky. All rights reserved.
 * <p>
 *  响应对象
 *
 * @author Long Cheng
 * @version 0.0.0 2020/06/18
 * <p>
 * History:
 * (author, date, desc)
 * (Long Cheng, 20200618, 创建文件)
 */
public class RestResult<T> {

    private int code;
    private String message;
    private T data;

    private RestResult(){}

    protected RestResult(int code, String message, T data) {
        this.code = code;
        this.message = message;
        this.data = data;
    }

    public int getCode() {
        return code;
    }

    public RestResult setCode(int code) {
        this.code = code;
        return this;
    }

    public String getMessage() {
        return message;
    }

    public RestResult setMessage(String message) {
        this.message = message;
        return this;
    }

    public T getData() {
        return data;
    }

    public RestResult<T> setData(T data) {
        this.data = data;
        return this;
    }
}