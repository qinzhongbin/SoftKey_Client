/*
 * Copyright (c) 2020. Qasky. All rights reserved.
 */

package com.qasky.softkey_client.util;

import org.bouncycastle.asn1.x509.BasicConstraints;

/**
 * 证书基本约束创建器，设置证书的属性
 * @author Zhu Jinping
 */
public class BasicConstraintsBuilder {
    /** CA 标志 */
    private boolean isCaFlag = false;
    /** 证书链最大长度 */
    private int pathLength = 0;

    /**
     * 设备证书链最大长度
     *
     * @param pathLength
     */
    public void setPathLength(Integer pathLength) {
        this.pathLength = pathLength;
        if (pathLength > 0) {
            //有长度限制，一定是CA
            this.isCaFlag = true;
        }
    }

    /**
     * 设置是否为CA标志
     *
     * @param caFlag
     */
    public void setCaFlag(boolean caFlag) {
        isCaFlag = caFlag;
    }

    /**
     * 根据已设置参数创建约束对象
     *
     * @return
     */
    public BasicConstraints build() {
        if (this.pathLength > 0) {
            return new BasicConstraints(this.pathLength);
        } else {
            return new BasicConstraints(this.isCaFlag);
        }
    }
}
