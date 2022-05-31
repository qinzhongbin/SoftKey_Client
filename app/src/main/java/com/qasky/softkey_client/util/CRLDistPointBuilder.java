/*
 * Copyright (c) 2020. Qasky. All rights reserved.
 */

package com.qasky.softkey_client.util;

import org.bouncycastle.asn1.x509.CRLDistPoint;
import org.bouncycastle.asn1.x509.DistributionPoint;
import org.bouncycastle.asn1.x509.DistributionPointName;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;

import java.util.ArrayList;
import java.util.List;

/**
 * CRL分发点创建器
 *
 * @author Zhu Jinping
 */
public class CRLDistPointBuilder {
    private List distPoints = new ArrayList<DistributionPoint>(1);

    /**
     * 增加新的URL 用于CRL下载
     *
     * @param url 用于CRL下载的URL
     */
    public void addDistPoint(String url) {
        if (StringUtil.isEmpty(url))
            return;
        GeneralName generalName = new GeneralName(GeneralName.uniformResourceIdentifier, url);
        GeneralNames generalNames = new GeneralNames(generalName);
        DistributionPointName distributionPointName = new DistributionPointName(generalNames);
        DistributionPoint distributionPoint = new DistributionPoint(distributionPointName, null, null);

        distPoints.add(distributionPoint);
    }

    /**
     * 创建CRL分发点对象
     *
     * @return
     */
    public CRLDistPoint build() {
        DistributionPoint[] distributionPoints = new DistributionPoint[distPoints.size()];
        distPoints.toArray(distributionPoints);
        return new CRLDistPoint(distributionPoints);
    }

}
