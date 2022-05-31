package com.qasky.softkey_client;

import androidx.multidex.MultiDexApplication;

import com.blankj.utilcode.util.AppUtils;
import com.blankj.utilcode.util.DeviceUtils;
import com.blankj.utilcode.util.LogUtils;
import com.blankj.utilcode.util.SDCardUtils;
import com.blankj.utilcode.util.ToastUtils;
import com.blankj.utilcode.util.Utils;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.Security;
import java.util.Arrays;

public class App extends MultiDexApplication {

    static {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            System.out.println("security provider BC not found");
        } else {
            System.out.println("old security provider BC's version is " + Security.getProvider(BouncyCastleProvider.PROVIDER_NAME).getVersion());
            Security.removeProvider("BC");
        }
        Security.addProvider(new BouncyCastleProvider());
        System.out.println("current security provider BC's version is " + Security.getProvider(BouncyCastleProvider.PROVIDER_NAME).getVersion());
    }

    @Override
    public void onCreate() {
        super.onCreate();
        Utils.init(this);
        LogUtils.getConfig()
                .setGlobalTag("QaSky")
                .setLogHeadSwitch(false)
                .setBorderSwitch(false);

        LogUtils.d("设备信息：" +
                "\n制造商：" + DeviceUtils.getManufacturer() +
                "\n型号：" + DeviceUtils.getModel() +
                "\nAndroid版本名称：" + DeviceUtils.getSDKVersionName() +
                "\nAndroid版本号: " + DeviceUtils.getSDKVersionCode() +
                "\nApp版本名称：" + AppUtils.getAppVersionName() +
                "\nApp版本号：" + AppUtils.getAppVersionCode() +
                "\nCPU支持架构：" + Arrays.toString(DeviceUtils.getABIs()) +
                "\n是否Root：" + DeviceUtils.isDeviceRooted());
    }
}
