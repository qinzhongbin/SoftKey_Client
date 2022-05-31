package com.qasky.softkey_client;

import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.ServiceConnection;
import android.os.Bundle;
import android.os.IBinder;
import android.os.RemoteException;
import android.view.View;
import android.widget.EditText;

import androidx.annotation.NonNull;
import androidx.appcompat.app.AlertDialog;
import androidx.appcompat.app.AppCompatActivity;

import com.blankj.utilcode.util.ConvertUtils;
import com.blankj.utilcode.util.GsonUtils;
import com.blankj.utilcode.util.LogUtils;
import com.blankj.utilcode.util.ThreadUtils;
import com.blankj.utilcode.util.TimeUtils;
import com.blankj.utilcode.util.ToastUtils;
import com.google.android.material.dialog.MaterialAlertDialogBuilder;
import com.google.android.material.progressindicator.CircularProgressIndicator;
import com.google.android.material.textfield.TextInputLayout;
import com.google.gson.reflect.TypeToken;
import com.qasky.softkey_client.databinding.ActivityMainBinding;
import com.qasky.softkey_client.databinding.DialogSetParamsBinding;
import com.qasky.softkey_client.dto.CleanOLBizKeyReq;
import com.qasky.softkey_client.dto.CleanOLBizKeyResp;
import com.qasky.softkey_client.dto.CreateOLBizKeyReq;
import com.qasky.softkey_client.dto.CreateOLBizKeyResp;
import com.qasky.softkey_client.dto.ExtServerConsultInfo;
import com.qasky.softkey_client.dto.RestResult;
import com.qasky.softkey_client.dto.SvrNegoOLBizKeyReq;
import com.qasky.softkey_client.dto.SvrNegoOLBizKeyResp;
import com.qasky.softkey_client.gm.SM3Util;
import com.qasky.softkey_client.gm.SM4Util;
import com.qasky.softkey_client.okhttp.OkHttpUtil;
import com.qasky.softkey_client.util.CertificateUtil;
import com.qasky.softkey_client.util.PemUtil;
import com.qasky.softkey_client.util.Sm2Util;
import com.qasky.softkey_server.ISKService;
import com.qasky.softkey_server.qcard.Application;
import com.qasky.softkey_server.qcard.NegotiateInfo;

import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.io.pem.PemObject;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Calendar;
import java.util.HashMap;
import java.util.List;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import okhttp3.Call;
import okhttp3.Callback;
import okhttp3.FormBody;
import okhttp3.MediaType;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.RequestBody;
import okhttp3.Response;

public class MainActivity extends AppCompatActivity {
    OkHttpClient okHttpClient;
    AlertDialog loadingDialog;
    AlertDialog paramsDialog;

    DialogSetParamsBinding paramsBinding;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        ActivityMainBinding binding = ActivityMainBinding.inflate(getLayoutInflater());
        setContentView(binding.getRoot());
        binding.tb.setOnMenuItemClickListener(item -> {
            if (item.getItemId() == R.id.set_params) {
                paramsDialog.show();
            }
            return true;
        });


        okHttpClient = OkHttpUtil.getInstance();

        loadingDialog = new MaterialAlertDialogBuilder(this).setView(R.layout.dialog_loading).setCancelable(false).create();

        paramsBinding = DialogSetParamsBinding.inflate(getLayoutInflater());
        paramsDialog = new MaterialAlertDialogBuilder(this)
                .setTitle("设置参数")
                .setView(paramsBinding.getRoot())
                .setPositiveButton("确定", (dialog, which) -> setParams())
                .setNegativeButton("取消", null)
                .create();

        setParams();
    }

    HashMap<String, String> params = new HashMap<>();
    String host;
    String appName;
    String conName;
    String userPIN;
    String softKeyLen;
    String keyAppSvrId;
    String secAuthKey;
    String protectKey;
    String sessionKey;
    String plain;

    byte[] iv = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    byte[] encryptKey;
    byte[] decryptKey;
    byte[] hmacKey;

    private void setParams() {
        params.clear();
        for (int i = 0; i < paramsBinding.params.getChildCount(); i++) {
            EditText et = ((TextInputLayout) paramsBinding.params.getChildAt(i)).getEditText();
            params.put(et.getResources().getResourceEntryName(et.getId()), et.getEditableText().toString());
        }

        host = params.get("host");
        appName = params.get("appName");
        conName = params.get("conName");
        userPIN = params.get("userPIN");
        softKeyLen = params.get("softKeyLen");
        keyAppSvrId = params.get("keyAppSvrId");
        secAuthKey = params.get("secAuthKey");
        protectKey = params.get("protectKey");
        sessionKey = params.get("sessionKey");
        plain = params.get("plain");

        String protectKey = params.get("protectKey");
        String secAuthKey = params.get("secAuthKey");
        byte[] cutProtectKey = Arrays.copyOfRange(SM3Util.hash(protectKey.getBytes(StandardCharsets.UTF_8)), 0, 16);
        byte[] keys = new byte[0];
        try {
            keys = SM4Util.decrypt_CBC_Padding(cutProtectKey, iv, Base64.decode(secAuthKey.getBytes(StandardCharsets.UTF_8)));
        } catch (IllegalBlockSizeException | BadPaddingException | InvalidKeyException | NoSuchAlgorithmException | NoSuchProviderException | NoSuchPaddingException | InvalidAlgorithmParameterException e) {
            e.printStackTrace();
        }

        encryptKey = Arrays.copyOfRange(keys, 0, 16);
        decryptKey = Arrays.copyOfRange(keys, 16, 32);
        hmacKey = Arrays.copyOfRange(keys, 32, 48);
    }

    private ISKService mService;

    ServiceConnection mConnection = new ServiceConnection() {
        public void onServiceConnected(ComponentName className, IBinder service) {
            mService = ISKService.Stub.asInterface(service);
            ToastUtils.showLong("服务已连接\n" + mService);
        }

        public void onServiceDisconnected(ComponentName className) {
            mService = null;
        }
    };

    public void bindService(View view) {
        Intent intent = new Intent().setComponent(new ComponentName("com.qasky.softkey_server", "com.qasky.softkey_server.service.SoftKeyService"));
        boolean success = bindService(intent, mConnection, Context.BIND_AUTO_CREATE);
        ToastUtils.showLong("服务绑定" + (success ? "成功" : "失败"));
    }

    public void unbindService(View view) {
        unbindService(mConnection);
        ToastUtils.showLong("解绑服务");
    }


    public void setSessionKey(View view) {
        try {
            byte[] pem = mService.getPem();
            byte[] content = PemUtil.loadPem(pem).getContent();
            X509Certificate x509Certificate = CertificateUtil.loadX509Certificate(content);
            PublicKey publicKey = x509Certificate.getPublicKey();
            byte[] keyEncrypted = Sm2Util.encrypt(publicKey, sessionKey.getBytes(StandardCharsets.UTF_8));
            mService.setSessionKey(keyEncrypted);
            ToastUtils.showLong("会话密钥：" + sessionKey);
        } catch (RemoteException | IOException | CertificateException | InvalidCipherTextException e) {
            e.printStackTrace();
        }
    }

    public void enumDev(View view) {
        try {
            boolean success = mService.enumDev();
            ToastUtils.showLong("枚举设备" + (success ? "成功" : "失败"));
        } catch (RemoteException e) {
            e.printStackTrace();
        }
    }

    public void freeDevs(View view) {
        try {
            mService.freeDevs();
        } catch (RemoteException e) {
            e.printStackTrace();
        }
    }

    public void loginDev(View view) {
        try {
            boolean success = mService.loginDev();
            ToastUtils.showLong("登录设备" + (success ? "成功" : "失败"));
        } catch (RemoteException e) {
            e.printStackTrace();
        }
    }

    public void logoutDev(View view) {
        try {
            boolean success = mService.logoutDev();
            ToastUtils.showLong("登出设备" + (success ? "成功" : "失败"));
        } catch (RemoteException e) {
            e.printStackTrace();
        }
    }

    public void initResource(View view) {
        try {
            boolean success = mService.initResource();
            ToastUtils.showLong("初始化资源" + (success ? "成功" : "失败"));
        } catch (RemoteException e) {
            e.printStackTrace();
        }
    }

    public void updateResource(View view) {
        try {
            boolean success = mService.updateResource();
            ToastUtils.showLong("更新资源" + (success ? "成功" : "失败"));
        } catch (RemoteException e) {
            e.printStackTrace();
        }
    }

    public void destroyResource(View view) {
        try {
            mService.destroyResource();
            ToastUtils.showLong("销毁资源");
        } catch (RemoteException e) {
            e.printStackTrace();
        }

    }

    String deviceId;

    public void getDeviceId(View view) {
        try {
            deviceId = mService.getDeviceId();
            ToastUtils.showLong("设备ID: " + deviceId);
        } catch (RemoteException e) {
            e.printStackTrace();
        }
    }

    String systemId;

    public void getAppList(View view) {
        try {
            List<Application> appList = mService.getAppList();

            new MaterialAlertDialogBuilder(this)
                    .setTitle("应用列表")
                    .setItems(appList.stream().map(Application::getName).toArray(String[]::new), (dialog, which) -> {
                        Application application = appList.get(which);
                        try {
                            systemId = mService.getSystemId(application.getName(), application.getCntrName());
                            ToastUtils.showLong("系统ID: " + systemId);
                        } catch (RemoteException e) {
                            e.printStackTrace();
                        }
                    })
                    .create()
                    .show();
        } catch (RemoteException e) {
            e.printStackTrace();
        }
    }

    public void queryKeyLength(View view) {
        try {
            long[] keyLenInfo = mService.queryKeyLength(appName, conName);
            ToastUtils.showLong("密钥总量: " + keyLenInfo[0] + "\n" + " 已使用: " + keyLenInfo[1]);
        } catch (RemoteException e) {
            e.printStackTrace();
        }
    }

    public void chargeKey(View view) {
        loadingDialog.show();
        ThreadUtils.executeByIo(new ThreadUtils.SimpleTask<Boolean>() {
            @Override
            public Boolean doInBackground() throws Throwable {
                return mService.chargeKey(host, appName, conName, userPIN);
            }

            @Override
            public void onSuccess(Boolean result) {
                ToastUtils.showLong("密钥充注" + (result ? "成功" : "失败"));
                loadingDialog.dismiss();
            }
        });
    }

    List<NegotiateInfo> negoInfos = new ArrayList<>();

    public void CTSNegotiate(View view) {
        loadingDialog.show();
        String timestamp = String.valueOf(System.currentTimeMillis());
        String authMsg = deviceId + "," + appName + "," + conName + "," + softKeyLen + "," + keyAppSvrId + "," + timestamp;
        String hmac = Base64.toBase64String(SM3Util.hmac(hmacKey, authMsg.getBytes(StandardCharsets.UTF_8)));
        Request request = new Request.Builder()
                .url("https://" + host + "/qkeyapply/serverConsultInfosByApp")
                .post(new FormBody.Builder()
                        .add("storeId", deviceId)
                        .add("appName", appName)
                        .add("containerName", conName)
                        .add("keyLen", softKeyLen)
                        .add("serverId", keyAppSvrId)
                        .add("timestamp", timestamp)
                        .add("hmac", hmac)
                        .build())
                .build();
        okHttpClient.newCall(request).enqueue(new Callback() {
            @Override
            public void onFailure(@NonNull Call call, @NonNull IOException e) {
                loadingDialog.dismiss();
                ToastUtils.showLong(e.getMessage());
            }

            @Override
            public void onResponse(@NonNull Call call, @NonNull Response response) throws IOException {
                loadingDialog.dismiss();
                if (response.isSuccessful()) {
                    RestResult<ExtServerConsultInfo> restResult = GsonUtils.fromJson(response.body().string(), new TypeToken<RestResult<ExtServerConsultInfo>>() {
                    }.getType());
                    ToastUtils.showLong(restResult.getMessage());
                    if (restResult.getCode() == 0) {
                        ExtServerConsultInfo data = restResult.getData();
                        String hmac_expect = Base64.toBase64String(SM3Util.hmac(hmacKey, String.join(",", data.toAuthMsgParams()).getBytes(StandardCharsets.UTF_8)));
                        if (timestamp.equals(data.getTimestamp()) && hmac_expect.equals(data.getHmac())) { // 校验时间戳与hmac
                            negoInfos.add(new NegotiateInfo(data.getFlag().toOriginalOrderJson(), data.getCheckCode()));
                            byte[] softQkey_encrypted = Base64.decode(data.getSoftQkey());
                            try {
                                byte[] softQkey = SM4Util.decrypt_CBC_Padding(decryptKey, iv, softQkey_encrypted);
                                LogUtils.d("服务端软密钥：0x" + ConvertUtils.bytes2HexString(softQkey)); // 客户端导出软密钥对比是否与服务端一致
                            } catch (IllegalBlockSizeException | BadPaddingException | InvalidKeyException | NoSuchAlgorithmException | NoSuchProviderException | NoSuchPaddingException | InvalidAlgorithmParameterException e) {
                                e.printStackTrace();
                            }
                        }
                    }
                }
            }
        });
    }

    public void negoOLBizKey(View view) {
        loadingDialog.show();
        ThreadUtils.getIoPool().execute(() -> {
            // step 1: 服务端创建在线业务密钥
            Calendar calendar = Calendar.getInstance();
            calendar.add(Calendar.YEAR, 1);
            CreateOLBizKeyReq createRequest = new CreateOLBizKeyReq();
            createRequest.setSecretSize(softKeyLen);
            createRequest.setValidityDate(TimeUtils.date2String(calendar.getTime()));
            createRequest.setSystemId(systemId);
            createRequest.setServerId(keyAppSvrId);
            createRequest.setTimestamp(System.currentTimeMillis());
            String authMsg_create = createRequest.getSecretSize() + "," + createRequest.getValidityDate() + "," + createRequest.getSystemId() + "," + createRequest.getServerId() + "," + createRequest.getTimestamp();
            createRequest.setHmac(Base64.toBase64String(SM3Util.hmac(hmacKey, authMsg_create.getBytes(StandardCharsets.UTF_8))));
            try {
                Response response_create = okHttpClient.newCall(new Request.Builder()
                        .url("https://" + host + "/onlinebizkey/createOnlineBizKey")
                        .post(RequestBody.create(GsonUtils.toJson(createRequest), MediaType.parse("application/json; charset=utf-8")))
                        .build()).execute();
                if (response_create.isSuccessful()) {
                    CreateOLBizKeyResp createResponse = GsonUtils.fromJson(response_create.body().string(), CreateOLBizKeyResp.class);
                    if (createResponse.getCode() == 0) {
                        String secretId = createResponse.getData().getSecretId();

                        // step 2: 服务端协商在线业务密钥
                        SvrNegoOLBizKeyReq svrNegoReq = new SvrNegoOLBizKeyReq();
                        svrNegoReq.setSecretId(secretId);
                        svrNegoReq.setSystemId(systemId);
                        svrNegoReq.setServerId(keyAppSvrId);
                        svrNegoReq.setTimestamp(String.valueOf(System.currentTimeMillis()));
                        String authMsg_svrNego = svrNegoReq.getSecretId() + "," + svrNegoReq.getSystemId() + "," + svrNegoReq.getServerId() + "," + svrNegoReq.getTimestamp();
                        svrNegoReq.setHmac(Base64.toBase64String(SM3Util.hmac(hmacKey, authMsg_svrNego.getBytes(StandardCharsets.UTF_8))));
                        Response response_svrNego = okHttpClient.newCall(new Request.Builder()
                                .url("https://" + host + "/onlinebizkey/serverNegotiateOnlineBizKey")
                                .post(RequestBody.create(GsonUtils.toJson(svrNegoReq), MediaType.parse("application/json; charset=utf-8")))
                                .build()).execute();
                        if (response_svrNego.isSuccessful()) {
                            SvrNegoOLBizKeyResp srvNegoResponse = GsonUtils.fromJson(response_svrNego.body().string(), SvrNegoOLBizKeyResp.class);
                            if (srvNegoResponse.getCode() == 0) {
                                String secretKey_encrypted_encoded = srvNegoResponse.getData().getSecretKey();
                                byte[] secretKey_encrypted = Base64.decode(secretKey_encrypted_encoded);
                                byte[] secretKey = SM4Util.decrypt_CBC_Padding(decryptKey, iv, secretKey_encrypted);
                                LogUtils.d("服务端在线业务密钥：0x" + ConvertUtils.bytes2HexString(secretKey));

                                // step 3: 客户端协商在线业务密钥
                                Thread.sleep(1000L); // 客户端协商时间应比服务端协商时间晚，模拟延时操作。
                                NegotiateInfo negotiateInfo = mService.negoOLBizKey(host, deviceId, systemId, secretId, keyAppSvrId, secAuthKey, protectKey);
                                if (negotiateInfo != null) {
                                    ToastUtils.showLong("在线业务密钥协商成功");
                                    negoInfos.add(negotiateInfo);
                                } else {
                                    ToastUtils.showLong("在线业务密钥协商失败");
                                }

                                // step 3.1: 获取密钥句柄
                                // step 3.2: 导出软密钥
                                // step 3.3: 对比客户端软密钥与服务端业务密钥是否一致
                                // step 4: 服务端销毁在线业务密钥 (业务结束后调用)
                                CleanOLBizKeyReq cleanRequest = new CleanOLBizKeyReq();
                                cleanRequest.setSecretId(secretId);
                                cleanRequest.setSystemId(systemId);
                                cleanRequest.setServerId(keyAppSvrId);
                                cleanRequest.setTimestamp(String.valueOf(System.currentTimeMillis()));
                                String authMsg_clean = cleanRequest.getSecretId() + "," + cleanRequest.getSystemId() + "," + cleanRequest.getServerId() + "," + cleanRequest.getTimestamp();
                                cleanRequest.setHmac(Base64.toBase64String(SM3Util.hmac(hmacKey, authMsg_clean.getBytes(StandardCharsets.UTF_8))));
                                Response response_clean = okHttpClient.newCall(new Request.Builder()
                                        .url("https://" + host + "/onlinebizkey/cleanNegotiateOnlineBizKey")
                                        .post(RequestBody.create(GsonUtils.toJson(cleanRequest), MediaType.parse("application/json; charset=utf-8")))
                                        .build()).execute();
                                if (response_clean.isSuccessful()) {
                                    CleanOLBizKeyResp cleanResponse = GsonUtils.fromJson(response_clean.body().string(), CleanOLBizKeyResp.class);
                                    if (cleanResponse.getCode() == 0) {
                                        LogUtils.d("清除在线业务密钥成功");
                                    } else {
                                        ToastUtils.showLong(cleanResponse.getMessage());
                                    }
                                }
                            } else {
                                ToastUtils.showLong(srvNegoResponse.getMessage());
                            }
                        }
                    } else {
                        ToastUtils.showLong(createResponse.getMessage());
                    }
                }
            } catch (Exception e) {
                e.printStackTrace();
            }
            loadingDialog.dismiss();
        });
    }

    long keyHandle;

    public void getKeyHandle(View view) {
        new AlertDialog.Builder(this)
                .setTitle("选择密钥协商信息检验码")
                .setItems(negoInfos.stream().map(NegotiateInfo -> NegotiateInfo.checkCode).toArray(String[]::new), (dialog, which) -> {
                    NegotiateInfo negotiateInfo = negoInfos.get(which);
                    try {
                        keyHandle = mService.getKeyHandle(appName, conName, userPIN, negotiateInfo.checkCode, negotiateInfo.flag);
                        ToastUtils.showLong("密钥句柄: 0x" + Long.toHexString(keyHandle));
                    } catch (RemoteException e) {
                        e.printStackTrace();
                    }
                })
                .setCancelable(false)
                .create().show();
    }

    public void freeKeyHandle(View view) {
        try {
            mService.freeKeyHandle(keyHandle);
            ToastUtils.showLong("释放密钥句柄");
        } catch (RemoteException e) {
            e.printStackTrace();
        }
    }

    byte[] cipher;

    public void encrypt(View view) {
        try {
            cipher = mService.encrypt(keyHandle, plain.getBytes(StandardCharsets.UTF_8));
            ToastUtils.showLong("加密成功");
        } catch (RemoteException e) {
            e.printStackTrace();
        }
    }

    public void decrypt(View view) {
        try {
            byte[] plain = mService.decrypt(keyHandle, cipher);
            ToastUtils.showLong(new String(plain, StandardCharsets.UTF_8));
        } catch (RemoteException e) {
            e.printStackTrace();
        }
    }

    public void getSoftKey(View view) {
        try {
            byte[] softKey;
            softKey = mService.getSoftKey(keyHandle, Long.parseLong(softKeyLen));
            softKey = SM4Util.decrypt_CBC_Padding(sessionKey.getBytes(StandardCharsets.UTF_8), iv, softKey);
            ToastUtils.showLong(ConvertUtils.bytes2HexString(softKey));
        } catch (RemoteException | IllegalBlockSizeException | BadPaddingException | InvalidKeyException | NoSuchAlgorithmException | NoSuchProviderException | NoSuchPaddingException | InvalidAlgorithmParameterException e) {
            e.printStackTrace();
            System.out.println(e);
        }
    }
}
