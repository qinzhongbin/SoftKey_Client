package com.qasky.softkey_server.qcard;

import android.os.Parcel;
import android.os.Parcelable;

public class NegotiateInfo implements Parcelable {
    public String flag;
    public String checkCode;

    public NegotiateInfo(String flag, String checkCode) {
        this.flag = flag;
        this.checkCode = checkCode;
    }

    protected NegotiateInfo(Parcel in) {
        flag = in.readString();
        checkCode = in.readString();
    }

    public static final Creator<NegotiateInfo> CREATOR = new Creator<NegotiateInfo>() {
        @Override
        public NegotiateInfo createFromParcel(Parcel in) {
            return new NegotiateInfo(in);
        }

        @Override
        public NegotiateInfo[] newArray(int size) {
            return new NegotiateInfo[size];
        }
    };

    @Override
    public int describeContents() {
        return 0;
    }

    @Override
    public void writeToParcel(Parcel dest, int flags) {
        dest.writeString(flag);
        dest.writeString(checkCode);
    }
}
