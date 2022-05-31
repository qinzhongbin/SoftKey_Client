package com.qasky.softkey_server.qcard;

import android.os.Parcel;
import android.os.Parcelable;

public class Application implements Parcelable {
    private String name;
    private String cntrName;

    public Application(String name, String cntrName) {
        this.name = name;
        this.cntrName = cntrName;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getCntrName() {
        return cntrName;
    }

    public void setCntrName(String cntrName) {
        this.cntrName = cntrName;
    }

    protected Application(Parcel in) {
        name = in.readString();
        cntrName = in.readString();
    }

    @Override
    public void writeToParcel(Parcel dest, int flags) {
        dest.writeString(name);
        dest.writeString(cntrName);
    }

    @Override
    public int describeContents() {
        return 0;
    }

    public static final Creator<Application> CREATOR = new Creator<Application>() {
        @Override
        public Application createFromParcel(Parcel in) {
            return new Application(in);
        }

        @Override
        public Application[] newArray(int size) {
            return new Application[size];
        }
    };
}
