package com.kryptix.kryptix;

import android.os.Bundle;
import com.getcapacitor.BridgeActivity;

public class MainActivity extends BridgeActivity {
    @Override
    public void onCreate(Bundle savedInstanceState) {
        registerPlugin(HyperDrivePlugin.class);
        super.onCreate(savedInstanceState);
    }
}
