package com.wifichat.utils;

import java.io.InputStream;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.util.ArrayList;
import java.util.List;

import android.app.Activity;

import com.wifichat.R;

public class SSLUtils {
	
	public static KeyStore loadClientKeystore(Activity activity) {
		
		try {
			String keyStoreType = KeyStore.getDefaultType();
			KeyStore keyStore = KeyStore.getInstance(keyStoreType);
			InputStream keyStoreStream = activity.getResources().openRawResource(R.raw.client2);
			keyStore.load(keyStoreStream, "123456".toCharArray());
			return keyStore;
		} catch (Exception e) {
			e.printStackTrace();
		}
		return null;
	}
	
	public static String[] getCipherSuitesWhiteList(String[] cipherSuites) {
        List<String> whiteList = new ArrayList<String>();
        List<String> rejected = new ArrayList<String>();
        for (String suite : cipherSuites) {
            String s = suite.toLowerCase();
            if (s.contains("anon") || //reject no anonymous
                    s.contains("export") || //reject no export
                    s.contains("null") || //reject no encryption
                    s.contains("md5") || //reject MD5 (weaknesses)
                    s.contains("_des") || //reject DES (key size too small)
                    s.contains("krb5") || //reject Kerberos: unlikely to be used
                    s.contains("ssl") || //reject ssl (only tls)
                    s.contains("empty")) {    //not sure what this one is
                rejected.add(suite);
            } else {
                whiteList.add(suite);
            }
        }
        //return new String[]{"TLSv1"};
        return whiteList.toArray(new String[whiteList.size()]);
        //return cipherSuites;
    }
}
