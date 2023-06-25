package de.androidcrypto.mifaredesfireev3examplesdesnfcjlib;

import android.graphics.Color;

import java.security.SecureRandom;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class Ev3 {





    public static String getErrorCode(byte[] twoByteResponse) {
        if (twoByteResponse == null) {
            return "response is null";
        }
        if (twoByteResponse.length != 2) {
            return "response is not of 2 bytes length";
        }
        byte sw1 = twoByteResponse[0];
        if (sw1 != (byte) 0x91) {
            return "first byte is not 0x91";
        }
        byte sw2 = twoByteResponse[1];
        switch (sw2) {
            case (byte) 0x00: return "00 success";
            case (byte) 0x0c: return "0C no change";
            case (byte) 0x0e: return "0E out of EPROM memory";
            case (byte) 0x1c: return "1C illegal command";
            case (byte) 0x1e: return "1E integrity error";
            case (byte) 0x40: return "40 No such key error";
            case (byte) 0x6e: return "6E Error (ISO?) error";
            case (byte) 0x7e: return "7E Length error";
            case (byte) 0x97: return "97 Crypto error";
            case (byte) 0x9D: return "9D Permission denied error";
            case (byte) 0x9e: return "9E Parameter error";
            //case (byte) 0x: return " error";
            case (byte) 0xA0: return "A0 application not found error";
            case (byte) 0xAE: return "AE authentication error";
            case (byte) 0xAF: return "AF Additional frame (more data to follow before final status code)";
            case (byte) 0xDE: return "DE duplicate error";

        }
        return "undefined error code";
    }

    public static int getColorFromErrorCode(String oneByteResponseString) {
        byte oneByteResponse = Byte.parseByte(oneByteResponseString);
        int colorRed = Color.rgb(255,0,0); // red
        int colorGreen = Color.rgb(0,255,0); // green
        if (oneByteResponse == (byte) 0x00) {
            return colorGreen;
        } else {
            return colorRed;
        }
    }

    /**
     * section for DES encryption
     */

    public static byte[] decrypt(byte[] data, byte[] key, byte[] IV) throws Exception {
        Cipher cipher = getCipher(Cipher.DECRYPT_MODE, key, IV);
        return cipher.doFinal(data);
    }

    public static byte[] encrypt(byte[] data, byte[] key, byte[] IV) throws Exception {
        Cipher cipher = getCipher(Cipher.ENCRYPT_MODE, key, IV);
        return cipher.doFinal(data);
    }

    public static Cipher getCipher(int mode, byte[] key, byte[] IV) throws Exception {
        Cipher cipher = Cipher.getInstance("DES/CBC/NoPadding");
        SecretKeySpec keySpec = new SecretKeySpec(key, "DES");
        IvParameterSpec algorithmParamSpec = new IvParameterSpec(IV);
        cipher.init(mode, keySpec, algorithmParamSpec);
        return cipher;
    }

    public static byte[] rotateLeft(byte[] data) {
        byte[] rotated = new byte[data.length];
        rotated[data.length - 1] = data[0];
        for (int i = 0; i < data.length - 1; i++) {
            rotated[i] = data[i + 1];
        }
        return rotated;
    }

    public static byte[] rotateRight(byte[] data) {
        byte[] unrotated = new byte[data.length];
        for (int i = 1; i < data.length; i++) {
            unrotated[i] = data[i - 1];
        }
        unrotated[0] = data[data.length - 1];
        return unrotated;
    }

    public static byte[] concatenate(byte[] dataA, byte[] dataB) {
        byte[] concatenated = new byte[dataA.length + dataB.length];
        for (int i = 0; i < dataA.length; i++) {
            concatenated[i] = dataA[i];
        }
        for (int i = 0; i < dataB.length; i++) {
            concatenated[dataA.length + i] = dataB[i];
        }
        return concatenated;
    }

    public static byte[] getRndADes() {
        byte[] value = new byte[8];
        SecureRandom secureRandom = new SecureRandom();
        secureRandom.nextBytes(value);
        return value;
    }



}
