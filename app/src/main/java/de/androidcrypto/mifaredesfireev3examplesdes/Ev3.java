package de.androidcrypto.mifaredesfireev3examplesdes;

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
            case (byte) 0x40: return "40 No such key error";
            case (byte) 0x6e: return "6E Error (ISO?) error";
            case (byte) 0x7e: return "7E Length error";
            case (byte) 0x97: return "97 Crypto error";
            case (byte) 0x9D: return "9D Permission denied error";
            case (byte) 0x9e: return "9E Parameter error";
            //case (byte) 0x: return " error";

            case (byte) 0xDE: return "DE duplicate error";

        }
        return "undefined error code";
    }


}
