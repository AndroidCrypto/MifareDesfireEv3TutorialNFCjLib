package de.androidcrypto.desfiretutorial;

/**
 * This class generates the payload for commands on Mifare DESFire EV1/2/3 cards
 * Note that the sanity checks limit some values for my purposes, e.g. fileSize is of maximum 32 bytes
 * Second: I do not use any offset so all data are written or read from the beginning of a file or record
 */

public class PayloadBuilder {

    /**
     * covers the creation of payloads for this file type
     * 00 = Standard Data file
     */

    public PayloadBuilder() {
    }

    private final int MAXIMUM_FILE_NUMBER = 14; // to keep the fileNumber chooser short
    private final int MAXIMUM_KEY_NUMBER = 15;
    private final int MAXIMUM_FILE_SIZE = 256;

    /**
     * section for file type 00 = Standard Files
     */

    public byte[] createStandardFile(int fileNumber, CommunicationSetting communicationSetting, int keyRW, int keyCar, int keyR, int keyW, int fileSize) {
        // sanity checks
        if ((fileNumber < 0) || (fileNumber > MAXIMUM_FILE_NUMBER)) return null;
        if ((keyRW < 0) || (keyRW > MAXIMUM_KEY_NUMBER)) return null;
        if ((keyCar < 0) || (keyCar > MAXIMUM_KEY_NUMBER)) return null;
        if ((keyR < 0) || (keyR > MAXIMUM_KEY_NUMBER)) return null;
        if ((keyW < 0) || (keyW > MAXIMUM_KEY_NUMBER)) return null;
        if (fileSize < 1) return null;

        // build
        byte communicationSettings = 0;
        if (communicationSetting == CommunicationSetting.Plain) communicationSettings = (byte) 0x00;
        if (communicationSetting == CommunicationSetting.MACed) communicationSettings = (byte) 0x01;
        if (communicationSetting == CommunicationSetting.Encrypted) communicationSettings = (byte) 0x03;
        byte accessRightsRwCar = (byte) ((keyRW << 4) | (keyCar & 0x0F)); // Read&Write Access & ChangeAccessRights
        byte accessRightsRW = (byte) ((keyR << 4) | (keyW & 0x0F)); // Read Access & Write Access
        byte[] fileSizeByte = intTo3ByteArrayLsb(fileSize);
        byte[] payload = new byte[7];
        payload[0] = (byte) (fileNumber & 0xff); // fileNumber
        payload[1] = communicationSettings;
        payload[2] = accessRightsRwCar;
        payload[3] = accessRightsRW;
        System.arraycopy(fileSizeByte, 0, payload, 4, 3);
        return payload;
    }

    public byte[] writeToStandardFile(int fileNumber, byte[] data) {
        // sanity checks
        if ((fileNumber < 0) || (fileNumber > MAXIMUM_FILE_NUMBER)) return null;
        if (data == null) return null;
        // build
        byte[] offset = new byte[]{(byte) 0x00, (byte) 0x00, (byte) 0x00}; // write at the beginning, fixed
        byte[] lengthOfData = intTo3ByteArrayLsb(data.length);
        byte[] payload = new byte[7 + data.length]; // 7 + length of data
        payload[0] = (byte) (fileNumber & 0xff); // fileNumber
        System.arraycopy(offset, 0, payload, 1, 3);
        System.arraycopy(lengthOfData, 0, payload, 4, 3);
        System.arraycopy(data, 0, payload, 7, data.length);
        return payload;
    }

    public enum CommunicationSetting{
        Plain, MACed, Encrypted
    }

    // converts an int to a 3 byte long array inversed = LSB style
    private byte[] intTo3ByteArrayLsb(int value) {
        return new byte[] {
                (byte)value,
                (byte)(value >> 8),
                (byte)(value >> 16)};
    }
}
