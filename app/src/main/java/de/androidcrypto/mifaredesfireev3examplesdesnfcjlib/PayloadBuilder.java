package de.androidcrypto.mifaredesfireev3examplesdesnfcjlib;

import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

/**
 * This class generates the payload for commands on Mifare DESFire EV1/2/3 cards
 * Note that the sanity checks limit some values for my purposes, e.g. fileSize is of maximum 32 bytes
 * Second: I do not use any offset so all data are written or read from the beginning of a file or record
 */

public class PayloadBuilder {

    /**
     * covers the create a write payloads for these file types
     * 00 = Standard Data file
     * 02 = Value files
     * 03 = Linear Records file
     * 04 = Cyclic Records file
     */

    public PayloadBuilder() {
    }

    private final int MAXIMUM_FILE_NUMBER = 15;
    private final int MAXIMUM_KEY_NUMBER = 15;
    private final int MAXIMUM_RECORD_NUMBER = 15;
    private final int MAXIMUM_FILE_SIZE = 32; // avoid framing
    private final int MAXIMUM_VALUE_CREDIT = 50;
    private final int MAXIMUM_VALUE_DEBIT = 50;
    private final int MINIMUM_VALUE_LOWER_LIMIT = 0;
    private final int MAXIMUM_VALUE_LOWER_LIMIT = 100;
    private final int MINIMUM_VALUE_UPPER_LIMIT = 0;
    private final int MAXIMUM_VALUE_UPPER_LIMIT = 100;
    private final int MAXIMUM_VALUE = 1000;

    public byte[] createApplicationIso(byte[] aid, byte keySettings, byte numberOfKeys, byte[] isoFileId, byte[] isoDfName) {
        // sanity checks
        if ((aid == null) || (isoFileId == null) || (isoDfName == null)) return null;
        if (Arrays.equals(aid, new byte[3])) return null;
        if (aid.length != 3) return null;
        // todo get a good check on key numbers range because they are combined with the kind of keys:
        // 00..0f = DES keys, 40..4f TDES keys, 80..8f AES keys
        //if ((numberOfKeys < 1) || (numberOfKeys > 15)) return null;
        if (isoFileId.length != 2) return null;
        if ((isoDfName.length < 1) || (isoDfName.length > 16)) return null;

        // build
        // we use a ByteArrayOutputStream as the ISO DF Name can be 1 to 15 bytes long
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        baos.write(aid, 0, 3);
        baos.write(keySettings);
        baos.write(numberOfKeys);
        baos.write(isoFileId, 0, 2);
        baos.write(isoDfName, 0, isoDfName.length);
        return baos.toByteArray();
    }

    /**
     * section for file type 00 = Standard Files
     */

    public byte[] createStandardFileLimitedFileSize(int fileNumber, CommunicationSetting communicationSetting, int keyRW, int keyCar, int keyR, int keyW, int fileSize) {
        // sanity checks
        if ((fileNumber < 0) || (fileNumber > MAXIMUM_FILE_NUMBER)) return null;
        if ((keyRW < 0) || (keyRW > MAXIMUM_KEY_NUMBER)) return null;
        if ((keyCar < 0) || (keyCar > MAXIMUM_KEY_NUMBER)) return null;
        if ((keyR < 0) || (keyR > MAXIMUM_KEY_NUMBER)) return null;
        if ((keyW < 0) || (keyW > MAXIMUM_KEY_NUMBER)) return null;
        if ((fileSize < 1) || (fileSize > MAXIMUM_FILE_SIZE)) return null;

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

    /*
        step 4
        MIFARE DESFire CreateStdDataFile with FileNo equal to 01h (CC File DESFire FID),
        ISO FileID equal to E103h, ComSet equal to 00h, AccessRights equal to EEEEh,
        FileSize bigger equal to 00000Fh
        Command: 90 CD 00 00 09 01 03 E1 00 00 E0 0F 00 00 00h
        NOTE: There is an error in the command, the Access Rights do have a wrong value

        step 6
        MIFARE DESFire CreateStdDataFile with FileNo equal to 02h (NDEF File DESFire FID),
        ISO FileID equal to E104h, ComSet equal to 00h, AccessRights equal to EEE0h,
        FileSize equal to 000800h (2048 Bytes)
        Command: 90 CD 00 00 09 02 04 E1 00 E0 EE 00 08 00 00h
         */
    public byte[] createStandardFileIso(int fileNumber, byte[] isoFileId, CommunicationSetting communicationSetting, int keyRW, int keyCar, int keyR, int keyW, int fileSize) {
        // sanity checks
        if ((fileNumber < 0) || (fileNumber > MAXIMUM_FILE_NUMBER)) return null;
        if (isoFileId == null) return null;
        if ((keyRW < 0) || (keyRW > MAXIMUM_KEY_NUMBER)) return null;
        if ((keyCar < 0) || (keyCar > MAXIMUM_KEY_NUMBER)) return null;
        if ((keyR < 0) || (keyR > MAXIMUM_KEY_NUMBER)) return null;
        if ((keyW < 0) || (keyW > MAXIMUM_KEY_NUMBER)) return null;
        //if ((fileSize < 0) || (fileSize > MAXIMUM_FILE_SIZE)) return null;
        if (fileSize < 0) return null;

        // build
        byte communicationSettings = 0;
        if (communicationSetting == CommunicationSetting.Plain) communicationSettings = (byte) 0x00;
        if (communicationSetting == CommunicationSetting.MACed) communicationSettings = (byte) 0x01;
        if (communicationSetting == CommunicationSetting.Encrypted) communicationSettings = (byte) 0x03;
        byte accessRightsRwCar = (byte) ((keyRW << 4) | (keyCar & 0x0F)); // Read&Write Access & ChangeAccessRights
        byte accessRightsRW = (byte) ((keyR << 4) | (keyW & 0x0F)) ;// Read Access & Write Access // read with key 0, write with key 0
        byte[] fileSizeByte = intTo3ByteArrayLsb(fileSize);
        byte[] payload = new byte[9];
        payload[0] = (byte) (fileNumber & 0xff); // fileNumber
        System.arraycopy(isoFileId, 0, payload, 1, 2);
        payload[3] = communicationSettings;
        payload[4] = accessRightsRwCar;
        payload[5] = accessRightsRW;
        System.arraycopy(fileSizeByte, 0, payload, 6, 3);
        return payload;
    }

    // special version for testing frames
    public byte[] createStandardFileMax70(int fileNumber, CommunicationSetting communicationSetting, int keyRW, int keyCar, int keyR, int keyW, int fileSize) {
        // sanity checks
        if ((fileNumber < 0) || (fileNumber > MAXIMUM_FILE_NUMBER)) return null;
        if ((keyRW < 0) || (keyRW > MAXIMUM_KEY_NUMBER)) return null;
        if ((keyCar < 0) || (keyCar > MAXIMUM_KEY_NUMBER)) return null;
        if ((keyR < 0) || (keyR > MAXIMUM_KEY_NUMBER)) return null;
        if ((keyW < 0) || (keyW > MAXIMUM_KEY_NUMBER)) return null;
        if ((fileSize < 0) || (fileSize > 70)) return null;

        // build
        byte communicationSettings = 0;
        if (communicationSetting == CommunicationSetting.Plain) communicationSettings = (byte) 0x00;
        if (communicationSetting == CommunicationSetting.MACed) communicationSettings = (byte) 0x01;
        if (communicationSetting == CommunicationSetting.Encrypted) communicationSettings = (byte) 0x03;
        byte accessRightsRwCar = (byte) ((keyRW << 4) | (keyCar & 0x0F)); // Read&Write Access & ChangeAccessRights
        byte accessRightsRW = (byte) ((keyR << 4) | (keyW & 0x0F)) ;// Read Access & Write Access // read with key 0, write with key 0
        byte[] fileSizeByte = intTo3ByteArrayLsb(fileSize);
        byte[] payload = new byte[7];
        payload[0] = (byte) (fileNumber & 0xff); // fileNumber
        payload[1] = communicationSettings;
        payload[2] = accessRightsRwCar;
        payload[3] = accessRightsRW;
        System.arraycopy(fileSizeByte, 0, payload, 4, 3);
        return payload;
    }

    public byte[] writeToStandardFile(int fileNumber, String data) {
        return writeToStandardFile(fileNumber, data.getBytes(StandardCharsets.UTF_8));
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

    public byte[] writeToStandardFileLimitedFileSize(int fileNumber, String data) {
        return writeToStandardFileLimitedFileSize(fileNumber, data.getBytes(StandardCharsets.UTF_8));
    }
    public byte[] writeToStandardFileLimitedFileSize(int fileNumber, byte[] data) {
        // sanity checks
        if ((fileNumber < 0) || (fileNumber > MAXIMUM_FILE_NUMBER)) return null;
        if (data == null) return null;
        if (data.length > MAXIMUM_FILE_SIZE) return null; // avoid framing

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

    public byte[] writeToStandardFileNdef(int fileNumber, byte[] data) {
        // sanity checks
        if ((fileNumber < 0) || (fileNumber > MAXIMUM_FILE_NUMBER)) return null;
        if (data == null) return null;
        if (data.length > MAXIMUM_FILE_SIZE) return null; // avoid framing

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

    public byte[] writeToStandardFileMax70(int fileNumber, byte[] data) {
        // sanity checks
        if ((fileNumber < 0) || (fileNumber > MAXIMUM_FILE_NUMBER)) return null;
        if (data == null) return null;
        if (data.length > 70) return null; // avoid framing

        // build
        byte[] offset = new byte[]{(byte) 0x00, (byte) 0xf00, (byte) 0x00}; // write at the beginning, fixed
        byte[] lengthOfData = intTo3ByteArrayLsb(data.length);
        byte[] payload = new byte[7 + data.length]; // 7 + length of data
        payload[0] = (byte) (fileNumber & 0xff); // fileNumber
        System.arraycopy(offset, 0, payload, 1, 3);
        System.arraycopy(lengthOfData, 0, payload, 4, 3);
        System.arraycopy(data, 0, payload, 7, data.length);
        return payload;
    }


    public byte[] readFromStandardFile(int fileNumber, int offsetToRead, int sizeToRead) {
        // sanity checks
        if ((fileNumber < 0) || (fileNumber > MAXIMUM_FILE_NUMBER)) return null;
        if ((offsetToRead < 0) || (offsetToRead > 40)) return null;
        if ((sizeToRead < 1) || (sizeToRead > 70)) return null;

        // build
        byte[] payload = new byte[7];
        byte[] offset = intTo3ByteArrayLsb(offsetToRead);
        byte[] lengthOfData = intTo3ByteArrayLsb(sizeToRead);
        payload[0] = (byte) (fileNumber & 0xff); // fileNumber
        System.arraycopy(offset, 0, payload, 1, 3);
        System.arraycopy(lengthOfData, 0, payload, 4, 3);
        return payload;
    }

    /**
     * section for file type 02 = Value Files
     */

    // note: a lot of limits are applied to parameters
    public byte[] createValueFile(int fileNumber, CommunicationSetting communicationSetting, int keyRW, int keyCar, int keyR, int keyW, int lowerLimit, int upperLimit, int value) {
        // sanity checks
        if ((fileNumber < 0) || (fileNumber > MAXIMUM_FILE_NUMBER)) return null;
        if ((keyRW < 0) || (keyRW > MAXIMUM_KEY_NUMBER)) return null;
        if ((keyCar < 0) || (keyCar > MAXIMUM_KEY_NUMBER)) return null;
        if ((keyR < 0) || (keyR > MAXIMUM_KEY_NUMBER)) return null;
        if ((keyW < 0) || (keyW > MAXIMUM_KEY_NUMBER)) return null;
        if ((lowerLimit < MINIMUM_VALUE_LOWER_LIMIT) || (lowerLimit > MAXIMUM_VALUE_LOWER_LIMIT)) return null;
        if ((upperLimit < MINIMUM_VALUE_LOWER_LIMIT) || (upperLimit > MAXIMUM_VALUE_UPPER_LIMIT)) return null;
        if (upperLimit <= lowerLimit) return null;
        if ((value < 0) || (value > 100)) return null;

        // build
        byte communicationSettings = 0;
        if (communicationSetting == CommunicationSetting.Plain) communicationSettings = (byte) 0x00;
        if (communicationSetting == CommunicationSetting.MACed) communicationSettings = (byte) 0x01;
        if (communicationSetting == CommunicationSetting.Encrypted) communicationSettings = (byte) 0x03;
        byte accessRightsRwCar = (byte) ((keyRW << 4) | (keyCar & 0x0F)); // Read&Write Access & ChangeAccessRights
        byte accessRightsRW = (byte) ((keyR << 4) | (keyW & 0x0F)) ;// Read Access & Write Access // read with key 0, write with key 0

        byte[] payload = new byte[17]; // just to show the length
        byte[] lowerLimitByte = intTo4Byte_le(lowerLimit);
        byte[] upperLimitByte = intTo4Byte_le(upperLimit);
        byte[] valueByte = intTo4Byte_le(value);
        byte limitedCreditOperationEnabled = (byte) 0x00; // 00 means not enabled, 1 means enabled feature
        payload[0] = (byte) (fileNumber & 0xff); // fileNumber
        payload[1] = communicationSettings;
        payload[2] = accessRightsRwCar;
        payload[3] = accessRightsRW;
        System.arraycopy(lowerLimitByte, 0, payload, 4, 4);
        System.arraycopy(upperLimitByte, 0, payload, 8, 4);
        System.arraycopy(valueByte, 0, payload, 12, 4);
        payload[16] = limitedCreditOperationEnabled;
        return payload;
    }

    public byte[] creditValueFile(int fileNumber, int creditValue) {
        if ((fileNumber < 0) || (fileNumber > MAXIMUM_FILE_NUMBER)) return null;
        if ((creditValue < 0) || (creditValue > MAXIMUM_VALUE_CREDIT)) return null;

        // build
        byte[] payload = new byte[5];
        byte[] value = intTo4Byte_le(creditValue);
        payload[0] = (byte) (fileNumber & 0xff); // fileNumber
        System.arraycopy(value, 0, payload, 1, 4);
        return payload;
    }

    // the debitValue needs to be positive
    public byte[] debitValueFile(int fileNumber, int debitValue) {
        if ((fileNumber < 0) || (fileNumber > MAXIMUM_FILE_NUMBER)) return null;
        if ((debitValue < 0) || (debitValue > MAXIMUM_VALUE_DEBIT)) return null;

        // build
        byte[] payload = new byte[5];
        byte[] value = intTo4Byte_le(debitValue);
        payload[0] = (byte) (fileNumber & 0xff); // fileNumber
        System.arraycopy(value, 0, payload, 1, 4);
        return payload;
    }

    /**
     * section for file type 03 = Linear Records Files
     */

    public byte[] createLinearRecordsFile(int fileNumber, CommunicationSetting communicationSetting, int keyRW, int keyCar, int keyR, int keyW, int fileSize, int maximumRecords) {
        // sanity checks
        if ((fileNumber < 0) || (fileNumber > MAXIMUM_FILE_NUMBER)) return null;
        if ((keyRW < 0) || (keyRW > MAXIMUM_KEY_NUMBER)) return null;
        if ((keyCar < 0) || (keyCar > MAXIMUM_KEY_NUMBER)) return null;
        if ((keyR < 0) || (keyR > MAXIMUM_KEY_NUMBER)) return null;
        if ((keyW < 0) || (keyW > MAXIMUM_KEY_NUMBER)) return null;
        if ((fileSize < 0) || (fileSize > MAXIMUM_FILE_SIZE)) return null;
        if ((maximumRecords < 1) || (maximumRecords > MAXIMUM_RECORD_NUMBER)) return null;

        // build
        byte[] payload = new byte[10]; // just to show the length
        byte communicationSettings = 0;
        if (communicationSetting == CommunicationSetting.Plain) communicationSettings = (byte) 0x00;
        if (communicationSetting == CommunicationSetting.MACed) communicationSettings = (byte) 0x01;
        if (communicationSetting == CommunicationSetting.Encrypted) communicationSettings = (byte) 0x03;
        byte accessRightsRwCar = (byte) ((keyRW << 4) | (keyCar & 0x0F)); // Read&Write Access & ChangeAccessRights
        byte accessRightsRW = (byte) ((keyR << 4) | (keyW & 0x0F)) ;// Read Access & Write Access // read with key 0, write with key 0
        byte[] fileSizeByte = intTo3ByteArrayLsb(fileSize);
        byte[] maximumRecordsByte = intTo3ByteArrayLsb(maximumRecords);
        payload[0] = (byte) (fileNumber & 0xff); // fileNumber
        payload[1] = communicationSettings;
        payload[2] = accessRightsRwCar;
        payload[3] = accessRightsRW;
        System.arraycopy(fileSizeByte, 0, payload, 4, 3);
        System.arraycopy(maximumRecordsByte, 0, payload, 7, 3);
        return payload;
    }

    public byte[] writeToLinearRecordsFile(int fileNumber, String data) {
        // is essentially the same command as for Cyclic Records Files
        return writeToCyclicRecordsFile(fileNumber, data.getBytes(StandardCharsets.UTF_8));
        //return writeToLinearRecordsFile(fileNumber, data.getBytes(StandardCharsets.UTF_8));
    }

    public byte[] writeToLinearRecordsFile(int fileNumber, byte[] data) {
        // is essentially the same command as for Cyclic Records Files
        return writeToCyclicRecordsFile(fileNumber, data);
    }

    /**
     * section for file type 04 = Cyclic Records Files
     */

    // as a new record is temporary stored the maximum number needs to be maximum + 1,
    // so the minimum on this field is 2
    public byte[] createCyclicRecordsFile(int fileNumber, CommunicationSetting communicationSetting, int keyRW, int keyCar, int keyR, int keyW, int fileSize, int maximumRecords) {
        // sanity checks
        if ((fileNumber < 0) || (fileNumber > MAXIMUM_FILE_NUMBER)) return null;
        if ((keyRW < 0) || (keyRW > MAXIMUM_KEY_NUMBER)) return null;
        if ((keyCar < 0) || (keyCar > MAXIMUM_KEY_NUMBER)) return null;
        if ((keyR < 0) || (keyR > MAXIMUM_KEY_NUMBER)) return null;
        if ((keyW < 0) || (keyW > MAXIMUM_KEY_NUMBER)) return null;
        if ((fileSize < 0) || (fileSize > MAXIMUM_FILE_SIZE)) return null;
        if ((maximumRecords < 2) || (maximumRecords > MAXIMUM_RECORD_NUMBER)) return null;

        // build
        byte[] payload = new byte[10]; // just to show the length
        byte communicationSettings = 0;
        if (communicationSetting == CommunicationSetting.Plain) communicationSettings = (byte) 0x00;
        if (communicationSetting == CommunicationSetting.MACed) communicationSettings = (byte) 0x01;
        if (communicationSetting == CommunicationSetting.Encrypted) communicationSettings = (byte) 0x03;
        byte accessRightsRwCar = (byte) ((keyRW << 4) | (keyCar & 0x0F)); // Read&Write Access & ChangeAccessRights
        byte accessRightsRW = (byte) ((keyR << 4) | (keyW & 0x0F)) ;// Read Access & Write Access // read with key 0, write with key 0
        byte[] fileSizeByte = intTo3ByteArrayLsb(fileSize);
        byte[] maximumRecordsByte = intTo3ByteArrayLsb(maximumRecords);
        payload[0] = (byte) (fileNumber & 0xff); // fileNumber
        payload[1] = communicationSettings;
        payload[2] = accessRightsRwCar;
        payload[3] = accessRightsRW;
        System.arraycopy(fileSizeByte, 0, payload, 4, 3);
        System.arraycopy(maximumRecordsByte, 0, payload, 7, 3);
        return payload;
    }

    public byte[] writeToCyclicRecordsFile(int fileNumber, String data) {
        return writeToCyclicRecordsFile(fileNumber, data.getBytes(StandardCharsets.UTF_8));
    }

    public byte[] writeToCyclicRecordsFile(int fileNumber, byte[] data) {
        // sanity checks
        if ((fileNumber < 0) || (fileNumber > MAXIMUM_FILE_NUMBER)) return null;
        if (data == null) return null;
        if (data.length > MAXIMUM_FILE_SIZE) return null;

        // build
        byte[] offset = new byte[]{(byte) 0x00, (byte) 0xf00, (byte) 0x00}; // write at the beginning, fixed
        byte[] lengthOfData = intTo3ByteArrayLsb(data.length);
        byte[] payload = new byte[7 + data.length]; // 7 + length of data
        payload[0] = (byte) (fileNumber & 0xff); // fileNumber
        System.arraycopy(offset, 0, payload, 1, 3);
        System.arraycopy(lengthOfData, 0, payload, 4, 3);
        System.arraycopy(data, 0, payload, 7, data.length);
        return payload;
    }

    public byte[] readFromCyclicRecordsFile(int fileNumber, int recordNumberToRead, int numberOfRecords) {
        // sanity checks
        if ((fileNumber < 0) || (fileNumber > MAXIMUM_FILE_NUMBER)) return null;
        if ((recordNumberToRead < 0) || (recordNumberToRead > MAXIMUM_RECORD_NUMBER)) return null;
        if ((numberOfRecords < 1) || (numberOfRecords > MAXIMUM_RECORD_NUMBER)) return null;
        if (recordNumberToRead >= numberOfRecords) return null;

        // build
        byte[] payload = new byte[7];
        byte[] recordNumber = intTo3ByteArrayLsb(recordNumberToRead);
        byte[] numberOfRecordsByte = intTo3ByteArrayLsb(numberOfRecords);
        payload[0] = (byte) (fileNumber & 0xff); // fileNumber
        System.arraycopy(recordNumber, 0, payload, 1, 3);
        System.arraycopy(numberOfRecordsByte, 0, payload, 4, 3);
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

    // conversions see https://stackoverflow.com/a/10380460/8166854
    private byte[] intTo4Byte_le(int myInteger){
        return ByteBuffer.allocate(4).order(ByteOrder.LITTLE_ENDIAN).putInt(myInteger).array();
    }

    private int byte4ToInt_le(byte [] byteArray){
        return ByteBuffer.wrap(byteArray).order(ByteOrder.LITTLE_ENDIAN).getInt();
    }

    private byte[] intTo4Byte_be(int myInteger){
        return ByteBuffer.allocate(4).order(ByteOrder.BIG_ENDIAN).putInt(myInteger).array();
    }

    private int byte4ToInt_be(byte [] byteArray){
        return ByteBuffer.wrap(byteArray).order(ByteOrder.BIG_ENDIAN).getInt();
    }

}
