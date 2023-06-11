package de.androidcrypto.mifaredesfireev3examplesdesnfcjlib;

import android.content.Context;
import android.content.DialogInterface;
import android.nfc.NfcAdapter;
import android.nfc.Tag;
import android.nfc.tech.IsoDep;
import android.os.Build;
import android.os.Bundle;
import android.os.VibrationEffect;
import android.os.Vibrator;
import android.view.Menu;
import android.view.MenuItem;
import android.view.View;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.TextView;

import androidx.annotation.NonNull;
import androidx.appcompat.app.AlertDialog;
import androidx.appcompat.app.AppCompatActivity;
import androidx.appcompat.widget.Toolbar;

import com.github.skjolber.desfire.ev1.model.DesfireApplicationId;
import com.github.skjolber.desfire.ev1.model.VersionInfo;
import com.github.skjolber.desfire.ev1.model.command.DefaultIsoDepWrapper;
import com.github.skjolber.desfire.ev1.model.command.IsoDepWrapper;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import nfcjlib.core.DESFireAdapter;
import nfcjlib.core.DESFireEV1;
import nfcjlib.core.KeyType;

public class MainActivity extends AppCompatActivity implements NfcAdapter.ReaderCallback  {

    private com.google.android.material.textfield.TextInputEditText output, errorCode;

    /**
     * section for general workflow
     */

    private LinearLayout llGeneralWorkflow;
    private Button tagVersion;

    /**
     * section for application handling
     */
    private LinearLayout llApplicationHandling;
    private Button applicationList, applicationCreate, applicationSelect;
    private com.google.android.material.textfield.TextInputEditText numberOfKeys, applicationId, applicationSelected;
    private byte[] selectedApplicationId = null;

    /**
     * section for standard file handling
     */

    private LinearLayout llStandardFile;
    private Button fileList, fileStandardCreate, fileStandardRead, authenticate;
    private com.google.android.material.textfield.TextInputEditText fileId, fileSize;

    // constants
    private final byte[] MASTER_APPLICATION_IDENTIFIER = new byte[3];
    private final byte[] DES_DEFAULT_KEY = new byte[8];
    private final byte APPLICATION_MASTER_KEY_SETTINGS = (byte) 0x0f; // amks
    private final byte KEY_NUMBER_RW = (byte) 0x00;

    // variables for NFC handling

    private NfcAdapter mNfcAdapter;
    private IsoDep isoDep;
    private byte[] tagIdByte;
    DESFireEV1 desfire;
    private DESFireAdapter desFireAdapter;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        Toolbar myToolbar = (Toolbar) findViewById(R.id.main_toolbar);
        setSupportActionBar(myToolbar);

        output = findViewById(R.id.etOutput);
        errorCode = findViewById(R.id.etErrorCode);

        // general workflow
        tagVersion = findViewById(R.id.btnGetTagVersion);


        // application handling
        llApplicationHandling = findViewById(R.id.llApplications);
        applicationList = findViewById(R.id.btnListApplications);
        applicationCreate = findViewById(R.id.btnCreateApplication);
        applicationSelect = findViewById(R.id.btnSelectApplication);
        applicationSelected = findViewById(R.id.etSelectedApplicationId);
        numberOfKeys = findViewById(R.id.etNumberOfKeys);
        applicationId = findViewById(R.id.etApplicationId);
        // standard file handling
        llStandardFile = findViewById(R.id.llStandardFile);
        fileList = findViewById(R.id.btnListFiles);
        authenticate = findViewById(R.id.btnAuthenticate);
        fileStandardCreate = findViewById(R.id.btnCreateStandardFile);
        fileStandardRead = findViewById(R.id.btnReadStandardFile);
        fileId = findViewById(R.id.etFileId);
        fileSize = findViewById(R.id.etFileSize);


        allLayoutsInvisible(); // default

        mNfcAdapter = NfcAdapter.getDefaultAdapter(this);

        /**
         * section for general workflow
         */

        tagVersion.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                // get the tag version data
                VersionInfo versionInfo;
                try {
                    versionInfo = desfire.getVersion();
                } catch (IOException e) {
                    //throw new RuntimeException(e);
                    writeToUiAppend(output, "IOException: " + e.getMessage());
                    e.printStackTrace();
                    return;
                } catch (Exception e) {
                    //throw new RuntimeException(e);
                    writeToUiAppend(output, "Exception: " + e.getMessage());
                    writeToUiAppend(output, "Stack: " + Arrays.toString(e.getStackTrace()));
                    e.printStackTrace();
                    return;
                }
                if (versionInfo == null) {
                    writeToUiAppend(output, "getVersionInfo is NULL");
                    return;
                }
                //String hardwareVersion = versionInfo.getHardwareVersion();
                //String softwareVersion = versionInfo.getSoftwareVersion();
                writeToUiAppend(output, "getVersionInfo: " + dumpVersionInfo(versionInfo));
                //writeToUiAppend(output, "getSoftwareVersion: " + softwareVersion);
                writeToUiAppend(output, "getVersion: " + desfire.getCode() + ":" + String.format("0x%02X", desfire.getCode()) + ":" + desfire.getCodeDesc());
            }
        });

        /**
         * section for applications
         */
        applicationList.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                // get application ids
                clearOutputFields();
                byte[] responseData = new byte[2];
                List<byte[]> applicationIdList = getApplicationIdsList(output, responseData);
                writeToUiAppend(errorCode, "getApplicationIdsList: " + Ev3.getErrorCode(responseData));
                if (applicationIdList != null) {
                    for (int i = 0; i < applicationIdList.size(); i++) {
                        writeToUiAppend(output, "entry " + i + " app id : " + Utils.bytesToHex(applicationIdList.get(i)));
                    }
                } else {
                    writeToUiAppend(errorCode, "getApplicationIdsList: returned NULL");
                }
            }
        });

        applicationCreate.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                // create a new application
                // get the input and sanity checks
                clearOutputFields();
                byte numberOfKeysByte = Byte.parseByte(numberOfKeys.getText().toString());
                byte[] applicationIdentifier = Utils.hexStringToByteArray(applicationId.getText().toString());
                Utils.reverseByteArrayInPlace(applicationIdentifier); // change to LSB
                if (applicationIdentifier == null) {
                    writeToUiAppend(errorCode, "you entered a wrong application ID");
                    return;
                }
                if (applicationIdentifier.length != 3) {
                    writeToUiAppend(errorCode, "you did not enter a 6 hex string application ID");
                    return;
                }
                try {
                    boolean success = desfire.createApplication(applicationIdentifier, APPLICATION_MASTER_KEY_SETTINGS, KeyType.DES, numberOfKeysByte);
                    writeToUiAppend(output, "createApplicationSuccess: " + success);
                    if (!success) {
                        writeToUiAppend(output, "createApplication NOT Success, aborted");
                        writeToUiAppend(output, "createApplication NOT Success: " + desfire.getCode() + ":" + String.format("0x%02X", desfire.getCode()) + ":" + desfire.getCodeDesc());
                        return;
                    }
                } catch (IOException e) {
                    //throw new RuntimeException(e);
                    writeToUiAppend(output, "IOException: " + e.getMessage());
                    e.printStackTrace();
                    return;
                } catch (Exception e) {
                    //throw new RuntimeException(e);
                    writeToUiAppend(output, "Exception: " + e.getMessage());
                    writeToUiAppend(output, "Stack: " + Arrays.toString(e.getStackTrace()));
                    e.printStackTrace();
                    return;
                }

            }
        });

        applicationSelect.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                // get all applications and show them in a listview for selection
                clearOutputFields();

                String[] applicationList;
                try {
                    // select PICC (is selected by default but...)
                    boolean success = desfire.selectApplication(MASTER_APPLICATION_IDENTIFIER);
                    writeToUiAppend(output, "selectMasterApplicationSuccess: " + success);
                    if (!success) {
                        writeToUiAppend(output, "selectMasterApplication NOT Success, aborted");
                        return;
                    }
                    List<DesfireApplicationId> desfireApplicationIdList = desfire.getApplicationsIds();

                    applicationList = new String[desfireApplicationIdList.size()];
                    for (int i = 0; i < desfireApplicationIdList.size(); i++) {
                        applicationList[i] = desfireApplicationIdList.get(i).getIdString();
                    }

                } catch (IOException e) {
                    //throw new RuntimeException(e);
                    writeToUiAppend(output, "IOException: " + e.getMessage());
                    e.printStackTrace();
                    return;
                } catch (Exception e) {
                    //throw new RuntimeException(e);
                    writeToUiAppend(output, "Exception: " + e.getMessage());
                    writeToUiAppend(output, "Stack: " + Arrays.toString(e.getStackTrace()));
                    e.printStackTrace();
                    return;
                }

                // setup the alert builder
                AlertDialog.Builder builder = new AlertDialog.Builder(view.getContext());
                builder.setTitle("Choose an application");

                // add a list
                //String[] animals = {"horse", "cow", "camel", "sheep", "goat"};
                //builder.setItems(animals, new DialogInterface.OnClickListener() {
                builder.setItems(applicationList, new DialogInterface.OnClickListener() {
                    @Override
                    public void onClick(DialogInterface dialog, int which) {
                        writeToUiAppend(output, "you  selected nr " + which + " = " + applicationList[which]);
                        selectedApplicationId = Utils.hexStringToByteArray(applicationList[which]);
                        applicationSelected.setText(applicationList[which]);
                    }
                });
                // create and show the alert dialog
                AlertDialog dialog = builder.create();
                dialog.show();
            }
        });

        /**
         * section  for standard files
         */

        authenticate.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                // authenticate with the default DES key
                clearOutputFields();
                try {
                    boolean success = desfire.authenticate(DES_DEFAULT_KEY, KEY_NUMBER_RW, KeyType.DES);
                    writeToUiAppend(output, "authenticateDesSuccess: " + success);
                    if (!success) {
                        writeToUiAppend(output, "authenticateDes NOT Success, aborted");
                        writeToUiAppend(output, "authenticateDes NOT Success: " + desfire.getCode() + ":" + String.format("0x%02X", desfire.getCode()) + ":" + desfire.getCodeDesc());
                        return;
                    }

                } catch (IOException e) {
                    //throw new RuntimeException(e);
                    writeToUiAppend(output, "IOException: " + e.getMessage());
                    e.printStackTrace();
                    return;
                } catch (Exception e) {
                    //throw new RuntimeException(e);
                    writeToUiAppend(output, "Exception: " + e.getMessage());
                    writeToUiAppend(output, "Stack: " + Arrays.toString(e.getStackTrace()));
                    e.printStackTrace();
                    return;
                }

                /*
                byte[] responseData = new byte[2];
                byte keyId = (byte) 0x00; // we authenticate with keyId 1
                boolean result = authenticateApplicationDes(output, keyId, DES_DEFAULT_KEY, true, responseData);
                writeToUiAppend(output, "result of authenticateApplicationDes: " + result);
                writeToUiAppend(errorCode, "authenticateApplicationDes: " + Ev3.getErrorCode(responseData));

                 */
            }
        });

        fileStandardCreate.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                // create a new standard file
                // get the input and sanity checks
                clearOutputFields();
                byte fileIdByte = Byte.parseByte(fileId.getText().toString());
                int fileSizeInt = Integer.parseInt(fileSize.getText().toString());
                if (fileIdByte > (byte) 0x0f) {
                    writeToUiAppend(errorCode, "you entered a wrong file ID");
                    return;
                }
                if (fileSizeInt != 32) {
                    writeToUiAppend(errorCode, "you entered a wrong file size, 32 bytes allowed only");
                    return;
                }
                try {
                    PayloadBuilder pb = new PayloadBuilder();
                    byte[] payloadStandardFile = pb.createStandardFile(fileIdByte, PayloadBuilder.CommunicationSetting.Plain,
                            0, 1, 2, 3, fileSizeInt);
                    boolean success = desfire.createStdDataFile(payloadStandardFile);
                    writeToUiAppend(output, "createStdDataFileSuccess: " + success);
                    if (!success) {
                        writeToUiAppend(output, "createStdDataFile NOT Success, aborted");
                        writeToUiAppend(output, "createStdDataFile NOT Success: " + desfire.getCode() + ":" + String.format("0x%02X", desfire.getCode()) + ":" + desfire.getCodeDesc());
                        return;
                    }
                } catch (IOException e) {
                    //throw new RuntimeException(e);
                    writeToUiAppend(output, "IOException: " + e.getMessage());
                    e.printStackTrace();
                    return;
                } catch (Exception e) {
                    //throw new RuntimeException(e);
                    writeToUiAppend(output, "Exception: " + e.getMessage());
                    writeToUiAppend(output, "Stack: " + Arrays.toString(e.getStackTrace()));
                    e.printStackTrace();
                    return;
                }
            }
        });

    }

    /**
     * section for general workflow
     */

    public String dumpVersionInfo(VersionInfo vi) {
        StringBuilder sb = new StringBuilder();
        sb.append("hardwareVendorId: ").append(vi.getHardwareVendorId()).append("\n");
        sb.append("hardwareType: ").append(vi.getHardwareType()).append("\n");
        sb.append("hardwareSubtype: ").append(vi.getHardwareSubtype()).append("\n");
        sb.append("hardwareVersionMajor: ").append(vi.getHardwareVersionMajor()).append("\n");
        sb.append("hardwareVersionMinor: ").append(vi.getHardwareVersionMinor()).append("\n");
        sb.append("hardwareStorageSize: ").append(vi.getHardwareStorageSize()).append("\n");

        sb.append("hardwareProtocol: ").append(vi.getHardwareProtocol()).append("\n");
        sb.append("softwareVendorId: ").append(vi.getSoftwareVendorId()).append("\n");
        sb.append("softwareType: ").append(vi.getSoftwareType()).append("\n");
        sb.append("softwareSubtype: ").append(vi.getSoftwareSubtype()).append("\n");

        sb.append("softwareVersionMajor: ").append(vi.getSoftwareVersionMajor()).append("\n");
        sb.append("softwareVersionMinor: ").append(vi.getSoftwareVersionMinor()).append("\n");
        sb.append("softwareStorageSize: ").append(vi.getSoftwareStorageSize()).append("\n");

        sb.append("softwareProtocol: ").append(vi.getSoftwareProtocol()).append("\n");
        sb.append("Uid: ").append(Utils.bytesToHex(vi.getUid())).append("\n");
        sb.append("batchNumber: ").append(Utils.bytesToHex(vi.getBatchNumber())).append("\n");
        sb.append("productionWeek: ").append(vi.getProductionWeek()).append("\n");
        sb.append("productionYear: ").append(vi.getProductionYear()).append("\n");
        sb.append("*** dump ended ***").append("\n");
        return sb.toString();
    }

    /**
     * section for authentication with DES
     */

    // if verbose = true all steps are printed out
    private boolean authenticateApplicationDes(TextView logTextView, byte keyId, byte[] key, boolean verbose, byte[] response) {
        try {
            writeToUiAppend(logTextView, "authenticateApplicationDes for keyId " + keyId + " and key " + Utils.bytesToHex(key));
            // do DES auth
            //String getChallengeCommand = "901a0000010000";
            //String getChallengeCommand = "9084000000"; // IsoGetChallenge
            byte[] getChallengeResponse = isoDep.transceive(wrapMessage((byte) 0x1a, new byte[]{(byte) (keyId & 0xFF)}));
            if (verbose)
                writeToUiAppend(logTextView, printData("getChallengeResponse", getChallengeResponse));
            // cf5e0ee09862d90391af
            // 91 af at the end shows there is more data

            byte[] challenge = Arrays.copyOf(getChallengeResponse, getChallengeResponse.length - 2);
            if (verbose) writeToUiAppend(logTextView, printData("challengeResponse", challenge));

            // Of course the rndA shall be a random number,
            // but we will use a constant number to make the example easier.
            //byte[] rndA = Utils.hexStringToByteArray("0001020304050607");
            byte[] rndA = Ev3.getRndADes();
            if (verbose) writeToUiAppend(logTextView, printData("rndA", rndA));

            // This is the default key for a blank DESFire card.
            // defaultKey = 8 byte array = [0x00, ..., 0x00]
            //byte[] defaultDESKey = Utils.hexStringToByteArray("0000000000000000");
            byte[] defaultDESKey = key.clone();
            byte[] IV = new byte[8];

            // Decrypt the challenge with default keybyte[] rndB = decrypt(challenge, defaultDESKey, IV);
            byte[] rndB = Ev3.decrypt(challenge, defaultDESKey, IV);
            if (verbose) writeToUiAppend(logTextView, printData("rndB", rndB));
            // Rotate left the rndB byte[] leftRotatedRndB = rotateLeft(rndB);
            byte[] leftRotatedRndB = Ev3.rotateLeft(rndB);
            if (verbose)
                writeToUiAppend(logTextView, printData("leftRotatedRndB", leftRotatedRndB));
            // Concatenate the RndA and rotated RndB byte[] rndA_rndB = concatenate(rndA, leftRotatedRndB);
            byte[] rndA_rndB = Ev3.concatenate(rndA, leftRotatedRndB);
            if (verbose) writeToUiAppend(logTextView, printData("rndA_rndB", rndA_rndB));

            // Encrypt the bytes of the last step to get the challenge answer byte[] challengeAnswer = encrypt(rndA_rndB, defaultDESKey, IV);
            IV = challenge;
            byte[] challengeAnswer = Ev3.encrypt(rndA_rndB, defaultDESKey, IV);
            if (verbose)
                writeToUiAppend(logTextView, printData("challengeAnswer", challengeAnswer));

            IV = Arrays.copyOfRange(challengeAnswer, 8, 16);
                /*
                    Build and send APDU with the answer. Basically wrap the challenge answer in the APDU.
                    The total size of apdu (for this scenario) is 22 bytes:
                    > 0x90 0xAF 0x00 0x00 0x10 [16 bytes challenge answer] 0x00
                */
            byte[] challengeAnswerAPDU = new byte[22];
            challengeAnswerAPDU[0] = (byte) 0x90; // CLS
            challengeAnswerAPDU[1] = (byte) 0xAF; // INS
            challengeAnswerAPDU[2] = (byte) 0x00; // p1
            challengeAnswerAPDU[3] = (byte) 0x00; // p2
            challengeAnswerAPDU[4] = (byte) 0x10; // data length: 16 bytes
            challengeAnswerAPDU[challengeAnswerAPDU.length - 1] = (byte) 0x00;
            System.arraycopy(challengeAnswer, 0, challengeAnswerAPDU, 5, challengeAnswer.length);
            if (verbose)
                writeToUiAppend(logTextView, printData("challengeAnswerAPDU", challengeAnswerAPDU));

            /*
             * Sending the APDU containing the challenge answer.
             * It is expected to be return 10 bytes [rndA from the Card] + 9100
             */
            byte[] challengeAnswerResponse = isoDep.transceive(challengeAnswerAPDU);
            // response = channel.transmit(new CommandAPDU(challengeAnswerAPDU));
            if (verbose)
                writeToUiAppend(logTextView, printData("challengeAnswerResponse", challengeAnswerResponse));
            byte[] challengeAnswerResp = Arrays.copyOf(challengeAnswerResponse, getChallengeResponse.length - 2);
            if (verbose)
                writeToUiAppend(logTextView, printData("challengeAnswerResp", challengeAnswerResp));

            /*
             * At this point, the challenge was processed by the card. The card decrypted the
             * rndA rotated it and sent it back.
             * Now we need to check if the RndA sent by the Card is valid.
             */// encrypted rndA from Card, returned in the last step byte[] encryptedRndAFromCard = response.getData();

            // Decrypt the rnd received from the Card.byte[] rotatedRndAFromCard = decrypt(encryptedRndAFromCard, defaultDESKey, IV);
            //byte[] rotatedRndAFromCard = decrypt(encryptedRndAFromCard, defaultDESKey, IV);
            byte[] rotatedRndAFromCard = Ev3.decrypt(challengeAnswerResp, defaultDESKey, IV);
            if (verbose)
                writeToUiAppend(logTextView, printData("rotatedRndAFromCard", rotatedRndAFromCard));

            // As the card rotated left the rndA,// we shall un-rotate the bytes in order to get compare it to our original rndA.byte[] rndAFromCard = rotateRight(rotatedRndAFromCard);
            byte[] rndAFromCard = Ev3.rotateRight(rotatedRndAFromCard);
            if (verbose) writeToUiAppend(logTextView, printData("rndAFromCard", rndAFromCard));
            writeToUiAppend(logTextView, "********** AUTH RESULT **********");
            //System.arraycopy(createApplicationResponse, 0, response, 0, createApplicationResponse.length);
            if (Arrays.equals(rndA, rndAFromCard)) {
                writeToUiAppend(logTextView, "Authenticated");
                response = new byte[]{(byte) 0x91, (byte) 0x00};
                return true;
            } else {
                writeToUiAppend(logTextView, "Authentication failed");
                response = new byte[]{(byte) 0x91, (byte) 0xFF};
                return false;
                //System.err.println(" ### Authentication failed. ### ");
                //log("rndA:" + toHexString(rndA) + ", rndA from Card: " + toHexString(rndAFromCard));
            }
            //writeToUiAppend(logTextView, "********** AUTH RESULT END **********");
            //return false;
        } catch (Exception e) {
            //throw new RuntimeException(e);
            writeToUiAppend(logTextView, "authenticateApplicationDes transceive failed: " + e.getMessage());
            writeToUiAppend(logTextView, "authenticateApplicationDes transceive failed: " + Arrays.toString(e.getStackTrace()));
        }
        //System.arraycopy(createApplicationResponse, 0, response, 0, createApplicationResponse.length);
        return false;
    }

    /**
     * section for standard file handling
     */

    private boolean createStandardFile(TextView logTextView, byte fileNumber, int fileSize, byte[] response) {
        // we create a standard file within the selected application
        byte createStandardFileCommand = (byte) 0xcd;
        // CD | File No | Comms setting byte | Access rights (2 bytes) | File size (3 bytes)
        byte commSettingsByte = 0; // plain communication without any encryption
                /*
                M0775031 DESFIRE
                Plain Communication = 0;
                Plain communication secured by DES/3DES MACing = 1;
                Fully DES/3DES enciphered communication = 3;
                 */
        //byte[] accessRights = new byte[]{(byte) 0xee, (byte) 0xee}; // should mean plain/free access without any keys
                /*
                There are four different Access Rights (2 bytes for each file) stored for each file within
                each application:
                - Read Access
                - Write Access
                - Read&Write Access
                - ChangeAccessRights
                 */
        // here we are using key 2 for read and key3 for write access access, key0 has read&write access and key1 has change rights !
        byte accessRightsRwCar = (byte) 0x01; // Read&Write Access & ChangeAccessRights
        byte accessRightsRW = (byte) 0x23; // Read Access & Write Access // read with key 1, write with key 2
        byte[] fileSizeArray = Utils.intTo3ByteArrayInversed(fileSize); // lsb
        byte[] createStandardFileParameters = new byte[7];
        createStandardFileParameters[0] = fileNumber;
        createStandardFileParameters[1] = commSettingsByte;
        createStandardFileParameters[2] = accessRightsRwCar;
        createStandardFileParameters[3] = accessRightsRW;
        System.arraycopy(fileSizeArray, 0, createStandardFileParameters, 4, 3);
        writeToUiAppend(logTextView, printData("createStandardFileParameters", createStandardFileParameters));
        byte[] createStandardFileResponse = new byte[0];
        try {
            createStandardFileResponse = isoDep.transceive(wrapMessage(createStandardFileCommand, createStandardFileParameters));
        } catch (Exception e) {
            //throw new RuntimeException(e);
            writeToUiAppend(logTextView, "transceive failed: " + e.getMessage());
            return false;
        }
        System.arraycopy(returnStatusBytes(createStandardFileResponse), 0, response, 0, 2);
        writeToUiAppend(logTextView, printData("createStandardFileResponse", createStandardFileResponse));
        if (checkDuplicateError(createStandardFileResponse)) {
            writeToUiAppend(logTextView, "the file was not created as it already exists, proceed");
            return true;
        }
        if (checkResponse(createStandardFileResponse)) {
            return true;
        } else {
            return false;
        }
    }

    /**
     * section for application handling
     */

    private List<byte[]> getApplicationIdsList(TextView logTextView, byte[] response) {
        // get application ids
        List<byte[]> applicationIdList = new ArrayList<>();
        byte getApplicationIdsCommand = (byte) 0x6a;
        byte[] getApplicationIdsResponse = new byte[0];
        try {
            getApplicationIdsResponse = isoDep.transceive(wrapMessage(getApplicationIdsCommand, null));
        } catch (Exception e) {
            //throw new RuntimeException(e);
            writeToUiAppend(logTextView, "transceive failed: " + e.getMessage());
            return null;
        }
        writeToUiAppend(logTextView, printData("getApplicationIdsResponse", getApplicationIdsResponse));
        // getApplicationIdsResponse length: 2 data: 9100 = no applications on card
        // getApplicationIdsResponse length: 5 data: a1a2a3 9100
        // there might be more application on the card that fit into one frame:
        // getApplicationIdsResponse length: 5 data: a1a2a3 91AF
        // AF at the end is indicating more data

        // check that result if 0x9100 (success) or 0x91AF (success but more data)
        if ((!checkResponse(getApplicationIdsResponse)) && (!checkResponseMoreData(getApplicationIdsResponse))) {
            // something got wrong (e.g. missing authentication ?)
            writeToUiAppend(logTextView, "there was an unexpected response");
            return null;
        }
        // if the read result is success 9100 we return the data received so far
        if (checkResponse(getApplicationIdsResponse)) {
            System.arraycopy(returnStatusBytes(getApplicationIdsResponse), 0, response, 0, 2);
            byte[] applicationListBytes = Arrays.copyOf(getApplicationIdsResponse, getApplicationIdsResponse.length - 2);
            applicationIdList = divideArray(applicationListBytes, 3);
            return applicationIdList;
        }
        if (checkResponseMoreData(getApplicationIdsResponse)) {
            writeToUiAppend(logTextView, "getApplicationIdsList: we are asked to grab more data from the card");
            byte[] applicationListBytes = Arrays.copyOf(getApplicationIdsResponse, getApplicationIdsResponse.length - 2);
            applicationIdList = divideArray(applicationListBytes, 3);
            byte getMoreDataCommand = (byte) 0xaf;
            boolean readMoreData = true;
            try {
                while (readMoreData) {
                    try {
                        getApplicationIdsResponse = isoDep.transceive(wrapMessage(getMoreDataCommand, null));
                    } catch (Exception e) {
                        //throw new RuntimeException(e);
                        writeToUiAppend(logTextView, "transceive failed: " + e.getMessage());
                        return null;
                    }
                    writeToUiAppend(logTextView, printData("getApplicationIdsResponse", getApplicationIdsResponse));
                    if (checkResponse(getApplicationIdsResponse)) {
                        // now we have received all data
                        List<byte[]> applicationIdListTemp = new ArrayList<>();
                        System.arraycopy(returnStatusBytes(getApplicationIdsResponse), 0, response, 0, 2);
                        applicationListBytes = Arrays.copyOf(getApplicationIdsResponse, getApplicationIdsResponse.length - 2);
                        applicationIdListTemp = divideArray(applicationListBytes, 3);
                        readMoreData = false; // end the loop
                        applicationIdList.addAll(applicationIdListTemp);
                        return applicationIdList;
                    }
                    if (checkResponseMoreData(getApplicationIdsResponse)) {
                        // some more data will follow, store temp data
                        List<byte[]> applicationIdListTemp = new ArrayList<>();
                        applicationListBytes = Arrays.copyOf(getApplicationIdsResponse, getApplicationIdsResponse.length - 2);
                        applicationIdListTemp = divideArray(applicationListBytes, 3);
                        applicationIdList.addAll(applicationIdListTemp);
                        readMoreData = true;
                    }
                } // while (readMoreData) {
            } catch (Exception e) {
                writeToUiAppend(logTextView, "Exception failure: " + e.getMessage());
            } // try
        }
        return null;
    }

    private boolean createApplicationPlainDes(TextView logTextView, byte[] applicationIdentifier, byte numberOfKeys, byte[] response) {
        if (logTextView == null) return false;
        if (applicationIdentifier == null) return false;
        if (applicationIdentifier.length != 3) return false;

        // create an application
        writeToUiAppend(logTextView, "create the application " + Utils.bytesToHex(applicationIdentifier));
        byte createApplicationCommand = (byte) 0xca;
        byte applicationMasterKeySettings = (byte) 0x0f;
        byte[] createApplicationParameters = new byte[5];
        System.arraycopy(applicationIdentifier, 0, createApplicationParameters, 0, applicationIdentifier.length);
        createApplicationParameters[3] = applicationMasterKeySettings;
        createApplicationParameters[4] = numberOfKeys;
        writeToUiAppend(logTextView, printData("createApplicationParameters", createApplicationParameters));
        byte[] createApplicationResponse = new byte[0];
        try {
            createApplicationResponse = isoDep.transceive(wrapMessage(createApplicationCommand, createApplicationParameters));
            writeToUiAppend(logTextView, printData("createApplicationResponse", createApplicationResponse));
            System.arraycopy(returnStatusBytes(createApplicationResponse), 0, response, 0, 2);
            //System.arraycopy(createApplicationResponse, 0, response, 0, createApplicationResponse.length);
            if (checkResponse(createApplicationResponse)) {
                return true;
            } else {
                return false;
            }
        } catch (Exception e) {
            //throw new RuntimeException(e);
            writeToUiAppend(logTextView, "createApplicationAes transceive failed: " + e.getMessage());
            return false;
        }
    }

    /**
     * section for command and response handling
     */

    private byte[] wrapMessage(byte command, byte[] parameters) throws Exception {
        ByteArrayOutputStream stream = new ByteArrayOutputStream();
        stream.write((byte) 0x90);
        stream.write(command);
        stream.write((byte) 0x00);
        stream.write((byte) 0x00);
        if (parameters != null) {
            stream.write((byte) parameters.length);
            stream.write(parameters);
        }
        stream.write((byte) 0x00);
        return stream.toByteArray();
    }

    private byte[] returnStatusBytes(byte[] data) {
        return Arrays.copyOfRange(data, (data.length - 2), data.length);
    }

    /**
     * checks if the response has an 0x'9100' at the end means success
     * and the method returns the data without 0x'9100' at the end
     * if any other trailing bytes show up the method returns false
     *
     * @param data
     * @return
     */
    private boolean checkResponse(@NonNull byte[] data) {
        // simple sanity check
        if (data.length < 2) {
            return false;
        } // not ok
        int status = ((0xff & data[data.length - 2]) << 8) | (0xff & data[data.length - 1]);
        if (status == 0x9100) {
            return true;
        } else {
            return false;
        }
    }

    /**
     * checks if the response has an 0x'91AF' at the end means success
     * but there are more data frames available
     * if any other trailing bytes show up the method returns false
     *
     * @param data
     * @return
     */
    private boolean checkResponseMoreData(@NonNull byte[] data) {
        // simple sanity check
        if (data.length < 2) {
            return false;
        } // not ok
        int status = ((0xff & data[data.length - 2]) << 8) | (0xff & data[data.length - 1]);
        if (status == 0x91AF) {
            return true;
        } else {
            return false;
        }
    }

    /**
     * checks if the response has an 0x'91de' at the end means the data
     * element is already existing
     * if any other trailing bytes show up the method returns false
     *
     * @param data
     * @return true is code is 91DE
     */
    private boolean checkDuplicateError(@NonNull byte[] data) {
        // simple sanity check
        if (data.length < 2) {
            return false;
        } // not ok
        int status = ((0xff & data[data.length - 2]) << 8) | (0xff & data[data.length - 1]);
        if (status != 0x91DE) {
            return false;
        } else {
            return true;
        }
    }

    /**
     * splits a byte array in chunks
     *
     * @param source
     * @param chunksize
     * @return a List<byte[]> with sets of chunksize
     */
    private static List<byte[]> divideArray(byte[] source, int chunksize) {
        List<byte[]> result = new ArrayList<byte[]>();
        int start = 0;
        while (start < source.length) {
            int end = Math.min(source.length, start + chunksize);
            result.add(Arrays.copyOfRange(source, start, end));
            start += chunksize;
        }
        return result;
    }

    /**
     * section for NFC handling
     */

    // This method is run in another thread when a card is discovered
    // !!!! This method cannot cannot direct interact with the UI Thread
    // Use `runOnUiThread` method to change the UI from this method
    @Override
    public void onTagDiscovered(Tag tag) {

        writeToUiAppend(output, "NFC tag discovered");
        isoDep = null;
        try {
            isoDep = IsoDep.get(tag);
            if (isoDep != null) {
                /*
                runOnUiThread(() -> {
                    Toast.makeText(getApplicationContext(),
                            "NFC tag is IsoDep compatible",
                            Toast.LENGTH_SHORT).show();
                });
                 */

                // Make a Sound
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                    ((Vibrator) getSystemService(VIBRATOR_SERVICE)).vibrate(VibrationEffect.createOneShot(150, 10));
                } else {
                    Vibrator v = (Vibrator) getSystemService(Context.VIBRATOR_SERVICE);
                    v.vibrate(200);
                }

                runOnUiThread(() -> {
                    output.setText("");
                    //output.setBackgroundColor(getResources().getColor(R.color.white));
                });
                isoDep.connect();
                // get tag ID
                tagIdByte = tag.getId();
                writeToUiAppend(output, "tag id: " + Utils.bytesToHex(tagIdByte));
                writeToUiAppend(output, "NFC tag connected");
                IsoDepWrapper isoDepWrapper = new DefaultIsoDepWrapper(isoDep);
                desFireAdapter = new DESFireAdapter(isoDepWrapper, true);
                desfire = new DESFireEV1();
                desfire.setAdapter(desFireAdapter);

            }

        } catch (IOException e) {
            writeToUiAppend(output, "ERROR: IOException " + e.getMessage());
            e.printStackTrace();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }

    }

    @Override
    protected void onResume() {
        super.onResume();

        if (mNfcAdapter != null) {

            Bundle options = new Bundle();
            // Work around for some broken Nfc firmware implementations that poll the card too fast
            options.putInt(NfcAdapter.EXTRA_READER_PRESENCE_CHECK_DELAY, 250);

            // Enable ReaderMode for all types of card and disable platform sounds
            // the option NfcAdapter.FLAG_READER_SKIP_NDEF_CHECK is NOT set
            // to get the data of the tag afer reading
            mNfcAdapter.enableReaderMode(this,
                    this,
                    NfcAdapter.FLAG_READER_NFC_A |
                            NfcAdapter.FLAG_READER_NFC_B |
                            NfcAdapter.FLAG_READER_NFC_F |
                            NfcAdapter.FLAG_READER_NFC_V |
                            NfcAdapter.FLAG_READER_NFC_BARCODE |
                            NfcAdapter.FLAG_READER_NO_PLATFORM_SOUNDS,
                    options);
        }
    }

    @Override
    protected void onPause() {
        super.onPause();
        if (mNfcAdapter != null)
            mNfcAdapter.disableReaderMode(this);
    }

    /**
     * section for layout handling
     */
    private void allLayoutsInvisible() {
        llApplicationHandling.setVisibility(View.GONE);
        llStandardFile.setVisibility(View.GONE);
    }

    /**
     * section for UI handling
     */

    private void writeToUiAppend(TextView textView, String message) {
        runOnUiThread(() -> {
            String newString = message + "\n" + textView.getText().toString();
            textView.setText(newString);
            System.out.println(message);
        });
    }

    public String printData(String dataName, byte[] data) {
        int dataLength;
        String dataString = "";
        if (data == null) {
            dataLength = 0;
            dataString = "IS NULL";
        } else {
            dataLength = data.length;
            dataString = Utils.bytesToHex(data);
        }
        StringBuilder sb = new StringBuilder();
        sb
                .append(dataName)
                .append(" length: ")
                .append(dataLength)
                .append(" data: ")
                .append(dataString);
        return sb.toString();
    }

    private void clearOutputFields() {
        output.setText("");
        errorCode.setText("");
    }

    /**
     * section for options menu
     */

    @Override
    public boolean onCreateOptionsMenu(Menu menu) {
        getMenuInflater().inflate(R.menu.menu_activity_main, menu);

        MenuItem mApplications = menu.findItem(R.id.action_applications);
        mApplications.setOnMenuItemClickListener(new MenuItem.OnMenuItemClickListener() {
            @Override
            public boolean onMenuItemClick(MenuItem item) {
                allLayoutsInvisible();
                llApplicationHandling.setVisibility(View.VISIBLE);
                return false;
            }
        });

        MenuItem mStandardFile = menu.findItem(R.id.action_standard_file);
        mStandardFile.setOnMenuItemClickListener(new MenuItem.OnMenuItemClickListener() {
            @Override
            public boolean onMenuItemClick(MenuItem item) {
                allLayoutsInvisible();
                llStandardFile.setVisibility(View.VISIBLE);
                return false;
            }
        });

        return super.onCreateOptionsMenu(menu);
    }

}