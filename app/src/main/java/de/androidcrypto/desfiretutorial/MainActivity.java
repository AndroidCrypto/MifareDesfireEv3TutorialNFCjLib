package de.androidcrypto.desfiretutorial;

import android.content.Context;
import android.content.DialogInterface;
import android.content.Intent;
import android.content.res.ColorStateList;
import android.graphics.Color;
import android.nfc.NfcAdapter;
import android.nfc.Tag;
import android.nfc.tech.IsoDep;
import android.os.Build;
import android.os.Bundle;
import android.os.VibrationEffect;
import android.os.Vibrator;
import android.text.TextUtils;
import android.util.Log;
import android.view.LayoutInflater;
import android.view.Menu;
import android.view.MenuItem;
import android.view.View;
import android.view.WindowManager;
import android.webkit.WebView;
import android.widget.Button;
import android.widget.CheckBox;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.RadioButton;
import android.widget.ScrollView;
import android.widget.TextView;

import androidx.appcompat.app.AlertDialog;
import androidx.appcompat.app.AppCompatActivity;
import androidx.appcompat.widget.Toolbar;

import com.github.skjolber.desfire.ev1.model.DesfireApplicationId;
import com.github.skjolber.desfire.ev1.model.DesfireApplicationKeySettings;
import com.github.skjolber.desfire.ev1.model.VersionInfo;
import com.github.skjolber.desfire.ev1.model.command.DefaultIsoDepWrapper;
import com.github.skjolber.desfire.ev1.model.command.IsoDepWrapper;
import com.github.skjolber.desfire.ev1.model.file.DesfireFile;
import com.github.skjolber.desfire.ev1.model.file.DesfireFileCommunicationSettings;
import com.github.skjolber.desfire.ev1.model.file.StandardDesfireFile;
import com.github.skjolber.desfire.ev1.model.key.DesfireKeyType;
import com.google.android.material.textfield.TextInputLayout;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import nfcjlib.core.DESFireAdapter;
import nfcjlib.core.DESFireEV1;
import nfcjlib.core.KeyType;

public class MainActivity extends AppCompatActivity implements NfcAdapter.ReaderCallback {

    private static final String TAG = MainActivity.class.getSimpleName();

    private com.google.android.material.textfield.TextInputEditText output, errorCode;
    private com.google.android.material.textfield.TextInputLayout errorCodeLayout;
    private ScrollView scrollView;
    private TextView noTagInformation;

    /**
     * section for general workflow
     */

    private LinearLayout llGeneralWorkflow;
    private Button tagVersion, keySettings, freeMemory, formatPicc, selectMasterApplication;
    private Button getFileSettingsDesfire;
    private Button getCardUid; // get cardUID * encrypted

    /**
     * section for application handling
     */
    private LinearLayout llApplicationHandling;
    private Button applicationCreate, applicationSelect, applicationDelete;
    private com.google.android.material.textfield.TextInputEditText numberOfKeys, applicationId, applicationSelected;
    private RadioButton rbApplicationKeyTypeDes, rbApplicationKeyTypeAes;
    private byte[] selectedApplicationId = null;

    /**
     * section for files handling
     */

    private LinearLayout llFiles;

    private Button fileSelect, fileDelete, getFileSettings;

    private com.google.android.material.textfield.TextInputEditText fileSelected;
    private String selectedFileId = "";
    private int selectedFileIdInt = -1;
    private int selectedFileSize;

    /**
     * section for standard & backup file handling
     */

    private LinearLayout llStandardFile;
    private Button fileStandardCreate, fileStandardWrite, fileStandardRead;
    private com.google.android.material.textfield.TextInputEditText fileSize, fileData;
    private RadioButton rbStandardFile;
    private com.shawnlin.numberpicker.NumberPicker npStandardFileId;
    RadioButton rbFileStandardPlainCommunication, rbFileStandardMacedCommunication, rbFileStandardEncryptedCommunication;

    /**
     * section for authentication
     */
    private LinearLayout llAuthentication2;
    private Button authDM0D, authD0D, authD1D, authD2D, authD3D, authD4D; // auth with default DES keys
    private Button authDM0A, authD0A, authD1A, authD2A, authD3A, authD4A; // auth with default AES keys

    // constants
    private String lineSeparator = "----------";
    private final byte[] MASTER_APPLICATION_IDENTIFIER = new byte[3]; // '00 00 00'
    private final byte[] MASTER_APPLICATION_KEY_DES_DEFAULT = Utils.hexStringToByteArray("0000000000000000");
    private final byte[] MASTER_APPLICATION_KEY_AES_DEFAULT = Utils.hexStringToByteArray("00000000000000000000000000000000");
    private final byte MASTER_APPLICATION_KEY_NUMBER = (byte) 0x00;
    private final byte[] APPLICATION_KEY_MASTER_DES_DEFAULT = Utils.hexStringToByteArray("0000000000000000"); // default DES key with 8 nulls
    private final byte[] APPLICATION_KEY_MASTER_AES_DEFAULT = Utils.hexStringToByteArray("00000000000000000000000000000000"); // default AES key with 16 nulls
    private final byte APPLICATION_KEY_MASTER_NUMBER = (byte) 0x00;
    private final byte APPLICATION_MASTER_KEY_SETTINGS = (byte) 0x0f; // amks
    private final byte[] APPLICATION_KEY_RW_DES_DEFAULT = Utils.hexStringToByteArray("0000000000000000"); // default DES key with 8 nulls
    private final byte[] APPLICATION_KEY_RW_AES_DEFAULT = Utils.hexStringToByteArray("00000000000000000000000000000000");
    private final byte APPLICATION_KEY_RW_NUMBER = (byte) 0x01;
    private final byte[] APPLICATION_KEY_CAR_DES_DEFAULT = Utils.hexStringToByteArray("0000000000000000"); // default DES key with 8 nulls
    private final byte[] APPLICATION_KEY_CAR_AES_DEFAULT = Utils.hexStringToByteArray("00000000000000000000000000000000");
    private final byte APPLICATION_KEY_CAR_NUMBER = (byte) 0x02;

    private final byte[] APPLICATION_KEY_R_DES_DEFAULT = Utils.hexStringToByteArray("0000000000000000"); // default DES key with 8 nulls
    private final byte[] APPLICATION_KEY_R_AES_DEFAULT = Utils.hexStringToByteArray("00000000000000000000000000000000");
    private final byte APPLICATION_KEY_R_NUMBER = (byte) 0x03;

    private final byte[] APPLICATION_KEY_W_DES_DEFAULT = Utils.hexStringToByteArray("0000000000000000"); // default DES key with 8 nulls
    private final byte[] APPLICATION_KEY_W_AES_DEFAULT = Utils.hexStringToByteArray("00000000000000000000000000000000");
    private final byte APPLICATION_KEY_W_NUMBER = (byte) 0x04;


    private final int COLOR_GREEN = Color.rgb(0, 255, 0);
    private final int COLOR_RED = Color.rgb(255, 0, 0);

    // variables for NFC handling

    private NfcAdapter mNfcAdapter;
    private IsoDep isoDep;
    private byte[] tagIdByte;
    private DESFireEV1 desfire;
    private DESFireAdapter desFireAdapter;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        Toolbar myToolbar = (Toolbar) findViewById(R.id.main_toolbar);
        setSupportActionBar(myToolbar);

        output = findViewById(R.id.etOutput);
        errorCode = findViewById(R.id.etErrorCode);
        errorCodeLayout = findViewById(R.id.etErrorCodeLayout);
        scrollView = findViewById(R.id.svScrollView);
        noTagInformation = findViewById(R.id.tvInformationNoTag);

        //standardWriteReadDefaultKeys = findViewById(R.id.btnStandardFileWriteReadDefaultKeys);
        getFileSettingsDesfire = findViewById(R.id.btnGetFileSettings);

        // general workflow
        llGeneralWorkflow = findViewById(R.id.llGeneral);
        tagVersion = findViewById(R.id.btnGetTagVersion);
        keySettings = findViewById(R.id.btnGetKeySettings);
        freeMemory = findViewById(R.id.btnGetFreeMemory);
        formatPicc = findViewById(R.id.btnFormatPicc);
        selectMasterApplication = findViewById(R.id.btnSelectMasterApplication);
        getCardUid = findViewById(R.id.btnGetCardUid);

        // application handling
        llApplicationHandling = findViewById(R.id.llApplications);
        applicationCreate = findViewById(R.id.btnCreateApplication);
        applicationSelect = findViewById(R.id.btnSelectApplication);
        applicationDelete = findViewById(R.id.btnDeleteApplication);
        applicationSelected = findViewById(R.id.etSelectedApplicationId);
        numberOfKeys = findViewById(R.id.etNumberOfKeys);
        applicationId = findViewById(R.id.etApplicationId);
        rbApplicationKeyTypeDes = findViewById(R.id.rbApplicationKeyTypeDes);
        rbApplicationKeyTypeAes = findViewById(R.id.rbApplicationKeyTypeAes);

        // files handling
        llFiles = findViewById(R.id.llFiles);
        fileSelect = findViewById(R.id.btnSelectFile);
        fileDelete = findViewById(R.id.btnDeleteFile);
        getFileSettings = findViewById(R.id.btnGetFileSettings);

        // standard & backup file handling
        llStandardFile = findViewById(R.id.llStandardFile);
        fileStandardCreate = findViewById(R.id.btnCreateStandardFile);
        fileStandardWrite = findViewById(R.id.btnWriteStandardFile);
        fileStandardRead = findViewById(R.id.btnReadStandardFile);
        npStandardFileId = findViewById(R.id.npStandardFileId);
        rbStandardFile = findViewById(R.id.rbStandardFile);
        rbFileStandardPlainCommunication = findViewById(R.id.rbFileStandardPlainCommunication);
        rbFileStandardMacedCommunication = findViewById(R.id.rbFileStandardMacedCommunication);
        rbFileStandardEncryptedCommunication = findViewById(R.id.rbFileStandardEncryptedCommunication);
        fileSize = findViewById(R.id.etFileStandardSize);
        fileData = findViewById(R.id.etFileStandardData);
        fileSelected = findViewById(R.id.etSelectedFileId);

        // authentication handling DES default keys
        llAuthentication2 = findViewById(R.id.llAuthentication2);
        authDM0D = findViewById(R.id.btnAuthDM0D);
        authD0D = findViewById(R.id.btnAuthD0D);
        authD1D = findViewById(R.id.btnAuthD1D);
        authD2D = findViewById(R.id.btnAuthD2D);
        authD3D = findViewById(R.id.btnAuthD3D);
        authD4D = findViewById(R.id.btnAuthD4D);

        // authentication handling AES default keys
        authDM0A = findViewById(R.id.btnAuthDM0A);
        authD0A = findViewById(R.id.btnAuthD0A);
        authD1A = findViewById(R.id.btnAuthD1A);
        authD2A = findViewById(R.id.btnAuthD2A);
        authD3A = findViewById(R.id.btnAuthD3A);
        authD4A = findViewById(R.id.btnAuthD4A);

        //allLayoutsInvisible(); // default

        // hide soft keyboard from showing up on startup
        getWindow().setSoftInputMode(WindowManager.LayoutParams.SOFT_INPUT_STATE_ALWAYS_HIDDEN);

        mNfcAdapter = NfcAdapter.getDefaultAdapter(this);

        allLayoutsVisibility(false);

        /**
         * section for general workflow
         */

        tagVersion.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                // get the tag version data
                clearOutputFields();
                VersionInfo versionInfo;
                try {
                    versionInfo = desfire.getVersion();
                } catch (IOException e) {
                    //throw new RuntimeException(e);
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, "IOException: " + e.getMessage(), COLOR_RED);
                    writeToUiAppend(errorCode, "Stack: " + Arrays.toString(e.getStackTrace()));
                    //writeToUiAppend(output, "IOException: " + e.getMessage());
                    e.printStackTrace();
                    scrollView.smoothScrollTo(0, 0);
                    return;
                } catch (Exception e) {
                    //throw new RuntimeException(e);
                    //writeToUiAppend(output, "Exception: " + e.getMessage());
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, "Exception: " + e.getMessage(), COLOR_RED);
                    writeToUiAppend(errorCode, "Stack: " + Arrays.toString(e.getStackTrace()));
                    e.printStackTrace();
                    scrollView.smoothScrollTo(0, 0);
                    return;
                }
                if (versionInfo == null) {
                    writeToUiAppend(output, "getVersionInfo is NULL");
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, "getVersionInfo is NULL", COLOR_RED);
                    scrollView.smoothScrollTo(0, 0);
                    return;
                }
                writeToUiAppend(output, "getVersionInfo: " + versionInfo.dump());
                writeToUiAppendBorderColor(errorCode, errorCodeLayout, "success in getting tagVersion", COLOR_GREEN);
                writeToUiAppend(errorCode, "getVersion: " + desfire.getCode() + ":" + String.format("0x%02X", desfire.getCode()) + ":" + desfire.getCodeDesc());
                scrollView.smoothScrollTo(0, 0);
            }
        });

        keySettings.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                // get the key settings for the selected application
                clearOutputFields();
                writeToUiAppend(output, "get key settings for selected application: " + Utils.printData("AID", selectedApplicationId));
                writeToUiAppend(output, "if AID == NULL it is for the Master Application 00 00 00");
                DesfireApplicationKeySettings keySettings;
                try {
                    keySettings = desfire.getKeySettings();

                } catch (IOException e) {
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, "IOException: " + e.getMessage(), COLOR_RED);
                    writeToUiAppend(errorCode, "Stack: " + Arrays.toString(e.getStackTrace()));
                    //writeToUiAppend(output, "IOException: " + e.getMessage());
                    e.printStackTrace();
                    scrollView.smoothScrollTo(0, 0);
                    return;
                }
                if (keySettings == null) {
                    writeToUiAppend(output, "could not get the key settings (missing authentication ?)");
                    scrollView.smoothScrollTo(0, 0);
                    return;
                }
                DialogInterface.OnClickListener dialogClickListener = new DialogInterface.OnClickListener() {
                    @Override
                    public void onClick(DialogInterface dialog, int which) {

                        switch (which) {

                            case DialogInterface.BUTTON_POSITIVE:
                                //Yes button clicked
                                boolean success;
                                break;
                            case DialogInterface.BUTTON_NEGATIVE:
                                //No button clicked
                                // nothing to do
                                break;
                        }
                    }
                };

                AlertDialog.Builder builder = new AlertDialog.Builder(MainActivity.this);

                LayoutInflater inflater = MainActivity.this.getLayoutInflater();
                View dialogView = inflater.inflate(R.layout.application_key_settings, null);
                builder.setView(dialogView);

                CheckBox cbBit0MasterKeyIsChangeable = dialogView.findViewById(R.id.cbAksBit0MasterKeyIsChangeable);
                CheckBox cbBit1MasterKeyAuthenticationNeededDirListing = dialogView.findViewById(R.id.cbAksBit1MasterKeyAuthenticationNeededDirListing);
                CheckBox cbBit2MasterKeyAuthenticationNeededCreateDelete = dialogView.findViewById(R.id.cbAksBit2MasterKeyAuthenticationNeededCreateDelete);
                CheckBox cbBit3MasterKeySettingsChangeAllowed = dialogView.findViewById(R.id.cbAksBit3MasterKeySettingsChangeAllowed);
                EditText maximumNumberOfKeys = dialogView.findViewById(R.id.etAksMaximumNumberOfKeys);
                EditText keySettingsCarKey = dialogView.findViewById(R.id.etAksKeySettingsCarKey);
                // set data from key settings
                cbBit0MasterKeyIsChangeable.setChecked(keySettings.isCanChangeMasterKey());
                cbBit1MasterKeyAuthenticationNeededDirListing.setChecked(!keySettings.isFreeDirectoryAccess());
                cbBit2MasterKeyAuthenticationNeededCreateDelete.setChecked(!keySettings.isFreeCreateAndDelete());
                cbBit3MasterKeySettingsChangeAllowed.setChecked(keySettings.isConfigurationChangable());
                DesfireKeyType keyType = keySettings.getType();
                maximumNumberOfKeys.setText(keySettings.getMaxKeys() + " of type " + keyType.toString());
                // get the following data only if it is not the Master Application
                String accessTypeDescription = "";
                if (!Arrays.equals(selectedApplicationId, MASTER_APPLICATION_IDENTIFIER)) {
                    int carKeySettings = keySettings.getChangeKeyAccessRights();
                    // see DESFire D40 datasheet M075031_desfire.pdf, page 35
                    if (carKeySettings == 0) {
                        accessTypeDescription = "Application master key authentication is necessary to change any key (default)";
                    } else if ((carKeySettings > 0) && (carKeySettings < 14)) {
                        accessTypeDescription = "Authentication with the specified key is necessary to change any key: " + carKeySettings;
                    } else if (carKeySettings == 14) {
                        accessTypeDescription = "Authentication with the key to be changed (same KeyNo) is necessary to change a key";
                    } else if (carKeySettings == 15) {
                        accessTypeDescription = "All Keys (except application master key, see Bit0) within this application are frozen";
                    } else {
                        accessTypeDescription = "undefined car key settings";
                    }
                } else {
                    accessTypeDescription = "data not available in Master Application";
                }
                keySettingsCarKey.setText(accessTypeDescription);

                builder
                        //.setMessage(selectedFolderString)
                        .setPositiveButton(android.R.string.yes, dialogClickListener)
                        .setTitle("Application key settings")
                        .show();
                scrollView.smoothScrollTo(0, 0);
            }
        });

        freeMemory.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                // get the free memory on the PICC
                clearOutputFields();
                writeToUiAppend(output, "get the free memory on the PICC");
                byte[] freeMemoryOnPicc;
                try {
                    freeMemoryOnPicc = desfire.freeMemory();
                    Utils.reverseByteArrayInPlace(freeMemoryOnPicc); // LSB
                    writeToUiAppend(output, "The free memory is " + Utils.intFrom3ByteArray(freeMemoryOnPicc) + " bytes");
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, "success in getting the free memory", COLOR_GREEN);
                    scrollView.smoothScrollTo(0, 0);
                } catch (IOException e) {
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, "IOException: " + e.getMessage(), COLOR_RED);
                    writeToUiAppend(errorCode, "Stack: " + Arrays.toString(e.getStackTrace()));
                    //writeToUiAppend(output, "IOException: " + e.getMessage());
                    e.printStackTrace();
                    scrollView.smoothScrollTo(0, 0);
                    return;
                }
            }
        });

        formatPicc.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                // format the PICC
                clearOutputFields();
                writeToUiAppend(output, "format the PICC");

                // open a confirmation dialog
                DialogInterface.OnClickListener dialogClickListener = new DialogInterface.OnClickListener() {
                    @Override
                    public void onClick(DialogInterface dialog, int which) {
                        switch (which) {
                            case DialogInterface.BUTTON_POSITIVE:
                                //Yes button clicked
                                boolean success;
                                try {
                                    success = desfire.formatPICC();
                                    writeToUiAppend(output, "formatPiccSuccess: " + success);
                                    if (!success) {
                                        writeToUiAppendBorderColor(errorCode, errorCodeLayout, "formatPicc NOT Success, aborted", COLOR_RED);
                                        writeToUiAppend(errorCode, "formatPicc NOT Success: " + desfire.getCode() + ":" + String.format("0x%02X", desfire.getCode()) + ":" + desfire.getCodeDesc());
                                        writeToUiAppend(errorCode, "Did you forget to authenticate with the Master Key first ?");
                                        scrollView.smoothScrollTo(0, 0);
                                        return;
                                    } else {
                                        writeToUiAppendBorderColor(errorCode, errorCodeLayout, "formatPicc success", COLOR_GREEN);
                                        selectedFileId = "";
                                        fileSelected.setText("");
                                        selectedApplicationId = null;
                                        applicationSelected.setText("");
                                        scrollView.smoothScrollTo(0, 0);
                                    }
                                } catch (IOException e) {
                                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, "IOException: " + e.getMessage(), COLOR_RED);
                                    writeToUiAppend(errorCode, "Stack: " + Arrays.toString(e.getStackTrace()));
                                    //writeToUiAppend(output, "IOException: " + e.getMessage());
                                    e.printStackTrace();
                                    scrollView.smoothScrollTo(0, 0);
                                    return;
                                }
                                break;
                            case DialogInterface.BUTTON_NEGATIVE:
                                //No button clicked
                                // nothing to do
                                writeToUiAppend(output, "format of the PICC aborted");
                                scrollView.smoothScrollTo(0, 0);
                                break;
                        }
                    }
                };
                final String selectedFolderString = "You are going to format the PICC " + "\n\n" +
                        "Do you want to proceed ?";
                AlertDialog.Builder builder = new AlertDialog.Builder(MainActivity.this);

                builder.setMessage(selectedFolderString).setPositiveButton(android.R.string.yes, dialogClickListener)
                        .setNegativeButton(android.R.string.no, dialogClickListener)
                        .setTitle("FORMAT the PICC")
                        .show();
        /*
        If you want to use the "yes" "no" literals of the user's language you can use this
        .setPositiveButton(android.R.string.yes, dialogClickListener)
        .setNegativeButton(android.R.string.no, dialogClickListener)
         */

                scrollView.smoothScrollTo(0, 0);
            }

        });

        selectMasterApplication.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                clearOutputFields();
                String logString = "select the Master application";
                writeToUiAppend(output, logString);
                String[] applicationList;
                try {
                    // select PICC (is selected by default but...)
                    boolean success = desfire.selectApplication(MASTER_APPLICATION_IDENTIFIER);
                    writeToUiAppend(output, logString + ": " + success);
                    if (!success) {
                        writeToUiAppend(output, logString + " NOT Success, aborted");
                        writeToUiAppendBorderColor(errorCode, errorCodeLayout, logString + " NOT Success, aborted", COLOR_RED);
                        scrollView.smoothScrollTo(0, 0);
                        return;
                    } else {
                        applicationSelected.setText("000000");
                        selectedApplicationId = new byte[3]; // 00 00 00
                        selectedFileId = "";
                        fileSelected.setText("");
                        writeToUiAppendBorderColor(errorCode, errorCodeLayout, logString + ": " + success, COLOR_GREEN);
                        scrollView.smoothScrollTo(0, 0);
                    }

                } catch (IOException e) {
                    //throw new RuntimeException(e);
                    //writeToUiAppend(output, "IOException: " + e.getMessage());
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, "IOException: " + e.getMessage(), COLOR_RED);
                    e.printStackTrace();
                    scrollView.smoothScrollTo(0, 0);
                    return;
                } catch (Exception e) {
                    //throw new RuntimeException(e);
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, "Exception: " + e.getMessage(), COLOR_RED);
                    writeToUiAppend(errorCode, "Stack: " + Arrays.toString(e.getStackTrace()));
                    e.printStackTrace();
                    scrollView.smoothScrollTo(0, 0);
                    return;
                }
            }
        });

        /**
         * section for applications
         */

        applicationCreate.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                // create a new application
                // get the input and sanity checks
                clearOutputFields();
                String logString = "create a new application";
                writeToUiAppend(output, logString);
                byte numberOfKeysByte = Byte.parseByte(numberOfKeys.getText().toString());
                byte[] applicationIdentifier = Utils.hexStringToByteArray(applicationId.getText().toString());
                if (applicationIdentifier == null) {
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, "you entered a wrong application ID", COLOR_RED);
                    scrollView.smoothScrollTo(0, 0);
                    return;
                }
                Utils.reverseByteArrayInPlace(applicationIdentifier); // change to LSB
                if (applicationIdentifier.length != 3) {
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, "you did not enter a 6 hex string application ID", COLOR_RED);
                    scrollView.smoothScrollTo(0, 0);
                    return;
                }
                KeyType keyType = KeyType.AES; // default
                if (rbApplicationKeyTypeDes.isChecked()) keyType = KeyType.DES;
                logString += " for " + keyType.toString() + " keys";
                try {
                    boolean success = desfire.createApplication(applicationIdentifier, APPLICATION_MASTER_KEY_SETTINGS, keyType, numberOfKeysByte);
                    writeToUiAppend(output, logString + " Success: " + success);
                    if (!success) {
                        writeToUiAppendBorderColor(errorCode, errorCodeLayout, logString + " NOT Success, aborted", COLOR_RED);
                        writeToUiAppend(errorCode, logString + " NOT Success: " + desfire.getCode() + ":" + String.format("0x%02X", desfire.getCode()) + ":" + desfire.getCodeDesc());
                        scrollView.smoothScrollTo(0, 0);
                        return;
                    } else {
                        writeToUiAppendBorderColor(errorCode, errorCodeLayout, logString + " SUCCESS", COLOR_GREEN);
                        scrollView.smoothScrollTo(0, 0);
                    }
                } catch (IOException e) {
                    //throw new RuntimeException(e);
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, "IOException: " + e.getMessage(), COLOR_RED);
                    e.printStackTrace();
                    scrollView.smoothScrollTo(0, 0);
                    return;
                } catch (Exception e) {
                    //throw new RuntimeException(e);
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, "Exception: " + e.getMessage(), COLOR_RED);
                    writeToUiAppend(errorCode, "Stack: " + Arrays.toString(e.getStackTrace()));
                    e.printStackTrace();
                    scrollView.smoothScrollTo(0, 0);
                    return;
                }
            }
        });

        applicationSelect.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                // get all applications and show them in a listview for selection
                clearOutputFields();
                String logString = "select an application";
                writeToUiAppend(output, logString);
                String[] applicationList;
                try {
                    // select PICC (is selected by default but...)
                    boolean success = desfire.selectApplication(MASTER_APPLICATION_IDENTIFIER);
                    writeToUiAppend(output, "selectMasterApplicationSuccess: " + success);
                    if (!success) {
                        writeToUiAppend(output, "selectMasterApplication NOT Success, aborted");
                        writeToUiAppendBorderColor(errorCode, errorCodeLayout, "selectMasterApplication NOT Success, aborted", COLOR_RED);
                        scrollView.smoothScrollTo(0, 0);
                        return;
                    }
                    List<DesfireApplicationId> desfireApplicationIdList = desfire.getApplicationsIds();
                    applicationList = new String[desfireApplicationIdList.size()];
                    for (int i = 0; i < desfireApplicationIdList.size(); i++) {
                        applicationList[i] = desfireApplicationIdList.get(i).getIdString();
                    }
                } catch (IOException e) {
                    //throw new RuntimeException(e);
                    //writeToUiAppend(output, "IOException: " + e.getMessage());
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, "IOException: " + e.getMessage(), COLOR_RED);
                    e.printStackTrace();
                    scrollView.smoothScrollTo(0, 0);
                    return;
                } catch (Exception e) {
                    //throw new RuntimeException(e);
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, "Exception: " + e.getMessage(), COLOR_RED);
                    writeToUiAppend(errorCode, "Stack: " + Arrays.toString(e.getStackTrace()));
                    e.printStackTrace();
                    scrollView.smoothScrollTo(0, 0);
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
                        writeToUiAppend(output, "you selected nr " + which + " = " + applicationList[which]);
                        boolean dfSelectApplication = false;
                        DesfireApplicationKeySettings desfireApplicationKeySettings;
                        try {
                            byte[] aid = Utils.hexStringToByteArray(applicationList[which]);
                            Utils.reverseByteArrayInPlace(aid);
                            dfSelectApplication = desfire.selectApplication(aid);
                            desfireApplicationKeySettings = desfire.getKeySettings();
                            scrollView.smoothScrollTo(0, 0);
                        } catch (IOException e) {
                            //throw new RuntimeException(e);
                            writeToUiAppendBorderColor(errorCode, errorCodeLayout, "IOException: " + e.getMessage(), COLOR_RED);
                            e.printStackTrace();
                            scrollView.smoothScrollTo(0, 0);
                            return;
                        }
                        // get the number and type of keys
                        int maxKeys = desfireApplicationKeySettings.getMaxKeys();
                        DesfireKeyType desfireKeyType = desfireApplicationKeySettings.getType();
                        String desfireKeyTypeString = desfireKeyType.toString();
                        // correct the output 'TDES' is in this context to 'DES'
                        if (desfireKeyTypeString.equals(DesfireKeyType.TDES.toString()))
                            desfireKeyTypeString = "DES";
                        writeToUiAppend(output, logString + " Result: " + dfSelectApplication);
                        if (dfSelectApplication) {
                            selectedApplicationId = Utils.hexStringToByteArray(applicationList[which]);
                            applicationSelected.setText(applicationList[which] + " (max " + maxKeys + " keys of " + desfireKeyTypeString + " type)");
                            selectedFileId = "";
                            fileSelected.setText("");
                            writeToUiAppendBorderColor(errorCode, errorCodeLayout, logString + " Result: " + dfSelectApplication, COLOR_GREEN);
                            scrollView.smoothScrollTo(0, 0);
                        } else {
                            writeToUiAppendBorderColor(errorCode, errorCodeLayout, logString + " NOT Success: " + desfire.getCode() + ":" + String.format("0x%02X", desfire.getCode()) + ":" + desfire.getCodeDesc(), COLOR_RED);
                            scrollView.smoothScrollTo(0, 0);
                        }
                    }
                });
                // create and show the alert dialog
                AlertDialog dialog = builder.create();
                dialog.show();
            }
        });

        applicationDelete.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                clearOutputFields();
                String logString = "delete a selected application";
                writeToUiAppend(output, logString);
                if (selectedApplicationId == null) {
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, "you need to select an application first", COLOR_RED);
                    scrollView.smoothScrollTo(0, 0);
                    return;
                }
                // open a confirmation dialog
                DialogInterface.OnClickListener dialogClickListener = new DialogInterface.OnClickListener() {
                    @Override
                    public void onClick(DialogInterface dialog, int which) {
                        switch (which) {
                            case DialogInterface.BUTTON_POSITIVE:
                                //Yes button clicked
                                try {
                                    byte[] aid = selectedApplicationId.clone();
                                    Utils.reverseByteArrayInPlace(aid);
                                    boolean success;
                                    try {
                                        success = desfire.deleteApplication(aid);
                                    } catch (AssertionError e) {
                                        // this may be an error in the library, but after the Assertion exception occured the application was deleted, so I'm ignoring this exception
                                        success = true;
                                    }
                                    writeToUiAppend(output, logString + " Success: " + success + " for applicationID: " + Utils.bytesToHexNpe(selectedApplicationId));
                                    if (!success) {
                                        writeToUiAppendBorderColor(errorCode, errorCodeLayout, logString + " NOT Success, aborted", COLOR_RED);
                                        writeToUiAppend(errorCode, "Did you forget to authenticate with the Application Master Key first ?");
                                        writeToUiAppend(errorCode, logString + " NOT Success: " + desfire.getCode() + ":" + String.format("0x%02X", desfire.getCode()) + ":" + desfire.getCodeDesc());
                                        scrollView.smoothScrollTo(0, 0);
                                        return;
                                    } else {
                                        writeToUiAppendBorderColor(errorCode, errorCodeLayout, logString + " success", COLOR_GREEN);
                                        applicationSelected.setText("");
                                        selectedApplicationId = null;
                                        selectedFileId = "";
                                        fileSelected.setText("");
                                        scrollView.smoothScrollTo(0, 0);
                                    }
                                } catch (IOException e) {
                                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, "IOException: " + e.getMessage(), COLOR_RED);
                                    e.printStackTrace();
                                    scrollView.smoothScrollTo(0, 0);
                                    return;
                                }
                                break;
                            case DialogInterface.BUTTON_NEGATIVE:
                                //No button clicked
                                // nothing to do
                                writeToUiAppend(output, logString + " aborted");
                                scrollView.smoothScrollTo(0, 0);
                                break;
                        }
                    }
                };
                final String selectedFolderString = "You are going to delete the application " +
                        Utils.bytesToHexNpe(selectedApplicationId) + "\n\n" +
                        "Do you want to proceed ?";
                AlertDialog.Builder builder = new AlertDialog.Builder(MainActivity.this);
                builder.setMessage(selectedFolderString).setPositiveButton(android.R.string.yes, dialogClickListener)
                        .setNegativeButton(android.R.string.no, dialogClickListener)
                        .setTitle("DELETE an application")
                        .show();
        /*
        If you want to use the "yes" "no" literals of the user's language you can use this
        .setPositiveButton(android.R.string.yes, dialogClickListener)
        .setNegativeButton(android.R.string.no, dialogClickListener)
         */
            }
        });


        /**
         * section for files
         */

        fileSelect.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                // select a file in a selected application
                clearOutputFields();

                byte[] fileIds;
                try {
                    fileIds = desfire.getFileIds();
                    if (fileIds == null) {
                        writeToUiAppend(output, "The getFileIds returned NULL");
                        scrollView.smoothScrollTo(0, 0);
                        return;
                    }
                } catch (IOException e) {
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, "IOException: " + e.getMessage(), COLOR_RED);
                    scrollView.smoothScrollTo(0, 0);
                    return;
                    //throw new RuntimeException(e);
                }

                if (fileIds.length == 0) {
                    writeToUiAppend(output, "The getFileIds returned no files");
                    scrollView.smoothScrollTo(0, 0);
                    return;
                }
                List<Byte> fileIdList = new ArrayList<>();
                List<String> fileIdInformationList = new ArrayList<>();
                for (int i = 0; i < fileIds.length; i++) {
                    fileIdList.add(fileIds[i]);
                    fileIdInformationList.add(getFileInformationType((int) fileIds[i]));
                }

                for (int i = 0; i < fileIdList.size(); i++) {
                    writeToUiAppend(output, "entry " + i + " file id : " + fileIdList.get(i) + (" (") + Utils.byteToHex(fileIdList.get(i)) + ")"
                            + " " + fileIdInformationList.get(i));
                }

                String[] fileList = new String[fileIdList.size()];
                for (int i = 0; i < fileIdList.size(); i++) {
                    //fileList[i] = Utils.byteToHex(fileIdList.get(i));
                    fileList[i] = String.valueOf(fileIdList.get(i))
                            + " (" + fileIdInformationList.get(i) + ")";
                }

                // setup the alert builder
                AlertDialog.Builder builder = new AlertDialog.Builder(view.getContext());
                builder.setTitle("Choose a file");

                builder.setItems(fileList, new DialogInterface.OnClickListener() {
                    @Override
                    public void onClick(DialogInterface dialog, int which) {
                        writeToUiAppend(output, "you  selected nr " + which + " = " + fileList[which]);
                        selectedFileId = String.valueOf(fileIdList.get(which));
                        selectedFileIdInt = Integer.parseInt(selectedFileId);
                        // now we run the command to select the application
                        byte[] responseData = new byte[2];

                        // here we are reading the fileSettings
                        DesfireFile desfireFile;
                        try {
                            desfireFile = desfire.forceFileSettingsUpdate(selectedFileIdInt);
                        } catch (Exception e) {
                            writeToUiAppendBorderColor(errorCode, errorCodeLayout, "IOException: " + e.getMessage(), COLOR_RED);
                            scrollView.smoothScrollTo(0, 0);
                            return;
                        }
                        if (desfireFile == null) {
                            writeToUiAppendBorderColor(errorCode, errorCodeLayout, "cant update the file communication settings, aborted", COLOR_RED);
                            scrollView.smoothScrollTo(0, 0);
                            return;
                        }
                        int readAccessKey = desfireFile.getReadAccessKey();
                        int writeAccessKey = desfireFile.getWriteAccessKey();
                        String csDescription = desfireFile.getCommunicationSettings().getDescription();
                        System.out.println("read: " + readAccessKey + " write " + writeAccessKey + " comm: " + csDescription);

                        fileSelected.setText(fileList[which]);
                        writeToUiAppendBorderColor(errorCode, errorCodeLayout, "file selected", COLOR_GREEN);
                        scrollView.smoothScrollTo(0, 0);
                    }
                });
                // create and show the alert dialog
                AlertDialog dialog = builder.create();
                dialog.show();
            }
        });

        fileDelete.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                clearOutputFields();
                writeToUiAppend(output, "delete a selected file");
                if (TextUtils.isEmpty(selectedFileId)) {
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, "you need to select a file first", COLOR_RED);
                    scrollView.smoothScrollTo(0, 0);
                    return;
                }
                // open a confirmation dialog
                DialogInterface.OnClickListener dialogClickListener = new DialogInterface.OnClickListener() {
                    @Override
                    public void onClick(DialogInterface dialog, int which) {
                        switch (which) {
                            case DialogInterface.BUTTON_POSITIVE:
                                //Yes button clicked
                                try {
                                    byte fileNo = Byte.parseByte(selectedFileId);
                                    boolean success = desfire.deleteFile(fileNo);
                                    writeToUiAppend(output, "deleteFileSuccess: " + success + " for fileID: " + selectedFileId);
                                    if (!success) {
                                        writeToUiAppendBorderColor(errorCode, errorCodeLayout, "deleteFile NOT Success, aborted", COLOR_RED);
                                        writeToUiAppend(errorCode, "Did you forget to authenticate with the Application Master Key first ?");
                                        writeToUiAppend(errorCode, "deleteFile NOT Success: " + desfire.getCode() + ":" + String.format("0x%02X", desfire.getCode()) + ":" + desfire.getCodeDesc());
                                        scrollView.smoothScrollTo(0, 0);
                                        return;
                                    } else {
                                        writeToUiAppendBorderColor(errorCode, errorCodeLayout, "deleteFile success", COLOR_GREEN);
                                        fileSelected.setText("");
                                        selectedFileId = null;
                                        scrollView.smoothScrollTo(0, 0);
                                    }
                                } catch (IOException e) {
                                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, "IOException: " + e.getMessage(), COLOR_RED);
                                    e.printStackTrace();
                                    scrollView.smoothScrollTo(0, 0);
                                    return;
                                }
                                break;
                            case DialogInterface.BUTTON_NEGATIVE:
                                //No button clicked
                                // nothing to do
                                writeToUiAppend(output, "delete a selected file aborted");
                                scrollView.smoothScrollTo(0, 0);
                                break;
                        }
                    }
                };
                final String selectedFolderString = "You are going to delete the file " +
                        selectedFileId + "\n\n" +
                        "Do you want to proceed ?";
                AlertDialog.Builder builder = new AlertDialog.Builder(MainActivity.this);
                builder.setMessage(selectedFolderString).setPositiveButton(android.R.string.yes, dialogClickListener)
                        .setNegativeButton(android.R.string.no, dialogClickListener)
                        .setTitle("DELETE a file")
                        .show();
        /*
        If you want to use the "yes" "no" literals of the user's language you can use this
        .setPositiveButton(android.R.string.yes, dialogClickListener)
        .setNegativeButton(android.R.string.no, dialogClickListener)
         */
            }
        });

        getFileSettings.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                // get the settings from the selected file
                clearOutputFields();
                String logString = "getFileSettings";
                writeToUiAppend(output, logString);
                if (TextUtils.isEmpty(selectedFileId)) {
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, "you need to select a file first", COLOR_RED);
                    scrollView.smoothScrollTo(0, 0);
                    return;
                }
                int selectedFileNumberInt = Integer.parseInt(selectedFileId);
                try {
                    DesfireFile fileSettings = desfire.getFileSettings(selectedFileNumberInt);
                    writeToUiAppend(output, "The following fileSettings are for fileId " + selectedFileNumberInt);
                    writeToUiAppend(output, fileSettings.toString());
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, logString + " SUCCESS", COLOR_GREEN);
                    scrollView.smoothScrollTo(0, 0);
                    return;
                } catch (IOException e) {
                    //throw new RuntimeException(e);
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, "IOException: " + e.getMessage(), COLOR_RED);
                    e.printStackTrace();
                    scrollView.smoothScrollTo(0, 0);
                    return;
                } catch (Exception e) {
                    //throw new RuntimeException(e);
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, "Exception: " + e.getMessage(), COLOR_RED);
                    writeToUiAppend(errorCode, "Stack: " + Arrays.toString(e.getStackTrace()));
                    e.printStackTrace();
                    scrollView.smoothScrollTo(0, 0);
                    return;
                }
            }
        });

        /**
         * section for standard files
         */

        fileStandardCreate.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                // create a new standard file
                writeToUiAppend(output, "create a standard or backup file");
                // get the input and sanity checks
                clearOutputFields();
                byte fileIdByte = (byte) (npStandardFileId.getValue() & 0xFF);

                // the number of files on an EV1 tag is limited to 32 (00..31), but we are using the limit for the old D40 tag with a maximum of 15 files (00..14)
                // this limit is hardcoded in the XML file for the fileId numberPicker

                //byte fileIdByte = Byte.parseByte(fileId.getText().toString());
                int fileSizeInt = Integer.parseInt(fileSize.getText().toString());
                if (fileIdByte > (byte) 0x0f) {
                    // this should not happen as the limit is hardcoded in npFileId
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, "you entered a wrong file ID", COLOR_RED);
                    scrollView.smoothScrollTo(0, 0);
                    return;
                }

                // new for communication setting choice
                PayloadBuilder.CommunicationSetting communicationSetting;
                if (rbFileStandardPlainCommunication.isChecked()) {
                    communicationSetting = PayloadBuilder.CommunicationSetting.Plain;
                } else if (rbFileStandardMacedCommunication.isChecked()) {
                    communicationSetting = PayloadBuilder.CommunicationSetting.MACed;
                } else {
                    communicationSetting = PayloadBuilder.CommunicationSetting.Encrypted;
                }
                boolean isStandardFile = rbStandardFile.isChecked(); // as there are 2 options only we just just check rbStandardFile
                try {
                    PayloadBuilder pb = new PayloadBuilder();
                    byte[] payloadStandardFile = pb.createStandardFile(fileIdByte, communicationSetting,
                            1, 2, 3, 4, fileSizeInt);
                    boolean success;
                    String createString;
                    if (isStandardFile) {
                        createString = "createStandardDataFile";
                        success = desfire.createStdDataFile(payloadStandardFile);

                    } else {
                        createString = "createBackupDataFile";
                        success = desfire.createBackupDataFile(payloadStandardFile);
                    }
                    writeToUiAppend(output, createString + "Success: " + success + " with FileID: " + Utils.byteToHex(fileIdByte) + " and size: " + fileSizeInt);
                    if (!success) {
                        writeToUiAppendBorderColor(errorCode, errorCodeLayout, createString + " NOT Success, aborted", COLOR_RED);
                        writeToUiAppend(errorCode, createString + " NOT Success: " + desfire.getCode() + ":" + String.format("0x%02X", desfire.getCode()) + ":" + desfire.getCodeDesc());
                        scrollView.smoothScrollTo(0, 0);
                        return;
                    }
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, createString + " Success: " + desfire.getCode() + ":" + String.format("0x%02X", desfire.getCode()) + ":" + desfire.getCodeDesc(), COLOR_GREEN);
                    scrollView.smoothScrollTo(0, 0);
                } catch (IOException e) {
                    //throw new RuntimeException(e);
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, "IOException: " + e.getMessage(), COLOR_RED);
                    e.printStackTrace();
                    scrollView.smoothScrollTo(0, 0);
                    return;
                } catch (Exception e) {
                    //throw new RuntimeException(e);
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, "Exception: " + e.getMessage(), COLOR_RED);
                    writeToUiAppend(errorCode, "Stack: " + Arrays.toString(e.getStackTrace()));
                    e.printStackTrace();
                    scrollView.smoothScrollTo(0, 0);
                    return;
                }
            }
        });

        fileStandardWrite.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                // write to a selected standard file in a selected application
                clearOutputFields();
                writeToUiAppend(output, "write to a standard or backup file");
                // this uses the pre selected file
                if (TextUtils.isEmpty(selectedFileId)) {
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, "you need to select a file first", COLOR_RED);
                    scrollView.smoothScrollTo(0, 0);
                    return;
                }
                String dataToWriteString = fileData.getText().toString();
                if (TextUtils.isEmpty(dataToWriteString)) {
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, "please enter some data to write", COLOR_RED);
                    scrollView.smoothScrollTo(0, 0);
                    return;
                }
                int fileIdInt = Integer.parseInt(selectedFileId);

                // check that it is a standard or backup file !
                DesfireFile fileSettings = null;
                try {
                    fileSettings = desfire.getFileSettings(fileIdInt);
                } catch (Exception e) {
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, "Exception: " + e.getMessage(), COLOR_RED);
                    e.printStackTrace();
                    scrollView.smoothScrollTo(0, 0);
                    return;
                }
                // check that it is a standard or backup file !
                String fileTypeName = fileSettings.getFileTypeName();
                writeToUiAppend(output, "file number " + fileIdInt + " is of type " + fileTypeName);
                if ((!fileTypeName.equals("Standard")) && (!fileTypeName.equals("Backup"))) {
                    writeToUiAppend(output, "The selected file is not of type Standard or Backup but of type " + fileTypeName + ", aborted");
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, "wrong file type", COLOR_RED);
                    scrollView.smoothScrollTo(0, 0);
                    return;
                }
                boolean isBackupFile = false; // backup files require a commit after writing
                if (fileTypeName.equals("Backup")) isBackupFile = true;
                // get a random payload with 32 bytes
                UUID uuid = UUID.randomUUID(); // this is 36 characters long
                //byte[] dataToWrite = Arrays.copyOf(uuid.toString().getBytes(StandardCharsets.UTF_8), 32); // this 32 bytes long

                // create an empty array and copy the dataToWrite to clear the complete standard file
                StandardDesfireFile standardDesfireFile = (StandardDesfireFile) fileSettings;
                int fileSize = standardDesfireFile.getFileSize();
                byte[] fullDataToWrite = new byte[fileSize];
                // limit the string
                if (dataToWriteString.length() > fileSize)
                    dataToWriteString = dataToWriteString.substring(0, fileSize);
                byte[] dataToWrite = dataToWriteString.getBytes(StandardCharsets.UTF_8);
                System.arraycopy(dataToWrite, 0, fullDataToWrite, 0, dataToWrite.length);

                PayloadBuilder pb = new PayloadBuilder();
                byte[] payload = pb.writeToStandardFile(fileIdInt, fullDataToWrite);

                writeToUiAppend(output, printData("payloadWriteData", payload));
                String writeFileString;
                if (isBackupFile) {
                    writeFileString = "writeToBackupFile";
                } else {
                    writeFileString = "writeToStandardFile";
                }
                boolean writeStandardSuccess = false;
                try {
                    writeStandardSuccess = desfire.writeData(payload);
                } catch (Exception e) {
                    //throw new RuntimeException(e);
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, "Exception: " + e.getMessage(), COLOR_RED);
                    writeToUiAppend(errorCode, "did you forget to authenticate with a write access key ?");
                    e.printStackTrace();
                    scrollView.smoothScrollTo(0, 0);
                    return;
                }
                writeToUiAppend(output, writeFileString + "Result: " + writeStandardSuccess);
                writeToUiAppend(output, writeFileString + "ResultCode: " + desfire.getCode() + ":" + String.format("0x%02X", desfire.getCode()) + ":" + desfire.getCodeDesc());
                if (writeStandardSuccess) {
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, writeFileString + " Success: " + desfire.getCode() + ":" + String.format("0x%02X", desfire.getCode()) + ":" + desfire.getCodeDesc(), COLOR_GREEN);
                } else {
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, writeFileString + " NOT Success: " + String.format("0x%02X", desfire.getCode()) + ":" + desfire.getCodeDesc(), COLOR_RED);
                    writeToUiAppend(errorCode, "did you forget to authenticate with a write access key ?");
                }
                if (isBackupFile) {
                    // a following commit is necessary
                    writeToUiAppend(output, writeFileString + ": a commit to the card is necessary");
                    if (writeStandardSuccess) {
                        try {
                            boolean successCommit = desfire.commitTransaction();
                            writeToUiAppend(output, "commitSuccess: " + successCommit);
                            if (!successCommit) {
                                writeToUiAppendBorderColor(errorCode, errorCodeLayout, "commit NOT Success, aborted", COLOR_RED);
                                writeToUiAppend(errorCode, "commit NOT Success: " + String.format("0x%02X", desfire.getCode()) + ":" + desfire.getCodeDesc());
                                writeToUiAppend(errorCode, "Did you forget to authenticate with a Write Access Key first ?");
                                scrollView.smoothScrollTo(0, 0);
                                return;
                            }
                            writeToUiAppendBorderColor(errorCode, errorCodeLayout, "commit Success: " + String.format("0x%02X", desfire.getCode()) + ":" + desfire.getCodeDesc(), COLOR_GREEN);
                        } catch (Exception e) {
                            //throw new RuntimeException(e);
                            writeToUiAppendBorderColor(errorCode, errorCodeLayout, "Exception: " + e.getMessage(), COLOR_RED);
                            writeToUiAppend(errorCode, "did you forget to authenticate with a write access key ?");
                            e.printStackTrace();
                            scrollView.smoothScrollTo(0, 0);
                            return;
                        }
                    } else {
                        writeToUiAppend(output, "as the writing to the backup file was not successful I'm not trying to send a commit");
                        scrollView.smoothScrollTo(0, 0);
                    }
                }
                scrollView.smoothScrollTo(0, 0);
            }
        });

        fileStandardRead.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                // read from a selected standard file in a selected application
                clearOutputFields();
                // this uses the pre selected file
                writeToUiAppend(output, "read from a standard or backup file");
                if (TextUtils.isEmpty(selectedFileId)) {
                    //writeToUiAppend(errorCode, "you need to select a file first");
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, "you need to select a file first", COLOR_RED);
                    scrollView.smoothScrollTo(0, 0);
                    return;
                }
                int fileIdInt = selectedFileIdInt;
                byte[] readStandard;
                boolean isBackupFile = false; // backup files require a commit after writing
                String readFileString;
                try {
                    // get the maximal length from getFileSettings
                    DesfireFile fileSettings = desfire.getFileSettings(fileIdInt);
                    // check that it is a standard file !
                    String fileTypeName = fileSettings.getFileTypeName();
                    writeToUiAppend(output, "file number " + fileIdInt + " is of type " + fileTypeName);
                    if ((!fileTypeName.equals("Standard")) && (!fileTypeName.equals("Backup"))) {
                        writeToUiAppend(output, "The selected file is not of type Standard or Backup but of type " + fileTypeName + ", aborted");
                        writeToUiAppendBorderColor(errorCode, errorCodeLayout, "wrong file type", COLOR_RED);
                        scrollView.smoothScrollTo(0, 0);
                        return;
                    }
                    if (fileTypeName.equals("Backup")) isBackupFile = true;

                    if (isBackupFile) {
                        readFileString = "readFromBackupFile";
                    } else {
                        readFileString = "readFromStandardFile";
                    }

                    StandardDesfireFile standardDesfireFile = (StandardDesfireFile) fileSettings;
                    int fileSize = standardDesfireFile.getFileSize();
                    writeToUiAppend(output, "fileSize: " + fileSize);
                    readStandard = desfire.readData((byte) (fileIdInt & 0xff), 0, fileSize);
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, readFileString + "Success: " + desfire.getCode() + ":" + String.format("0x%02X", desfire.getCode()) + ":" + desfire.getCodeDesc(), COLOR_GREEN);
                    scrollView.smoothScrollTo(0, 0);
                } catch (IOException e) {
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, "IOException: " + e.getMessage(), COLOR_RED);
                    writeToUiAppend(errorCode, "did you forget to authenticate with a read access key ?");
                    e.printStackTrace();
                    scrollView.smoothScrollTo(0, 0);
                    return;
                } catch (Exception e) {
                    //throw new RuntimeException(e);
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, "Exception: " + e.getMessage(), COLOR_RED);
                    writeToUiAppend(errorCode, "did you forget to authenticate with a read access key ?");
                    e.printStackTrace();
                    scrollView.smoothScrollTo(0, 0);
                    return;
                }
                if (readStandard == null) {
                    writeToUiAppend(output, "error on reading from file number " + fileIdInt);
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, "did you forget to authenticate with a read access key ?", COLOR_RED);
                    scrollView.smoothScrollTo(0, 0);
                    return;
                }
                writeToUiAppend(output, printData(readFileString, readStandard));
                writeToUiAppend(output, new String(readStandard, StandardCharsets.UTF_8));
                writeToUiAppend(output, "finished");
                writeToUiAppend(output, "");
                scrollView.smoothScrollTo(0, 0);
            }
        });


        /**
         * section for authentication with default keys
         */

        authDM0D.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                // authenticate with the master application key = 00...
                authenticate("authenticate with DEFAULT DES key number 0x00 = master application key", MASTER_APPLICATION_KEY_NUMBER, MASTER_APPLICATION_KEY_DES_DEFAULT, "master", KeyType.DES);
            }
        });


        authD0D.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                // authenticate with the application master key = 00...
                authenticate("authenticate with DEFAULT DES key number 0x00 = application master key", APPLICATION_KEY_MASTER_NUMBER, APPLICATION_KEY_MASTER_DES_DEFAULT, "app master", KeyType.DES);
            }
        });

        authD1D.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                // authenticate with the read&write access key = 01...
                authenticate("authenticate with DEFAULT DES key number 0x01 = read & write access key", APPLICATION_KEY_RW_NUMBER, APPLICATION_KEY_RW_DES_DEFAULT, "read & write", KeyType.DES);
            }
        });

        authD2D.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                // authenticate with the change access rights key = 02...
                authenticate("authenticate with DEFAULT DES key number 0x02 = change access rights key", APPLICATION_KEY_CAR_NUMBER, APPLICATION_KEY_CAR_DES_DEFAULT, "change access rights", KeyType.DES);
            }
        });

        authD3D.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                // authenticate with the read access key = 03...
                authenticate("authenticate with DEFAULT DES key number 0x03 = read access key", APPLICATION_KEY_R_NUMBER, APPLICATION_KEY_R_DES_DEFAULT, "read", KeyType.DES);
            }
        });

        authD4D.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                // authenticate with the read&write access key = 01...
                authenticate("authenticate with DEFAULT DES key number 0x04 = write access key", APPLICATION_KEY_W_NUMBER, APPLICATION_KEY_W_DES_DEFAULT, "write", KeyType.DES);
            }
        });

        // AES keys

        authDM0A.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                // authenticate with the master application key = 00...
                authenticate("authenticate with DEFAULT AES key number 0x00 = master application key", MASTER_APPLICATION_KEY_NUMBER, MASTER_APPLICATION_KEY_AES_DEFAULT, "master", KeyType.AES);
            }
        });


        authD0A.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                // authenticate with the application master key = 00...
                authenticate("authenticate with DEFAULT AES key number 0x00 = application master key", APPLICATION_KEY_MASTER_NUMBER, APPLICATION_KEY_MASTER_AES_DEFAULT, "app master", KeyType.AES);
            }
        });

        authD1A.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                // authenticate with the read&write access key = 01...
                authenticate("authenticate with DEFAULT AES key number 0x01 = read & write access key", APPLICATION_KEY_RW_NUMBER, APPLICATION_KEY_RW_AES_DEFAULT, "read & write", KeyType.AES);
            }
        });

        authD2A.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                // authenticate with the change access rights key = 02...
                authenticate("authenticate with DEFAULT AES key number 0x02 = change access rights key", APPLICATION_KEY_CAR_NUMBER, APPLICATION_KEY_CAR_AES_DEFAULT, "change access rights", KeyType.AES);
            }
        });

        authD3A.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                // authenticate with the read access key = 03...
                authenticate("authenticate with DEFAULT AES key number 0x03 = read access key", APPLICATION_KEY_R_NUMBER, APPLICATION_KEY_R_AES_DEFAULT, "read", KeyType.AES);
            }
        });

        authD4A.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                // authenticate with the read&write access key = 01...
                authenticate("authenticate with DEFAULT AES key number 0x04 = write access key", APPLICATION_KEY_W_NUMBER, APPLICATION_KEY_W_AES_DEFAULT, "write", KeyType.AES);
            }
        });

        /**
         * section for service methods
         */

        getFileSettingsDesfire.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                // reads the stored file settings from DESFireEV1 class
                clearOutputFields();
                String logString = "get the fileSettings from DESFireEV1 class";
                writeToUiAppend(output, logString);
                DesfireFile desfireFile = null;
                try {
                    desfireFile = desfire.getFileSettings(selectedFileIdInt);
                } catch (Exception e) {
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, "Exception: " + e.getMessage(), COLOR_RED);
                    e.printStackTrace();
                    scrollView.smoothScrollTo(0, 0);
                    return;
                }
                if (desfireFile == null) {
                    writeToUiAppend(output, "the fileSettings from DESFireEV1 class are NULL");
                    scrollView.smoothScrollTo(0, 0);
                    return;
                }
                String fileTypeName = desfireFile.getFileTypeName();
                int fileStandardSize = 0;
                writeToUiAppend(output, "The file " + selectedFileIdInt + " is of type " + fileTypeName);
                DesfireFileCommunicationSettings comSetting = desfireFile.getCommunicationSettings();
                writeToUiAppend(output, "the communicationSettings are " + comSetting.getDescription());
                if (!fileTypeName.equals("Standard")) {
                    writeToUiAppend(output, "The file is not of type Standard but of type " + fileTypeName + ", no fileSize");
                } else {
                    StandardDesfireFile standardDesfireFile = (StandardDesfireFile) desfireFile;
                    fileStandardSize = standardDesfireFile.getFileSize();
                    writeToUiAppend(output, "file " + selectedFileIdInt + " size: " + fileStandardSize);
                }

                Map<Integer, String> permMap = desfireFile.getCompactPermissionMap();
                writeToUiAppend(output, "----- permission map (authentication keys) ------");
                for (Map.Entry<Integer, String> entry : permMap.entrySet()) {
                    writeToUiAppend(output, entry.getKey() + ":" + entry.getValue().toString());
                }
                writeToUiAppend(output, "-------------------------------------------------");
                writeToUiAppendBorderColor(errorCode, errorCodeLayout, logString + " SUCCESS", COLOR_GREEN);
                scrollView.smoothScrollTo(0, 0);
            }
        });

        getCardUid.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                clearOutputFields();
                String logString = "getCardUid";
                writeToUiAppend(output, logString);
                try {
                    byte[] result = desfire.getCardUID();
                    if (result == null) {
                        writeToUiAppend(output, "Could not get the UID from card - did you forget to AUTHENTICATE with any key ?");
                        writeToUiAppendBorderColor(errorCode, errorCodeLayout, logString + " Did you forget to AUTHENTICATE with any key ?", COLOR_RED);
                        scrollView.smoothScrollTo(0, 0);
                        return;
                    }
                    writeToUiAppend(output, printData("card UID", result));
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, logString + " SUCCESS", COLOR_GREEN);
                    scrollView.smoothScrollTo(0, 0);
                } catch (IOException e) {
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, "IOException: " + e.getMessage(), COLOR_RED);
                    writeToUiAppend(errorCode, "did you forget to authenticate with a read access key ?");
                    e.printStackTrace();
                    scrollView.smoothScrollTo(0, 0);
                    return;
                } catch (Exception e) {
                    //throw new RuntimeException(e);
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, "Exception: " + e.getMessage(), COLOR_RED);
                    writeToUiAppend(errorCode, "did you forget to authenticate with a read access key ?");
                    e.printStackTrace();
                    scrollView.smoothScrollTo(0, 0);
                    return;
                }
                scrollView.smoothScrollTo(0, 0);
            }
        });


    }

    /**
     * section for UI helper methods to shorten the code
     */

    private void authenticate(String logString, byte keyNumber, byte[] authenticationKey, String keyName, KeyType keyType) {
        // authenticate with the application master key = 00...
        clearOutputFields();
        writeToUiAppend(output, logString);
        if (selectedApplicationId == null) {
            writeToUiAppendBorderColor(errorCode, errorCodeLayout, "you need to select an application first", COLOR_RED);
            scrollView.smoothScrollTo(0, 0);
            return;
        }
        boolean success = authenticateApplication(keyNumber, authenticationKey, keyName, keyType);
        writeToUiAppend(output, logString + " success: " + success);
        scrollView.smoothScrollTo(0, 0);
        scrollView.smoothScrollTo(0, 0);
    }


    private String getFileInformationType(int fileNumber) {
        String fileType;
        String commType;
        DesfireFile desfireFile = null;
        try {
            desfireFile = desfire.getFileSettings(fileNumber);
        } catch (Exception e) {
            writeToUiAppendBorderColor(errorCode, errorCodeLayout, "Exception: " + e.getMessage(), COLOR_RED);
            e.printStackTrace();
            return "";
        }
        if (desfireFile == null) {
            writeToUiAppend(output, "the fileSettings from DESFireEV1 class are NULL");
            return "";
        }
        fileType = desfireFile.getFileTypeName();
        int comSett = desfireFile.getCommunicationSettings().getValue();
        if (comSett == 0) {
            commType = "Plain";
        } else if (comSett == 1) {
            commType = "MACed";
        } else {
            commType = "Encrypted";
        }
        return fileType + " | " + commType;
    }

    /**
     * section for authentication
     */

    private boolean authenticateApplication(byte keyNumber, byte[] key, String keyName, KeyType keyType) {
        writeToUiAppend(output, keyType.toString() + " authentication with key " + String.format("0x%02X", keyNumber) + "(= " + keyName + "access key)");
        try {
            boolean authApp = desfire.authenticate(key, keyNumber, keyType);
            writeToUiAppend(output, "authApplicationResult: " + authApp);
            if (!authApp) {
                writeToUiAppendBorderColor(errorCode, errorCodeLayout, "authenticateApplication NOT Success, aborted", COLOR_RED);
                writeToUiAppend(errorCode, "authenticateApplication NOT Success: " + desfire.getCode() + ":" + String.format("0x%02X", desfire.getCode()) + ":" + desfire.getCodeDesc());
                return false;
            } else {
                writeToUiAppendBorderColor(errorCode, errorCodeLayout, "authenticateApplication SUCCESS", COLOR_GREEN);
                return true;
            }
        } catch (IOException e) {
            writeToUiAppendBorderColor(errorCode, errorCodeLayout, "IOException: " + e.getMessage(), COLOR_RED);
            writeToUiAppend(errorCode, "Stack: " + Arrays.toString(e.getStackTrace()));
            //writeToUiAppend(output, "IOException: " + e.getMessage());
            e.printStackTrace();
            return false;
        } catch (Exception e) {
            writeToUiAppendBorderColor(errorCode, errorCodeLayout, "Exception: " + e.getMessage(), COLOR_RED);
            writeToUiAppend(errorCode, "Stack: " + Arrays.toString(e.getStackTrace()));
            //writeToUiAppend(output, "IOException: " + e.getMessage());
            e.printStackTrace();
            return false;
        }
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
                    allLayoutsVisibility(true);
                    output.setText("");
                    errorCode.setText("");
                });
                isoDep.connect();
                // get tag ID
                tagIdByte = tag.getId();
                writeToUiAppend(output, "tag id: " + Utils.bytesToHex(tagIdByte));
                writeToUiAppend(output, "NFC tag connected");
                writeToUiAppendBorderColor(errorCode, errorCodeLayout, "the app is ready to work with", COLOR_GREEN);
                IsoDepWrapper isoDepWrapper = new DefaultIsoDepWrapper(isoDep);
                desFireAdapter = new DESFireAdapter(isoDepWrapper, true);
                desfire = new DESFireEV1();
                desfire.setAdapter(desFireAdapter);

                // try to read the version info, if this fails it might be a hce emulated desfire tag
                try {
                    VersionInfo versionInfo = desfire.getVersion();
                    System.out.println(versionInfo.dump());
                } catch (Exception e) {
                    e.printStackTrace();
                    String eMessage = e.getMessage();
                    Log.i(TAG, "Exception: " + eMessage);
                    if (eMessage.equals("Invalid response 69")) {
                        // try to select the tag by it's DF name
                        String selectHceStringDesfire = "00A4040007D2760000850100";
                        byte[] selectHce = Utils.hexStringToByteArray(selectHceStringDesfire);
                        Log.i(TAG, "selectHce: " + com.github.skjolber.desfire.ev1.model.command.Utils.getHexString(selectHce));
                        byte[] response;
                        response = isoDep.transceive(selectHce);
                        Log.i(TAG, "response after selectHce: " + com.github.skjolber.desfire.ev1.model.command.Utils.getHexString(response));
                    }
                }
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
                            NfcAdapter.FLAG_READER_SKIP_NDEF_CHECK |
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

    private void allLayoutsVisibility(boolean isVisible) {
        llApplicationHandling.setVisibility(isVisible ? View.VISIBLE : View.INVISIBLE);
        llFiles.setVisibility(isVisible ? View.VISIBLE : View.INVISIBLE);
        llStandardFile.setVisibility(isVisible ? View.VISIBLE : View.INVISIBLE);
        llAuthentication2.setVisibility(isVisible ? View.VISIBLE : View.INVISIBLE);
        llGeneralWorkflow.setVisibility(isVisible ? View.VISIBLE : View.INVISIBLE);
        noTagInformation.setVisibility(isVisible ? View.GONE : View.VISIBLE);
    }

    /**
     * section for UI handling
     */

    private void writeToUiAppend(TextView textView, String message) {
        runOnUiThread(() -> {
            String oldString = textView.getText().toString();
            if (TextUtils.isEmpty(oldString)) {
                textView.setText(message);
            } else {
                String newString = message + "\n" + oldString;
                textView.setText(newString);
                System.out.println(message);
            }
        });
    }

    private void writeToUiAppendBorderColor(TextView textView, TextInputLayout textInputLayout, String message, int color) {
        runOnUiThread(() -> {

            // set the color to green
            //Color from rgb
            // int color = Color.rgb(255,0,0); // red
            //int color = Color.rgb(0,255,0); // green
            //Color from hex string
            //int color2 = Color.parseColor("#FF11AA"); light blue
            int[][] states = new int[][]{
                    new int[]{android.R.attr.state_focused}, // focused
                    new int[]{android.R.attr.state_hovered}, // hovered
                    new int[]{android.R.attr.state_enabled}, // enabled
                    new int[]{}  //
            };
            int[] colors = new int[]{
                    color,
                    color,
                    color,
                    //color2
                    color
            };
            ColorStateList myColorList = new ColorStateList(states, colors);
            textInputLayout.setBoxStrokeColorStateList(myColorList);

            String oldString = textView.getText().toString();
            if (TextUtils.isEmpty(oldString)) {
                textView.setText(message);
            } else {
                String newString = message + "\n" + oldString;
                textView.setText(newString);
                System.out.println(message);
            }
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
        // reset the border color to primary for errorCode
        int color = R.color.colorPrimary;
        int[][] states = new int[][]{
                new int[]{android.R.attr.state_focused}, // focused
                new int[]{android.R.attr.state_hovered}, // hovered
                new int[]{android.R.attr.state_enabled}, // enabled
                new int[]{}  //
        };
        int[] colors = new int[]{
                color,
                color,
                color,
                color
        };
        ColorStateList myColorList = new ColorStateList(states, colors);
        errorCodeLayout.setBoxStrokeColorStateList(myColorList);
    }

    /**
     * section for options menu
     */

    @Override
    public boolean onCreateOptionsMenu(Menu menu) {
        getMenuInflater().inflate(R.menu.menu_activity_main, menu);

        MenuItem mLicenseInformation = menu.findItem(R.id.action_licenseInformation);
        mLicenseInformation.setOnMenuItemClickListener(new MenuItem.OnMenuItemClickListener() {
            @Override
            public boolean onMenuItemClick(MenuItem item) {
                displayLicensesAlertDialog();
                return false;
            }
        });
        MenuItem mAbout = menu.findItem(R.id.action_about);
        mAbout.setOnMenuItemClickListener(new MenuItem.OnMenuItemClickListener() {
            @Override
            public boolean onMenuItemClick(MenuItem item) {
                Intent i = new Intent(MainActivity.this, AboutActivity.class);
                startActivity(i);
                return false;
            }
        });

        return super.onCreateOptionsMenu(menu);
    }

    // run: displayLicensesAlertDialog();
    // display licenses dialog see: https://bignerdranch.com/blog/open-source-licenses-and-android/
    private void displayLicensesAlertDialog() {
        WebView view = (WebView) LayoutInflater.from(this).inflate(R.layout.dialog_licenses, null);
        view.loadUrl("file:///android_asset/open_source_licenses.html");
        android.app.AlertDialog mAlertDialog = new android.app.AlertDialog.Builder(MainActivity.this).create();
        mAlertDialog = new android.app.AlertDialog.Builder(this, androidx.appcompat.R.style.Theme_AppCompat_Light_Dialog_Alert)
                .setTitle("Libraries used and their licenses")
                .setView(view)
                .setPositiveButton(android.R.string.ok, null)
                .show();
    }


}