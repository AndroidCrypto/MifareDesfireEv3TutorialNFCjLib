package de.androidcrypto.mifaredesfireev3examplesdes;

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

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class MainActivity extends AppCompatActivity implements NfcAdapter.ReaderCallback  {

    private com.google.android.material.textfield.TextInputEditText output, errorCode;
    private LinearLayout llApplicationHandling;
    private Button applicationList, applicationCreate, applicationSelect;
    private com.google.android.material.textfield.TextInputEditText numberOfKeys, applicationId, applicationSelected;

    private byte[] selectedApplicationId = null;

    // variables for NFC handling

    private NfcAdapter mNfcAdapter;
    private IsoDep isoDep;
    private byte[] tagIdByte;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        Toolbar myToolbar = (Toolbar) findViewById(R.id.main_toolbar);
        setSupportActionBar(myToolbar);

        output = findViewById(R.id.etOutput);
        errorCode = findViewById(R.id.etErrorCode);

        // application handling
        llApplicationHandling = findViewById(R.id.llApplications);
        applicationList = findViewById(R.id.btnListApplications);
        applicationCreate = findViewById(R.id.btnCreateApplication);
        applicationSelect = findViewById(R.id.btnSelectApplication);
        applicationSelected = findViewById(R.id.etSelectedApplicationId);
        numberOfKeys = findViewById(R.id.etNumberOfKeys);
        applicationId = findViewById(R.id.etApplicationId);

        allLayoutsInvisible(); // default

        mNfcAdapter = NfcAdapter.getDefaultAdapter(this);

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
                if (applicationIdentifier == null) {
                    writeToUiAppend(errorCode, "you entered a wrong application ID");
                    return;
                }
                if (applicationIdentifier.length != 3) {
                    writeToUiAppend(errorCode, "you did not enter a 6 hex string application ID");
                    return;
                }
                byte[] responseData = new byte[2];
                boolean result = createApplicationPlainDes(output, applicationIdentifier, numberOfKeysByte, responseData);
                writeToUiAppend(output, "result of createAnApplication: " + result);
                writeToUiAppend(errorCode, "createAnApplication: " + Ev3.getErrorCode(responseData));
            }
        });

        applicationSelect.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                // get all applications and show them in a listview for selection
                clearOutputFields();
                byte[] responseData = new byte[2];
                List<byte[]> applicationIdList = getApplicationIdsList(output, responseData);
                writeToUiAppend(errorCode, "getApplicationIdsList: " + Ev3.getErrorCode(responseData));
                if (applicationIdList != null) {
                    for (int i = 0; i < applicationIdList.size(); i++) {
                        // writeToUiAppend(output, "entry " + i + " app id : " + Utils.bytesToHex(applicationIdList.get(i)));
                    }
                } else {
                    writeToUiAppend(errorCode, "getApplicationIdsList: returned NULL");
                    return;
                }
                String[] applicationList = new String[applicationIdList.size()];
                for (int i = 0; i < applicationIdList.size(); i++) {
                    applicationList[i] = Utils.bytesToHex(applicationIdList.get(i));
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

        return super.onCreateOptionsMenu(menu);
    }

}