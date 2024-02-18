package de.androidcrypto.desfiretutorial;

import android.app.AlertDialog;
import android.app.Dialog;
import android.os.Bundle;
import android.view.LayoutInflater;
import android.webkit.WebView;

import androidx.annotation.NonNull;
import androidx.fragment.app.DialogFragment;

public class LicensesDialogFragment extends DialogFragment {

    public static LicensesDialogFragment newInstance() {
        return new LicensesDialogFragment();
    }

    @NonNull
    @Override
    public Dialog onCreateDialog(Bundle savedInstanceState) {
        WebView view = (WebView) LayoutInflater.from(getActivity()).inflate(R.layout.dialog_licenses, null);
        view.loadUrl("file:///android_asset/open_source_licenses.html");
        return new AlertDialog.Builder(getActivity(), androidx.appcompat.R.style.Theme_AppCompat_Light_Dialog_Alert)
                .setTitle("Libraries used and their licenses")
                .setView(view)
                .setPositiveButton(android.R.string.ok, null)
                .create();
    }

}


