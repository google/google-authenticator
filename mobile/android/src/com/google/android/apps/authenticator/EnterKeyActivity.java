// Copyright (C) 2009 Google Inc.

package com.google.android.apps.authenticator;

import com.google.android.apps.authenticator.Base32String.DecodingException;

import android.app.Activity;
import android.graphics.Color;
import android.os.Bundle;
import android.text.Editable;
import android.text.TextWatcher;
import android.view.View;
import android.view.View.OnClickListener;
import android.widget.ArrayAdapter;
import android.widget.Button;
import android.widget.EditText;
import android.widget.Spinner;
import android.widget.TextView;

import java.security.GeneralSecurityException;

/**
 * The activity that allows users to manually enter a key.
 * 
 * @author sweis@google.com (Steve Weis)
 */
public class EnterKeyActivity extends Activity implements OnClickListener,
    TextWatcher {
  private static final int MIN_KEY_BYTES = 10;
  private TextView mStatusText;
  private EditText mKeyEntryField;
  private EditText mAccountName;
  private Spinner mType;
  private Button mSubmitButton;
  private Button mCancelButton;
  
  /**
   * Called when the activity is first created
   */
  @Override
  public void onCreate(Bundle savedInstanceState) {
    super.onCreate(savedInstanceState);
    setContentView(R.layout.enter_key);

    // Find all the views on the page
    mKeyEntryField = (EditText) findViewById(R.id.key_value);    
    mStatusText = (TextView) findViewById(R.id.status_text);
    mSubmitButton = (Button) findViewById(R.id.submit_button);
    mCancelButton = (Button) findViewById(R.id.cancel_button);
    mAccountName = (EditText) findViewById(R.id.account_name);
    mType = (Spinner) findViewById(R.id.type_choice);
    
    ArrayAdapter<CharSequence> types = ArrayAdapter.createFromResource(this, 
        R.array.type, android.R.layout.simple_spinner_item);
    types.setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item);
    mType.setAdapter(types);

    // Set listeners
    mSubmitButton.setOnClickListener(this);
    mCancelButton.setOnClickListener(this);
    mKeyEntryField.addTextChangedListener(this);
  }
  
  /*
   * Return key entered by user, replacing visually similar characters 1 and 0.
   */
  private String getEnteredKey() {
    String enteredKey = mKeyEntryField.getText().toString();
    return enteredKey.replaceAll("1", "I").replaceAll("0", "O");
  }
  
  /*
   * Either return a check code or an error message
   */
  private boolean validateKeyAndUpdateStatus(boolean submitting) {
    String userEnteredKey = getEnteredKey();
    try {
      byte[] decoded = Base32String.decode(userEnteredKey);
      if (decoded.length < MIN_KEY_BYTES) {
        // If the user is trying to submit a key that's too short, then
        // display a message saying it's too short.
        mStatusText.setText(submitting ?
            getString(R.string.enter_key_too_short) : "");
        mStatusText.setTextColor(Color.RED);
        return false;
      } else {
        mStatusText.setText("");  // Blank out the status.
        mStatusText.setTextColor(Color.WHITE);
        return true;
      }
    } catch (DecodingException e) {
      mStatusText.setText(e.getMessage());
      mStatusText.setTextColor(Color.RED);
      return false;
    }
  }

  public void onClick(View view) {
    if (view == mSubmitButton) {
      if (validateKeyAndUpdateStatus(true)) {
        AuthenticatorActivity.saveSecret(this,
            mAccountName.getText().toString(), 
            getEnteredKey(),
            null,
            mType.getSelectedItemPosition(),
            AccountDb.DEFAULT_COUNTER);
        finish();
      }
    } else if (view == mCancelButton) {
      finish(); 
    }
  }
  
  /**
   * {@inheritDoc}
   */
  public void afterTextChanged(Editable userEnteredValue) {
    validateKeyAndUpdateStatus(false);
  }

  /**
   * {@inheritDoc}
   */
  public void beforeTextChanged(CharSequence arg0, int arg1, int arg2, int arg3) {
    // Do nothing
  }

  /**
   * {@inheritDoc}
   */
  public void onTextChanged(CharSequence arg0, int arg1, int arg2, int arg3) {
    // Do nothing
  }
}
