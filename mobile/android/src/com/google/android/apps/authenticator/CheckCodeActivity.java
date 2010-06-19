// Copyright (C) 2009 Google Inc.

package com.google.android.apps.authenticator;

import android.app.Activity;
import android.content.Intent;
import android.os.Bundle;
import android.text.Html;
import android.text.TextUtils;
import android.view.View;
import android.widget.TextView;

import com.google.android.apps.authenticator.Base32String.DecodingException;

import java.security.GeneralSecurityException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * The activity that displays the integrity check value for a key.
 * The user is passed in via the extra bundle in "user".  
 * 
 * @author sweis@google.com (Steve Weis)
 */
public class CheckCodeActivity extends Activity {
  private TextView mCheckCodeTextView;
  private TextView mCodeTextView;
  private TextView mCounterValue;

  /** Called when the activity is first created. */
  @Override
  public void onCreate(Bundle savedInstanceState) {
    super.onCreate(savedInstanceState);
    setContentView(R.layout.check_code);
    mCodeTextView = (TextView) findViewById(R.id.code_value);
    mCheckCodeTextView = (TextView) findViewById(R.id.check_code);
    mCounterValue = (TextView) findViewById(R.id.counter_value);
  }

  @Override
  protected void onResume() {
    super.onResume();
    
    Intent intent = getIntent();
    Bundle extras = intent.getExtras();
    String user = extras.getString("user");

    AccountDb.OtpType type = AccountDb.getType(user);
    if (type == AccountDb.OtpType.HOTP) {
      mCounterValue.setText(AccountDb.getCounter(user).toString());
      findViewById(R.id.counter_area).setVisibility(View.VISIBLE);
    } else {
      findViewById(R.id.counter_area).setVisibility(View.GONE);
    }
    
    String secret = AuthenticatorActivity.getSecret(user);
    String checkCode = null;
    String errorMessage = null;
    try {
      checkCode = getCheckCode(secret);
    } catch (GeneralSecurityException e) {
      errorMessage = getString(R.string.general_security_exception);
    } catch (DecodingException e) {
      errorMessage = getString(R.string.decoding_exception);
    }
    if (errorMessage != null) {
      mCheckCodeTextView.setText(errorMessage);
      return;
    }
    mCodeTextView.setText(checkCode);
    String checkCodeMessage = String.format(getString(R.string.check_code),
        TextUtils.htmlEncode(user));
    CharSequence styledCheckCode = Html.fromHtml(checkCodeMessage);   
    mCheckCodeTextView.setText(styledCheckCode);
    mCheckCodeTextView.setVisibility(View.VISIBLE);
    findViewById(R.id.code_area).setVisibility(View.VISIBLE);
  }

  static String getCheckCode(String secret) throws GeneralSecurityException,
      DecodingException {
    final byte[] keyBytes = Base32String.decode(secret);
    Mac mac = Mac.getInstance("HMACSHA1");
    mac.init(new SecretKeySpec(keyBytes, ""));
    PasscodeGenerator pcg = new PasscodeGenerator(mac);
    return pcg.generateResponseCode(0L);
  }

}
