// Copyright (C) 2009 Google Inc.

package com.google.android.apps.authenticator;

import android.content.Context;
import android.os.Handler;
import android.view.LayoutInflater;
import android.view.View;
import android.view.View.OnClickListener;
import android.view.ViewGroup;
import android.widget.ArrayAdapter;
import android.widget.Button;
import android.widget.TextView;

/**
 * A tuple of user, OTP value, and type, that represents a particular user.
 * 
 * @author adhintz@google.com (Drew Hintz)
  */
class PinInfo {
  public String mPin; // calculated OTP, or a placeholder if not calculated
  public String mUser;
  public boolean mIsHotp = false; // used to see if button needs to be displayed
}

/**
 * Displays the list of users and the current OTP values.
 */
public class PinListAdapter extends ArrayAdapter<PinInfo>  {
  public static final float SCALEX_NORMAL = (float) 1.0;
  public static final float SCALEX_UNDERSCORE = (float) 0.87;
  private AuthenticatorActivity mContext;
  
  public PinListAdapter(Context context, int userRowId, PinInfo[] items) {
    super(context, userRowId, items);
    mContext = (AuthenticatorActivity) context;
  }
  
  /**
   * Displays the user and OTP for the specified position. If HOTP, creates
   * button for generating the next OTP value.
   */
  @Override
  public View getView(int position, View convertView, ViewGroup parent){
   LayoutInflater inflater = mContext.getLayoutInflater();
   PinInfo currentPin = getItem(position);

   View row;
   if (AuthenticatorActivity.mAccessibilityAvailable) {
     row = inflater.inflate(R.layout.user_row, null);
   } else {
     row = inflater.inflate(R.layout.user_row_legacy, null);
   }
   TextView pinView = (TextView) row.findViewById(R.id.pin_value);
   TextView userView = (TextView) row.findViewById(R.id.current_user);
   Button buttonView = (Button) row.findViewById(R.id.next_otp);
   
   if (currentPin.mIsHotp) {
     buttonView.setVisibility(View.VISIBLE);
     ((ViewGroup) row).setDescendantFocusability(
         ViewGroup.FOCUS_BLOCK_DESCENDANTS); // makes long press work
     OnButtonClickListener clickListener = new OnButtonClickListener(mContext, row, position);
     buttonView.setOnClickListener(clickListener);
     row.setTag(clickListener);
   } else { // TOTP, so no button needed
     buttonView.setVisibility(View.GONE);
   }
   
   if (mContext.getString(R.string.empty_pin).equals(currentPin.mPin)) {
     pinView.setTextScaleX(SCALEX_UNDERSCORE); // smaller gap between underscores
   } else {
     pinView.setTextScaleX(SCALEX_NORMAL);
   }
   pinView.setText(currentPin.mPin);
   userView.setText(currentPin.mUser);
   
   return row;
  }
}

/**
 * Listener for the Button that generates the next OTP value.
 */
class OnButtonClickListener implements OnClickListener {
  private static final long NEXT_OTP_TIMEOUT_MS = 5000;
  private AuthenticatorActivity mContext;
  private View mRow;
  private int mPosition;
  public Handler mHandler = new Handler();
  private Runnable mEnableButton = new Runnable() {
    public void run() {
      Button nextOtp = (Button) mRow.findViewById(R.id.next_otp);
      nextOtp.setEnabled(true);
    }
  };
  
  OnButtonClickListener(AuthenticatorActivity context, View row, int position) {
    mContext = context;
    mRow = row;
    mPosition = position;
  }

  /**
   * {@inheritDoc}
   */
  public void onClick(View v) {
    TextView userView = (TextView) mRow.findViewById(R.id.current_user);
    TextView pinView = (TextView) mRow.findViewById(R.id.pin_value);
    Button nextOtp = (Button) mRow.findViewById(R.id.next_otp);
    nextOtp.setEnabled(false);
    mHandler.postDelayed(mEnableButton, NEXT_OTP_TIMEOUT_MS);
    String user = (String) userView.getText();
    String pin = mContext.computeAndDisplayPin(user, mPosition, true);
    pinView.setText(pin);
    pinView.setTextScaleX(PinListAdapter.SCALEX_NORMAL); // adjust to display numbers
  }
}
