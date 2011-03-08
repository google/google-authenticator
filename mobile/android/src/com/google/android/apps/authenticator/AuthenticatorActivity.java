// Copyright (C) 2009 Google Inc.

package com.google.android.apps.authenticator;

import com.google.android.apps.authenticator.AccountDb.OtpType;
import com.google.android.apps.authenticator.Base32String.DecodingException;

import android.app.Activity;
import android.app.AlertDialog;
import android.content.ActivityNotFoundException;
import android.content.Context;
import android.content.DialogInterface;
import android.content.Intent;
import android.content.pm.PackageManager.NameNotFoundException;
import android.database.Cursor;
import android.net.Uri;
import android.os.Bundle;
import android.os.Handler;
import android.os.Vibrator;
import android.text.ClipboardManager;
import android.text.Html;
import android.text.method.LinkMovementMethod;
import android.util.Log;
import android.view.ContextMenu;
import android.view.ContextMenu.ContextMenuInfo;
import android.view.Menu;
import android.view.MenuInflater;
import android.view.MenuItem;
import android.view.View;
import android.view.View.OnClickListener;
import android.view.ViewGroup;
import android.widget.AdapterView;
import android.widget.AdapterView.AdapterContextMenuInfo;
import android.widget.AdapterView.OnItemClickListener;
import android.widget.Button;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.ListView;
import android.widget.TextView;
import android.widget.Toast;

import java.security.GeneralSecurityException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * The main activity that displays usernames and codes
 * 
 * @author sweis@google.com (Steve Weis)
 * @author adhintz@google.com (Drew Hintz)
 */
public class AuthenticatorActivity extends Activity implements OnClickListener {

  private static AuthenticatorActivity SINGLETON; // used only by saveSecret 
  
  /** The tag for log messages */
  static final String TAG = "Authenticator";
  private static final long VIBRATE_DURATION = 200L;

  private TextView mStatusText;
  private TextView mEnterPinTextView;
  private ListView mUserList;
  private PinListAdapter mUserAdapter;
  private PinInfo[] mUsers = {};
  private Button mScanBarcodeButton;
  private Button mEnterKeyButton;
  private LinearLayout mButtonsLayout;
  private Handler mHandler;

  private Runnable mRefreshTask;

  public static boolean mAccessibilityAvailable;
  private static String mVersion;
  
  static {
    try {
      WrapAccessibilityEvent.checkAvailable();
      mAccessibilityAvailable = true;
    } catch (VerifyError e) {
      mAccessibilityAvailable = false;
    }
  }

  static final String DEFAULT_USER = "Default account";
  private static final String OTP_SCHEME = "otpauth";
  private static final String TOTP = "totp"; // time-based
  private static final String HOTP = "hotp"; // counter-based
  private static final String USER_PARAM = "user";
  private static final String SECRET_PARAM = "secret";
  private static final String COUNTER_PARAM = "counter";
  private static final int CHECK_KEY_VALUE_ID = 0;
  private static final int RENAME_ID = 1;
  private static final int DELETE_ID = 2;
  private static final int COPY_TO_CLIPBOARD_ID = 3;
  private static final int SCAN_REQUEST = 31337;
  private static final String ZXING_MARKET = 
    "market://search?q=pname:com.google.zxing.client.android";
  private static final String ZXING_DIRECT = 
    "https://zxing.googlecode.com/files/BarcodeScanner3.1.apk";
  private static final String OPEN_SOURCE_URI =
    "http://code.google.com/p/google-authenticator/";
  private static final String TERMS_URI = "http://www.google.com/accounts/TOS";
  private static final String PRIVACY_URI =
    "http://www.google.com/mobile/privacy.html";
  
  // Based on default OTP interval, but set to update more frequently to avoid stale codes.
  private static final int REFRESH_INTERVAL_SEC = PasscodeGenerator.INTERVAL / 3;
  
  
  /** Called when the activity is first created. */
  @Override
  public void onCreate(Bundle savedInstanceState) {
    super.onCreate(savedInstanceState);
    SINGLETON = this;
    AccountDb.initialize(this);
    setContentView(R.layout.main);

    // restore state on screen rotation
    Object savedState = getLastNonConfigurationInstance();
    if (savedState != null) {
      mUsers = (PinInfo[]) savedState;
    }

    mUserList = (ListView) findViewById(R.id.user_list);
    mStatusText = (TextView) findViewById(R.id.status_text);
    mScanBarcodeButton = (Button) findViewById(R.id.scan_barcode_button);
    mScanBarcodeButton.setOnClickListener(this);
    mEnterKeyButton = (Button) findViewById(R.id.enter_key_button);
    mEnterKeyButton.setOnClickListener(this);
    mButtonsLayout = (LinearLayout) findViewById(R.id.main_buttons);
    mButtonsLayout.setVisibility(View.GONE);
    mEnterPinTextView = (TextView) findViewById(R.id.enter_pin);
    mEnterPinTextView.setVisibility(View.GONE);
    
    mUserList.setVisibility(View.GONE);
    if (mAccessibilityAvailable) {
      mUserAdapter = new PinListAdapter(this, R.layout.user_row, mUsers);
    } else {
      mUserAdapter = new PinListAdapter(this, R.layout.user_row_legacy, mUsers);
    }
    mUserList.setAdapter(mUserAdapter);
    mUserList.setOnItemClickListener(new OnItemClickListener(){
    	@Override
        public void onItemClick(AdapterView<?> arg0, View row, int arg2, long arg3) {
            OnButtonClickListener clickListener = (OnButtonClickListener) row.getTag();
            Button nextOtp = (Button) row.findViewById(R.id.next_otp);
            if ((clickListener != null) && nextOtp.isEnabled()){
                clickListener.onClick(row);
            }
            if (mAccessibilityAvailable) {
              WrapAccessibilityEvent.sendEvent(mUserList, 
                  WrapAccessibilityEvent.TYPE_VIEW_SELECTED);
            }
        }
    });

    try {
      mVersion =
        getPackageManager().getPackageInfo(getPackageName(), 0).versionName;
    } catch (NameNotFoundException e) {
      mVersion = "Unknown";
    }

    // Create the handler used for processing refresh tasks.
    mHandler = new Handler();
  }

  @Override
  public Object onRetainNonConfigurationInstance() {
    return mUsers;  // save state of users and currently displayed PINs
  }

  @Override
  protected void onResume() {
    super.onResume();
    Log.i(TAG, "onResume");
    Intent intent = getIntent();
    Uri uri = intent.getData();

    // If this activity was started by the user clicking on a link, then
    // we should fetch the secret key from the given URL.
    if (uri != null) {
      parseSecret(uri);
      setIntent(new Intent());
    }

    // Schedule the automatic refresh task.
    Runnable task = new Runnable() {
      @Override
      public void run() {
        // This task perpetuates itself by scheduling for another round of
        // execution using the same handler on main activity.
        // Before continuing execution, we verify that it is still current
        // for the activity-- if the activity is stopped/restarted,
        // a task object will scheduled and this one allowed to expire.
        if (mRefreshTask == this) {
          AuthenticatorActivity.this.refreshUserList();
          mHandler.postDelayed(this, REFRESH_INTERVAL_SEC * 1000);
        }        
      }
    };

    // Kick-start the refresh loop by running the task once.
    mRefreshTask = task;
    mRefreshTask.run();
  }

  @Override
  protected void onPause() {
    super.onPause();  // Required by Android.
    mRefreshTask = null;
  }

  /** Display list of user emails and updated pin codes. */
  protected void refreshUserList() {
    refreshUserList(false);
  }

  /**
   * Display list of user emails and updated pin codes. 
   * 
   * @param isAccountModified if true, force full refresh
   */
  protected void refreshUserList(boolean isAccountModified) {

    // If the users have changed, let the (potentially running) widget know it needs to be
    // updated
    Intent intent = new Intent(AuthenticatorWidget.WidgetReceiver.APPWIDGET_UPDATE);
    intent.setClass(this, AuthenticatorWidget.WidgetReceiver.class);
    sendBroadcast(intent);

    Cursor cursor = AccountDb.getNames();
    try {
      if (!AccountDb.cursorIsEmpty(cursor)) {
        int index = cursor.getColumnIndex(AccountDb.EMAIL_COLUMN);
        if (isAccountModified || mUsers.length != cursor.getCount()) {
          mUsers = new PinInfo[cursor.getCount()];
        }
        for (int i = 0; i < cursor.getCount(); i++) {
          cursor.moveToPosition(i);
          String user = cursor.getString(index);
          Log.i(TAG, "onResume user: " + user);
          computeAndDisplayPin(user, i, false);
        }

        if (mAccessibilityAvailable) {
          mUserAdapter = new PinListAdapter(this, R.layout.user_row, mUsers);
        } else {
          mUserAdapter = new PinListAdapter(this, R.layout.user_row_legacy, mUsers);
        }
        mUserList.setAdapter(mUserAdapter); // force refresh of display

        if (mUserList.getVisibility() != View.VISIBLE) {
          mEnterPinTextView.setText(R.string.enter_pin);
          mEnterPinTextView.setVisibility(View.VISIBLE);
          mButtonsLayout.setVisibility(View.GONE);
          mUserList.setVisibility(View.VISIBLE);
          registerForContextMenu(mUserList);
        }

      } else {
        // If the user started up this app but there is no secret key yet,
        // then tell the user to visit a web page to get the secret key.
        mUsers = new PinInfo[0]; // clear any existing user PIN state 
        tellUserToGetSecretKey();
      }
    } finally {
      AccountDb.tryCloseCursor(cursor);
    }
  }

  /**
   * Tells the user to visit a web page to get a secret key.
   */
  private void tellUserToGetSecretKey() {
    String notInitialized = getString(R.string.not_initialized);
    CharSequence styledNotInitalized = Html.fromHtml(notInitialized);
    mEnterPinTextView.setText(styledNotInitalized);
    mEnterPinTextView.setMovementMethod(LinkMovementMethod.getInstance());
    mEnterPinTextView.setVisibility(View.VISIBLE);
    mButtonsLayout.setVisibility(View.VISIBLE);
    mUserList.setVisibility(View.GONE);
  }

  /**
   * Computes the PIN and saves it in mUsers. This currently runs in the UI
   * thread so it should not take more than a second or so. If necessary, we can
   * move the computation to a background thread.
   * 
   * @param user the user email to display with the PIN
   * @param position the index for the screen of this user and PIN
   * @param computeHotp true if we should increment counter and display new hotp
   * 
   * @return the generated PIN
   */
  public String computeAndDisplayPin(String user, int position, 
      boolean computeHotp) {
    OtpType type = AccountDb.getType(user);
    String secret = getSecret(user);
    PinInfo currentPin;
    if (mUsers[position] != null) {
      currentPin = mUsers[position]; // existing PinInfo, so we'll update it
    } else {
      currentPin = new PinInfo();
      currentPin.mPin = getString(R.string.empty_pin); 
    }
    
    currentPin.mUser = user;
    
    if (type == OtpType.TOTP) {
      currentPin.mPin = computePin(secret, null);
    } else if (type == OtpType.HOTP){
      currentPin.mIsHotp = true;
      if (computeHotp) {
        AccountDb.incrementCounter(user);
        Integer counter = AccountDb.getCounter(user);
        currentPin.mPin = AuthenticatorActivity.computePin(secret,
            counter.longValue());
      }
    }
    
    mUsers[position] = currentPin;
    return currentPin.mPin;
  }

  /**
   * Reads the secret key that was saved on the phone.
   * 
   * @return the secret key
   */
  static String getSecret(String user) {
    return AccountDb.getSecret(user);
  }

  /**
   * Computes the one-time PIN given the secret key.
   * 
   * @param secret the secret key
   * @param counter null if using totp, otherwise value of hotp counter
   * @return the PIN, or if error an error message
   */
  public static String computePin(String secret, Long counter) {
    if (secret == null || secret.length() == 0) {
      return "Null or empty secret";
    }
    try {
      final byte[] keyBytes = Base32String.decode(secret);
      Mac mac = Mac.getInstance("HMACSHA1");
      mac.init(new SecretKeySpec(keyBytes, ""));
      PasscodeGenerator pcg = new PasscodeGenerator(mac);
      if (counter == null) {  // time-based totp
        return pcg.generateTimeoutCode();
      } else { // counter-based hotp
        return pcg.generateResponseCode(counter);
      }
    } catch (GeneralSecurityException e) {
      return "General security exception";
    } catch (DecodingException e) {
      return "Decoding exception";
    }
          
  }

  /**
   * Parses a secret value from a URI. The format will be:
   * 
   * https://www.google.com/accounts/KeyProv?user=username#secret 
   *   OR
   * totp://username@domain#secret  
   * otpauth://totp/user@example.com?secret=FFF...
   * otpauth://hotp/user@example.com?secret=FFF...&counter=123
   * 
   * @param uri The URI containing the secret key
   */
  private void parseSecret(Uri uri) {
    String scheme = uri.getScheme().toLowerCase();
    String path = uri.getPath();
    String authority = uri.getAuthority();
    String user = DEFAULT_USER;
    String secret;
    Integer type = AccountDb.OtpType.TOTP.value;
    Integer counter = AccountDb.DEFAULT_COUNTER; // only interesting for HOTP
    if (OTP_SCHEME.equals(scheme)) {
      if (authority != null && authority.equals(TOTP)) {
        type = AccountDb.OtpType.TOTP.value;
      } else if (authority != null && authority.equals(HOTP)) {
        type = AccountDb.OtpType.HOTP.value;
        String counterParameter = uri.getQueryParameter(COUNTER_PARAM);
        if (counterParameter != null) {
          counter = Integer.parseInt(counterParameter);
        }
      }
      
      if (path != null && path.length() > 1) {
        user = path.substring(1); // path is "/user", so remove leading /
      }

      secret = uri.getQueryParameter(SECRET_PARAM);
    // TODO(adhintz) remove TOTP scheme here and in AndroidManifest.xml
    } else if (TOTP.equals(scheme)) {
      if (authority != null) {
        user = authority;
      }
      secret = uri.getFragment();
    } else {  // https://www.google.com... URI format
      String userParam = uri.getQueryParameter(USER_PARAM);
      if (userParam != null) {
        user = userParam;
      }
      secret = uri.getFragment();
    }
    
    if (secret == null || secret.length() == 0) {
      Log.e(TAG, "Secret key not found in URI");
      new AlertDialog.Builder(this)
      .setTitle(R.string.error_title)
      .setMessage(R.string.error_uri)
      .setIcon(android.R.drawable.ic_dialog_alert)
      .setPositiveButton(R.string.ok, null)
      .show();
      return;
    }
    
    if (!secret.equals(getSecret(user)) ||
        counter != AccountDb.getCounter(user) ||
        type != AccountDb.getType(user).value) {
      saveSecret(this, user, secret, null, type, counter);
      mStatusText.setText(R.string.secret_saved);
    }
  }

  /**
   * Saves the secret key to local storage on the phone.
   * 
   * @param user the user email address. When editing, the new user email.
   * @param secret the secret key
   * @param originalUser If editing, the original user email, otherwise null.
   * @param type hotp vs totp
   * @param counter only important for the hotp type
   */
  static void saveSecret(Context context, String user, String secret, 
                         String originalUser, Integer type, Integer counter) {
    // TODO(adhintz) change type to AccountDb.OtpType instead of Integer
    if (originalUser == null) {  // new user account
      originalUser = user;
    }
    String oldSecret = getSecret(user);
    if (secret != null) {
      AccountDb.update(user, secret, originalUser, type, counter);
      ((Vibrator) context.getSystemService(Context.VIBRATOR_SERVICE))
        .vibrate(VIBRATE_DURATION);
    }
    SINGLETON.refreshUserList(true);
  }

  /** Converts user list ordinal id to user email */
  private String idToEmail(long id) {
    return mUsers[(int) id].mUser;
  }

  @Override
  public void onCreateContextMenu(ContextMenu menu, View v, ContextMenuInfo menuInfo) {
    super.onCreateContextMenu(menu, v, menuInfo);
    AdapterContextMenuInfo info = (AdapterContextMenuInfo) menuInfo;
    String user = idToEmail(info.id);
    OtpType type = AccountDb.getType(user);
    menu.setHeaderTitle(user);
    menu.add(0, COPY_TO_CLIPBOARD_ID, 0, R.string.copy_to_clipboard);
    // Option to display the check-code is only available for HOTP accounts.
    if (type == OtpType.HOTP) {
      menu.add(0, CHECK_KEY_VALUE_ID, 0, R.string.check_code_menu_item);
    }
    menu.add(0, RENAME_ID, 0, R.string.rename);
    menu.add(0, DELETE_ID, 0, R.string.delete);
  }

  @Override
  public boolean onContextItemSelected(MenuItem item) {
    AdapterContextMenuInfo info = (AdapterContextMenuInfo) item.getMenuInfo();
    Intent intent;
    final String user = idToEmail(info.id); // final so listener can see value
    switch (item.getItemId()) {
      case COPY_TO_CLIPBOARD_ID:
        ClipboardManager clipboard = 
          (ClipboardManager) getSystemService(CLIPBOARD_SERVICE);
        clipboard.setText(mUsers[(int) info.id].mPin);
        return true;
      case CHECK_KEY_VALUE_ID:
        intent = new Intent(Intent.ACTION_VIEW);
        intent.setClass(this, CheckCodeActivity.class);
        intent.putExtra("user", user);
        startActivity(intent);
        return true;
      case RENAME_ID:
        final Context context = this; // final so listener can see value
        final View frame = getLayoutInflater().inflate(R.layout.rename,
            (ViewGroup) findViewById(R.id.rename_root));
        final EditText nameEdit = (EditText) frame.findViewById(R.id.rename_edittext);
        nameEdit.setText(user);
        new AlertDialog.Builder(this)
        .setTitle(String.format(getString(R.string.rename_message), user))
        .setView(frame)
        .setPositiveButton(R.string.submit,
            this.getRenameClickListener(context, user, nameEdit))
        .setNegativeButton(R.string.cancel, null)
        .show();
        return true;
      case DELETE_ID:
        new AlertDialog.Builder(this)
          .setTitle(R.string.delete_message)
          .setMessage(user)
          .setIcon(android.R.drawable.ic_dialog_alert)
          .setPositiveButton(R.string.ok,
              new DialogInterface.OnClickListener() {
                @Override
                public void onClick(DialogInterface dialog, int whichButton) {
                  AccountDb.delete(user);
                  refreshUserList();
                }
              }
          )
          .setNegativeButton(R.string.cancel, null)
          .show();
        return true;
      default:
        return super.onContextItemSelected(item);
    }
  }

  DialogInterface.OnClickListener getRenameClickListener(final Context context,
      final String user, final EditText nameEdit) {
    return new DialogInterface.OnClickListener() {
      @Override
      public void onClick(DialogInterface dialog, int whichButton) {
        String newName = nameEdit.getText().toString();
        if (newName != user) {
          if (AccountDb.nameExists(newName)) {
            Toast.makeText(context, R.string.error_exists, 15).show();
          } else {
            saveSecret(context, newName,
                getSecret(user), user, AccountDb.getType(user).value,
                AccountDb.getCounter(user));
          }
        }
      }
    };
  }
  
  @Override
  public boolean onCreateOptionsMenu(Menu menu) {
    // Inflate the menu XML resource.
    MenuInflater inflater = getMenuInflater();
    inflater.inflate(R.menu.main, menu);
    return true;
  }
  
  @Override
  public boolean onPrepareOptionsMenu(Menu menu) {
    // Do not display the Refresh button if we do not have any keys.
    if (mUserList.getVisibility() == View.GONE) {
      menu.findItem(R.id.refresh).setVisible(false);
    } else {
      menu.findItem(R.id.refresh).setVisible(true);
    }
    return true;
  }

  @Override
  public boolean onMenuItemSelected(int featureId, MenuItem item) {
    Intent intent;
    switch (item.getItemId()) {
      case R.id.enter_key_item:
        this.manuallyEnterKey();
        return true;
      case R.id.scan_barcode:
        this.scanBarcode();
        return true;
      case R.id.refresh:
        refreshUserList();
        return true;
      case R.id.about:
        new AlertDialog.Builder(this)
        .setTitle(R.string.about_menu_item)
        .setMessage(Html.fromHtml(
            String.format(getString(R.string.about_text), mVersion)))
        .setPositiveButton(R.string.ok, null)
        .show();
        return true;
      case R.id.opensource:
        intent = new Intent(Intent.ACTION_VIEW, Uri.parse(OPEN_SOURCE_URI));
        startActivity(intent);
        return true;
      case R.id.terms:
        intent = new Intent(Intent.ACTION_VIEW, Uri.parse(TERMS_URI));
        startActivity(intent);
        return true;
      case R.id.privacy:
        intent = new Intent(Intent.ACTION_VIEW, Uri.parse(PRIVACY_URI));
        startActivity(intent);
        return true;
    }

    return super.onMenuItemSelected(featureId, item);
  }
  
  @Override
  public void onActivityResult(int requestCode, int resultCode, Intent intent) {
    if (requestCode == SCAN_REQUEST && resultCode == Activity.RESULT_OK) {
      String contents = intent.getStringExtra("SCAN_RESULT");
      parseSecret(Uri.parse(contents));
    }
  }
  
  @Override
  public void onClick(View view) {
    if (view == mScanBarcodeButton) {
      this.scanBarcode();
    } else if (view == mEnterKeyButton) {
      this.manuallyEnterKey();
    }
  }
  
  private void manuallyEnterKey() {
    Intent intent = new Intent(Intent.ACTION_VIEW);
    intent.setClass(this, EnterKeyActivity.class);
    startActivity(intent);
  }

  private void scanBarcode() {
    Intent intentScan = new Intent("com.google.zxing.client.android.SCAN");
    intentScan.putExtra("SCAN_MODE", "QR_CODE_MODE");
    intentScan.putExtra("SAVE_HISTORY", false);
    try { startActivityForResult(intentScan, SCAN_REQUEST); }
    catch (ActivityNotFoundException e) { showDownloadDialog(); }
  }
  
  /**
   * Prompt to download ZXing from Market. If Market app is not installed, such 
   * as on a development phone, open the HTTPS URI for the ZXing apk.
   */
  private void showDownloadDialog() {
    new AlertDialog.Builder(this)
      .setTitle(R.string.install_dialog_title)
      .setMessage(R.string.install_dialog_message)
      .setIcon(android.R.drawable.ic_dialog_alert)
      .setPositiveButton(R.string.install_button,
          new DialogInterface.OnClickListener() {
            @Override
            public void onClick(DialogInterface dialog, int whichButton) {
              Intent intent = new Intent(Intent.ACTION_VIEW, 
                                         Uri.parse(ZXING_MARKET));
              try { startActivity(intent); }
              catch (ActivityNotFoundException e) { // if no Market app
                intent = new Intent(Intent.ACTION_VIEW,
                                    Uri.parse(ZXING_DIRECT));
                startActivity(intent);
              }
            }
          }
      )
      .setNegativeButton(R.string.cancel, null)
      .show();
  }
            
}
