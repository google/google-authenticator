/*-
 * Copyright 2010 Google Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy of
 * the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under
 * the License.
 */

package com.google.authenticator.blackberry;

import net.rim.blackberry.api.browser.Browser;
import net.rim.blackberry.api.browser.BrowserSession;
import net.rim.device.api.i18n.ResourceBundle;
import net.rim.device.api.system.Alert;
import net.rim.device.api.system.Application;
import net.rim.device.api.system.ApplicationDescriptor;
import net.rim.device.api.ui.MenuItem;
import net.rim.device.api.ui.Screen;
import net.rim.device.api.ui.UiApplication;
import net.rim.device.api.ui.component.LabelField;
import net.rim.device.api.ui.component.Menu;
import net.rim.device.api.ui.component.RichTextField;
import net.rim.device.api.ui.container.MainScreen;

import org.bouncycastle.crypto.Mac;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.params.KeyParameter;

import com.google.authenticator.blackberry.AccountDb.OtpType;
import com.google.authenticator.blackberry.Base32String.DecodingException;
import com.google.authenticator.blackberry.resource.AuthenticatorResource;

/**
 * BlackBerry port of {@code AuthenticatorActivity}.
 */
public class AuthenticatorScreen extends MainScreen implements UpdateCallback,
    AuthenticatorResource, Runnable {
  
  private static ResourceBundle sResources = ResourceBundle.getBundle(
      BUNDLE_ID, BUNDLE_NAME);

  private static final int VIBRATE_DURATION = 200;
  
  private static final long REFRESH_INTERVAL = 30 * 1000;

  private static final boolean AUTO_REFRESH = true;
  
  private static final String TERMS_URL = "http://www.google.com/accounts/TOS";
  
  private static final String PRIVACY_URL = "http://www.google.com/mobile/privacy.html";

  /**
   * Computes the one-time PIN given the secret key.
   * 
   * @param secret
   *          the secret key
   * @return the PIN
   * @throws GeneralSecurityException
   * @throws DecodingException
   *           If the key string is improperly encoded.
   */
  public static String computePin(String secret, Long counter) {
    try {
      final byte[] keyBytes = Base32String.decode(secret);
      Mac mac = new HMac(new SHA1Digest());
      mac.init(new KeyParameter(keyBytes));
      PasscodeGenerator pcg = new PasscodeGenerator(mac);
      if (counter == null) { // time-based totp
        return pcg.generateTimeoutCode();
      } else { // counter-based hotp
        return pcg.generateResponseCode(counter.longValue());
      }
    } catch (RuntimeException e) {
      return "General security exception";
    } catch (DecodingException e) {
      return "Decoding exception";
    }
  }

  /**
   * Parses a secret value from a URI. The format will be:
   * 
   * <pre>
   * https://www.google.com/accounts/KeyProv?user=username#secret 
   *   OR
   * totp://username@domain#secret  
   * otpauth://totp/user@example.com?secret=FFF...
   * otpauth://hotp/user@example.com?secret=FFF...&amp;counter=123
   * </pre>
   * 
   * @param uri The URI containing the secret key
   */
  void parseSecret(Uri uri) {
    String scheme = uri.getScheme().toLowerCase();
    String path = uri.getPath();
    String authority = uri.getAuthority();
    String user = DEFAULT_USER;
    String secret;
    AccountDb.OtpType type = AccountDb.OtpType.TOTP;
    Integer counter = new Integer(0); // only interesting for HOTP
    if (OTP_SCHEME.equals(scheme)) {
      if (authority != null && authority.equals(TOTP)) {
        type = AccountDb.OtpType.TOTP;
      } else if (authority != null && authority.equals(HOTP)) {
        type = AccountDb.OtpType.HOTP;
        String counterParameter = uri.getQueryParameter(COUNTER_PARAM);
        if (counterParameter != null) {
          counter = Integer.valueOf(counterParameter);
        }
      }
      
      if (path != null && path.length() > 1) {
        user = path.substring(1); // path is "/user", so remove leading /
      }
      
      secret = uri.getQueryParameter(SECRET_PARAM);
      // TODO: remove TOTP scheme
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
    
    if (secret == null) {
      // Secret key not found in URI
      return;
    }
    
    // TODO: April 2010 - remove version parameter handling.
    String version = uri.getQueryParameter(VERSION_PARAM);
    if (version == null) { // version is null for legacy URIs
      try {
        secret = Base32String.encode(Base32Legacy.decode(secret));
      } catch (DecodingException e) {
        // Error decoding legacy key from URI
        e.printStackTrace();
      }
    }
    
    if (!secret.equals(getSecret(user)) ||
        counter != AccountDb.getCounter(user) ||
        type != AccountDb.getType(user)) {
      saveSecret(user, secret, null, type);
      mStatusText.setText(sResources.getString(SECRET_SAVED));
    }
  }
  
  static String getSecret(String user) {
    return AccountDb.getSecret(user);
  }

  static void saveSecret(String user, String secret, 
      String originalUser, AccountDb.OtpType type) {
    if (originalUser == null) {
      originalUser = user;
    }
    if (secret != null) {
      AccountDb.update(user, secret, originalUser, type);
      Alert.startVibrate(VIBRATE_DURATION);
    }
  }

  private LabelField mVersionText;
  private LabelField mStatusText;
  private RichTextField mEnterPinTextView;
  private PinListField mUserList;
  private PinListFieldCallback mUserAdapter;
  private PinInfo[] mUsers = {};
  private boolean mUpdateAvailable;
  private int mTimer = -1;
  
  static final String DEFAULT_USER = "Default account";
  private static final String OTP_SCHEME = "otpauth";
  private static final String TOTP = "totp"; // time-based
  private static final String HOTP = "hotp"; // counter-based
  private static final String USER_PARAM = "user";
  private static final String SECRET_PARAM = "secret";
  private static final String VERSION_PARAM = "v";
  private static final String COUNTER_PARAM = "counter";

  public AuthenticatorScreen() {
    setTitle(sResources.getString(APP_NAME));
    // LabelField cannot scroll content that is bigger than the screen,
    // so use RichTextField instead.
    mEnterPinTextView = new RichTextField(sResources.getString(ENTER_PIN));

    mUserList = new PinListField();
    mUserAdapter = new PinListFieldCallback(mUsers);
    setAdapter();

    ApplicationDescriptor applicationDescriptor = ApplicationDescriptor
        .currentApplicationDescriptor();
    String version = applicationDescriptor.getVersion();
    mVersionText = new LabelField(version, FIELD_RIGHT | FIELD_BOTTOM);
    mStatusText = new LabelField("", FIELD_HCENTER | FIELD_BOTTOM);

    add(mEnterPinTextView);
    add(mUserList);
    add(new LabelField(" ")); // One-line spacer
    add(mStatusText);
    add(mVersionText);

    FieldUtils.setVisible(mEnterPinTextView, false);
    
    UpdateCallback callback = this;
    new UpdateTask(callback).start();
  }
  
  private void setAdapter() {
    int lastIndex = mUserList.getSelectedIndex();
    mUserList.setCallback(mUserAdapter);
    mUserList.setSize(mUsers.length);
    mUserList.setRowHeight(mUserAdapter.getRowHeight());
    mUserList.setSelectedIndex(lastIndex);
  }

  /**
   * {@inheritDoc}
   */
  protected void onDisplay() {
    super.onDisplay();
    onResume();
  }

  /**
   * {@inheritDoc}
   */
  protected void onExposed() {
    super.onExposed();
    onResume();
  }
  
  /**
   * {@inheritDoc}
   */
  protected void onObscured() {
    onPause();
    super.onObscured();
  }

  private void onResume() {
    refreshUserList();
    if (AUTO_REFRESH) {
      startTimer();
    }
  }

  private void onPause() {
    if (isTimerSet()) {
      stopTimer();
    }
  }
  
  private boolean isTimerSet() {
    return mTimer != -1;
  }
  
  private void startTimer() {
    if (isTimerSet()) {
      stopTimer();
    }
    Application application = getApplication();
    Runnable runnable = this;
    boolean repeat = true;
    mTimer = application.invokeLater(runnable, REFRESH_INTERVAL, repeat);
  }
  
  private void stopTimer() {
    if (isTimerSet()) {
      Application application = getApplication();
      application.cancelInvokeLater(mTimer);
      mTimer = -1;
    }
  }
  
  /**
   * {@inheritDoc}
   */
  public void run() {
    refreshUserList();
  }
  
  void refreshUserList() {
    String[] cursor = AccountDb.getNames();
    if (cursor.length > 0) {
      if (mUsers.length != cursor.length) {
        mUsers = new PinInfo[cursor.length];
      }
      for (int i = 0; i < cursor.length; i++) {
        String user = cursor[i];
        computeAndDisplayPin(user, i, false);
      }
      mUserAdapter = new PinListFieldCallback(mUsers);
      setAdapter(); // force refresh of display

      if (!FieldUtils.isVisible(mUserList)) {
        mEnterPinTextView.setText(sResources.getString(ENTER_PIN));
        FieldUtils.setVisible(mEnterPinTextView, true);
        FieldUtils.setVisible(mUserList, true);
      }
    } else {
      // If the user started up this app but there is no secret key yet,
      // then tell the user to visit a web page to get the secret key.
      mUsers = new PinInfo[0]; // clear any existing user PIN state
      tellUserToGetSecretKey();
    }
  }

  /**
   * Tells the user to visit a web page to get a secret key.
   */
  private void tellUserToGetSecretKey() {
    // TODO: fill this in with code to send our phone number to the server
    String notInitialized = sResources.getString(NOT_INITIALIZED);
    mEnterPinTextView.setText(notInitialized);
    FieldUtils.setVisible(mEnterPinTextView, true);
    FieldUtils.setVisible(mUserList, false);
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
  String computeAndDisplayPin(String user, int position, boolean computeHotp) {
    OtpType type = AccountDb.getType(user);
    String secret = getSecret(user);
    PinInfo currentPin;
    if (mUsers[position] != null) {
      currentPin = mUsers[position]; // existing PinInfo, so we'll update it
    } else {
      currentPin = new PinInfo();
      currentPin.mPin = sResources.getString(EMPTY_PIN);
    }
    
    currentPin.mUser = user;
    if (type == OtpType.TOTP) {
      currentPin.mPin = computePin(secret, null);
    } else if (type == OtpType.HOTP) {
      currentPin.mIsHotp = true;
      if (computeHotp) {
        AccountDb.incrementCounter(user);
        Integer counter = AccountDb.getCounter(user);
        currentPin.mPin = computePin(secret, new Long(counter.longValue()));
      }
    }
    mUsers[position] = currentPin;
    return currentPin.mPin;
  }

  private void pushScreen(Screen screen) {
    UiApplication app = (UiApplication) getApplication();
    app.pushScreen(screen);
  }

  /**
   * {@inheritDoc}
   */
  public Menu getMenu(int instance) {
    if (instance == Menu.INSTANCE_CONTEXT) {
      // Show the full menu instead of the context menu 
      return super.getMenu(Menu.INSTANCE_DEFAULT);
    } else {
      return super.getMenu(instance);
    }
  }
  
  /**
   * {@inheritDoc}
   */
  protected void makeMenu(Menu menu, int instance) {
    super.makeMenu(menu, instance);
    MenuItem enterKeyItem = new MenuItem(sResources, ENTER_KEY_MENU_ITEM, 0, 0) {
      public void run() {
        pushScreen(new EnterKeyScreen());
      }
    };
    MenuItem termsItem = new MenuItem(sResources, TERMS_MENU_ITEM, 0, 0) {
      public void run() {
        BrowserSession session = Browser.getDefaultSession();
        session.displayPage(TERMS_URL);
      }
    };
    MenuItem privacyItem = new MenuItem(sResources, PRIVACY_MENU_ITEM, 0, 0) {
      public void run() {
        BrowserSession session = Browser.getDefaultSession();
        session.displayPage(PRIVACY_URL);
      }
    };
    menu.add(enterKeyItem);
    if (!isTimerSet()) {
      MenuItem refreshItem = new MenuItem(sResources, REFRESH_MENU_ITEM, 0, 0) {
        public void run() {
          refreshUserList();
        }
      };
      menu.add(refreshItem);
    }
    if (mUpdateAvailable) {
      MenuItem updateItem = new MenuItem(sResources, UPDATE_NOW, 0, 0) {
        public void run() {
          BrowserSession session = Browser.getDefaultSession();
          session.displayPage(Build.DOWNLOAD_URL);
          mStatusText.setText("");
        }
      };
      menu.add(updateItem);
    }
    menu.add(termsItem);
    menu.add(privacyItem);
  }

  /**
   * {@inheritDoc}
   */
  public void onUpdate(String version) {
    String status = sResources.getString(UPDATE_AVAILABLE) + ": " + version;
    mStatusText.setText(status);
    mUpdateAvailable = true;
  }
}
