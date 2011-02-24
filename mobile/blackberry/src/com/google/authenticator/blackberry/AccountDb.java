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

import java.util.Hashtable;
import java.util.Vector;

import com.google.authenticator.blackberry.resource.AuthenticatorResource;

import net.rim.device.api.i18n.ResourceBundle;
import net.rim.device.api.system.CodeModuleManager;
import net.rim.device.api.system.CodeSigningKey;
import net.rim.device.api.system.ControlledAccess;
import net.rim.device.api.system.PersistentObject;
import net.rim.device.api.system.PersistentStore;

/**
 * BlackBerry port of {@code AccountDb}.
 */
public class AccountDb {
  private static final String TABLE_NAME = "accounts";
  static final String ID_COLUMN = "_id";
  static final String EMAIL_COLUMN = "email";
  static final String SECRET_COLUMN = "secret";
  static final String COUNTER_COLUMN = "counter";
  static final String TYPE_COLUMN = "type";
  static final Integer TYPE_LEGACY_TOTP = new Integer(-1); // TODO: remove April 2010

  private static final long PERSISTENT_STORE_KEY = 0x9f1343901e600bf7L;

  static Hashtable sPreferences;

  static PersistentObject sPersistentObject;

  /**
   * Types of secret keys.
   */
  public static class OtpType {
    private static ResourceBundle sResources = ResourceBundle.getBundle(
    		AuthenticatorResource.BUNDLE_ID, AuthenticatorResource.BUNDLE_NAME);
    
    public static final OtpType TOTP = new OtpType(0); // time based
    public static final OtpType HOTP = new OtpType(1); // counter based

    private static final OtpType[] values = { TOTP, HOTP };

    public final Integer value; // value as stored in database

    OtpType(int value) {
      this.value = new Integer(value);
    }

    public static OtpType getEnum(Integer i) {
      for (int index = 0; index < values.length; index++) {
        OtpType type = values[index];
        if (type.value.intValue() == i.intValue()) {
          return type;
        }
      }
      return null;
    }
    
    public static OtpType[] values() {
      return values;
    }
    
    /**
     * {@inheritDoc}
     */
    public String toString() {
      if (this == TOTP) {
        return sResources.getString(AuthenticatorResource.TOTP);
      } else if (this == HOTP) {
        return sResources.getString(AuthenticatorResource.HOTP);
      } else {
        return super.toString();
      }
    }
  }

  private AccountDb() {
    // Don't new me
  }

  static {
    sPersistentObject = PersistentStore.getPersistentObject(PERSISTENT_STORE_KEY);
    sPreferences = (Hashtable) sPersistentObject.getContents();
    if (sPreferences == null) {
      sPreferences = new Hashtable();
    }
    // Use an instance of a class owned by this application
    // to easily get the appropriate CodeSigningKey:
    Object appObject = new FieldUtils();
    
    // Get the public code signing key
    CodeSigningKey codeSigningKey = CodeSigningKey.get(appObject);
    if (codeSigningKey == null) {
      throw new SecurityException("Code not protected by a signing key");
    }
    
    // Ensure that the code has been signed with the corresponding private key
    int moduleHandle = CodeModuleManager.getModuleHandleForObject(appObject);
    if (!ControlledAccess.verifyCodeModuleSignature(moduleHandle, codeSigningKey)) {
      String signerId = codeSigningKey.getSignerId();
      throw new SecurityException("Code not signed by " + signerId + " key");
    }
    
    Object contents = sPreferences;
    
    // Only allow signed applications to access user data
    contents = new ControlledAccess(contents, codeSigningKey);
    
    sPersistentObject.setContents(contents);
    sPersistentObject.commit();
  }

  private static Vector getAccounts() {
    Vector accounts = (Vector) sPreferences.get(TABLE_NAME);
    if (accounts == null) {
      accounts = new Vector(10);
      sPreferences.put(TABLE_NAME, accounts);
      sPersistentObject.commit();
    }
    return accounts;
  }

  private static Hashtable getAccount(String email) {
    if (email == null) {
      throw new NullPointerException();
    }
    Vector accounts = getAccounts();
    for (int i = 0, n = accounts.size(); i < n; i++) {
      Hashtable account = (Hashtable) accounts.elementAt(i);
      if (email.equals(account.get(EMAIL_COLUMN))) {
        return account;
      }
    }
    return null;
  }

  static String[] getNames() {
    Vector accounts = getAccounts();
    int size = accounts.size();
    String[] names = new String[size];
    for (int i = 0; i < size; i++) {
      Hashtable account = (Hashtable) accounts.elementAt(i);
      names[i] = (String) account.get(EMAIL_COLUMN);
    }
    return names;
  }

  static boolean nameExists(String email) {
    Hashtable account = getAccount(email);
    return account != null;
  }

  static String getSecret(String email) {
    Hashtable account = getAccount(email);
    return account != null ? (String) account.get(SECRET_COLUMN) : null;
  }

  static Integer getCounter(String email) {
    Hashtable account = getAccount(email);
    return account != null ? (Integer) account.get(COUNTER_COLUMN) : null;
  }

  static void incrementCounter(String email) {
    Hashtable account = getAccount(email);
    if (account != null) {
      Integer counter = (Integer) account.get(COUNTER_COLUMN);
      counter = new Integer(counter.intValue() + 1);
      account.put(COUNTER_COLUMN, counter);
      sPersistentObject.commit();
    }
  }

  static OtpType getType(String user) {
    Hashtable account = getAccount(user);
    if (account != null) {
      Integer value = (Integer) account.get(TYPE_COLUMN);
      return OtpType.getEnum(value);
    } else {
      return null;
    }
  }

  static void delete(String email) {
    Vector accounts = getAccounts();
    boolean modified = false;
    for (int index = 0; index < accounts.size();) {
      Hashtable account = (Hashtable) accounts.elementAt(index);
      if (email.equals(account.get(EMAIL_COLUMN))) {
        accounts.removeElementAt(index);
        modified = true;
      } else {
        index++;
      }
    }
    if (modified) {
      sPersistentObject.commit();
    }
  }

  /**
   * Save key to database, creating a new user entry if necessary.
   * @param email the user email address. When editing, the new user email.
   * @param secret the secret key.
   * @param oldEmail If editing, the original user email, otherwise null.
   */
  static void update(String email, String secret, String oldEmail,
      AccountDb.OtpType type) {
    Hashtable account = oldEmail != null ? getAccount(oldEmail) : null;
    if (account == null) {
      account = new Hashtable(10);
      Vector accounts = getAccounts();
      accounts.addElement(account);
    }
    account.put(EMAIL_COLUMN, email);
    account.put(SECRET_COLUMN, secret);
    account.put(TYPE_COLUMN, type.value);
    if (!account.containsKey(COUNTER_COLUMN)) {
      account.put(COUNTER_COLUMN, new Integer(0));
    }
    sPersistentObject.commit();
  }
}
