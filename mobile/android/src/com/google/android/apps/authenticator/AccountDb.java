// Copyright (C) 2010 Google Inc.

package com.google.android.apps.authenticator;

import android.content.ContentValues;
import android.content.Context;
import android.database.Cursor;
import android.database.DatabaseUtils;
import android.database.sqlite.SQLiteDatabase;

/**
 * A database of email addresses and secret values
 * 
 * @author sweis@google.com (Steve Weis)
 */
public class AccountDb {
  public static final Integer DEFAULT_COUNTER = 0;  // for hotp type
  private static final String TABLE_NAME = "accounts";
  static final String ID_COLUMN = "_id";
  static final String EMAIL_COLUMN = "email";
  static final String SECRET_COLUMN = "secret";
  static final String COUNTER_COLUMN = "counter";
  static final String TYPE_COLUMN = "type";
  private static final String PATH = "databases";
  private static SQLiteDatabase DATABASE = null;
  
  /**
   * Types of secret keys. 
   */
  public enum OtpType {  // must be the same as in res/values/strings.xml:type
    TOTP (0),  // time based
    HOTP (1);  // counter based
    
    public final Integer value;  // value as stored in SQLite database
    OtpType(Integer value) {
      this.value = value;
    }
    
    public static OtpType getEnum(Integer i) {
      for (OtpType type : OtpType.values()) {
        if (type.value.equals(i)) {
          return type;
        }
      }
      
      return null;
    }
    
  }
  
  private AccountDb() {
    // Don't new me
  }

  /*
   * initialize() must be called before any other AccountDb methods can be used.
   */
  static void initialize(Context context) {
    if (DATABASE != null) {
      return;
    }
    
    DATABASE = context.openOrCreateDatabase(PATH, Context.MODE_PRIVATE, null);
    String createTableIfNeeded = String.format(
        "CREATE TABLE IF NOT EXISTS %s" +
        " (%s INTEGER PRIMARY KEY, %s TEXT NOT NULL, %s TEXT NOT NULL, " +
        " %s INTEGER DEFAULT %s, %s INTEGER)",
        TABLE_NAME, ID_COLUMN, EMAIL_COLUMN, SECRET_COLUMN, COUNTER_COLUMN, 
        DEFAULT_COUNTER, TYPE_COLUMN);
    DATABASE.execSQL(createTableIfNeeded);
  }
  
  static Cursor getNames() {
    return DATABASE.query(TABLE_NAME, null, null, null, null, null, null, null);
  }
  
  static Cursor getAccount(String email) {
    return DATABASE.query(TABLE_NAME, null, EMAIL_COLUMN + "= ?",
        new String[] {email}, null, null, null);
  }
  
  static boolean nameExists(String email) {
    Cursor cursor = getAccount(email);
    try {
      return !cursorIsEmpty(cursor);
    } finally {
      tryCloseCursor(cursor);
    }
  }
  
  static String getSecret(String email) {
    Cursor cursor = getAccount(email);
    try {
      if (!cursorIsEmpty(cursor)) {
        cursor.moveToFirst();
        return cursor.getString(cursor.getColumnIndex(SECRET_COLUMN));
      }
    } finally {
      tryCloseCursor(cursor);
    }
    return null;   
  }

  static Integer getCounter(String email) {
    Cursor cursor = getAccount(email);
    try {
      if (!cursorIsEmpty(cursor)) {
        cursor.moveToFirst();
        return cursor.getInt(cursor.getColumnIndex(COUNTER_COLUMN));
      } 
    } finally {
      tryCloseCursor(cursor);
    }
    return null;   
  }
  
  static void incrementCounter(String email) {
    ContentValues values = new ContentValues();
    values.put(EMAIL_COLUMN, email);
    Integer counter = getCounter(email);
    values.put(COUNTER_COLUMN, counter + 1);
    DATABASE.update(TABLE_NAME, values, whereClause(email), null);
  }

  static OtpType getType(String email) {
    Cursor cursor = getAccount(email);
    try {
      if (!cursorIsEmpty(cursor)) {
        cursor.moveToFirst();
        Integer value = cursor.getInt(cursor.getColumnIndex(TYPE_COLUMN));
        return OtpType.getEnum(value);
      } 
    } finally {
      tryCloseCursor(cursor);
    }
    return null;   
  }

  static void setType(String email, OtpType type) {
    ContentValues values = new ContentValues();
    values.put(EMAIL_COLUMN, email);
    values.put(TYPE_COLUMN, type.value);
    DATABASE.update(TABLE_NAME, values, whereClause(email), null);
  }

  private static String whereClause(String email) {
    return EMAIL_COLUMN + " = " + DatabaseUtils.sqlEscapeString(email);
  }
  
  static void delete(String email) {
    DATABASE.delete(TABLE_NAME, whereClause(email), null);
  }

  /**
   * Save key to database, creating a new user entry if necessary.
   * @param email the user email address. When editing, the new user email.
   * @param secret the secret key.
   * @param oldEmail If editing, the original user email, otherwise null.
   * @param type hotp vs totp
   * @param counter only important for the hotp type
   */
  static void update(String email, String secret, String oldEmail,
      Integer type, Integer counter) {
    ContentValues values = new ContentValues();
    values.put(EMAIL_COLUMN, email);
    values.put(SECRET_COLUMN, secret);
    values.put(TYPE_COLUMN, type);
    values.put(COUNTER_COLUMN, counter);
    int updated = DATABASE.update(TABLE_NAME, values, 
                                  whereClause(oldEmail), null);
    if (updated == 0) {
      DATABASE.insert(TABLE_NAME, null, values);
    }
  }
  
  /**
   * Returns true if the cursor is null, or contains no rows.
   */
  public static boolean cursorIsEmpty(Cursor c) {
    return c == null || c.getCount() == 0;
  }
  
  /**
   * Closes the cursor if it is not null and not closed.
   */
  public static void tryCloseCursor(Cursor c) {
    if (c != null && !c.isClosed()) {
      c.close();
    }
  }
}
