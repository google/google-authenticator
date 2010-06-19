// Copyright (C) 2009 Google Inc.

package com.google.android.apps.authenticator;

import android.app.AlarmManager;
import android.app.PendingIntent;
import android.app.Service;
import android.appwidget.AppWidgetManager;
import android.appwidget.AppWidgetProvider;
import android.content.BroadcastReceiver;
import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.database.Cursor;
import android.os.IBinder;
import android.os.SystemClock;
import android.util.Log;
import android.view.View;
import android.widget.RemoteViews;

import com.google.android.apps.authenticator.AccountDb.OtpType;


/**
 * The widget that displays the pin code for the configured accounts.
 */

public class AuthenticatorWidget extends AppWidgetProvider {

  private static final String TAG = "AuthenticatorWidget";
  
  // max length of the username in the widget
  private static int mMaxUserNameLength = 18;
  
  // Configured users
  private static String[] mUsers;
  
  // Index into mUsers
  private static int mUsersIdx;
  
  // How often the pin is updated in milliseconds.
  private static final int updatePeriod = 30000;
  
  @Override
  public void onUpdate(Context context, AppWidgetManager appWidgetManager,
      int[] appWidgetIds) {
    
    AccountDb.initialize(context);
    
    Intent intent;
    PendingIntent pendingIntent;
    RemoteViews update = new RemoteViews(context.getPackageName(), R.layout.widget_main);
   
    Log.i(TAG, "Widget updating");

    getUsers();
    mUsersIdx = 0;

    update = setupButtons(context);
    
    // fire off the background service to keep the displayed pin current.
    context.startService(new Intent(context, UserPinService.class));
    schedule(context);
    
    refreshWidget(context, update);
  }

  /**
   * Redraw the widget.
   * 
   * @param context
   * @param remoteView
   * 
   */
  private static void refreshWidget(Context context, RemoteViews remoteView) {
    ComponentName thisWidget = new ComponentName(context, AuthenticatorWidget.class); 
    AppWidgetManager appWidgetManager = AppWidgetManager.getInstance(context);
    appWidgetManager.updateAppWidget(thisWidget, remoteView);
  }
  
  /**
   * Update the configured user list.
   */
  public static void getUsers() {
    Cursor cursor = AccountDb.getNames();
    try {
      if (AccountDb.cursorIsEmpty(cursor)) {
        mUsers = new String[0];
        return;
      }

      mUsers = new String[cursor.getCount()];
      int index = cursor.getColumnIndex(AccountDb.EMAIL_COLUMN);
      for (int i = 0; i < cursor.getCount(); i++) {
        cursor.moveToPosition(i);
        mUsers[i] = cursor.getString(index);
      }
      // if user count changes, index could be invalid, so repair it
      if (mUsersIdx >= cursor.getCount()) {
        mUsersIdx = 0;
      }
    } finally {
      AccountDb.tryCloseCursor(cursor);
    }
  }
  
  /**
   * Return the number of configured users.
   * 
   * @return mUsers.length, the number of configured users.
   */
  private static int getUserCount() {
    getUsers();
    return mUsers.length;
  }
  
  private static String getCurrentPin(Context context, String user) {
    String pin = new String();
    
    OtpType type = AccountDb.getType(user);
    
    if (type == OtpType.TOTP) {
      pin = AuthenticatorActivity.computePin(
          AuthenticatorActivity.getSecret(user), null);
    } else if (type == OtpType.HOTP) {
      pin = context.getResources().getString(R.string.hotp_widget_text);
    }
    return pin;
  }
  
  /**
   * Connect the Buttons to their callbacks.
   * 
   * @param context the Context of this widget
   * @return view, the RemoteView
   */
  public static RemoteViews setupButtons(Context context) {

    RemoteViews view = new RemoteViews(context.getPackageName(), R.layout.widget_main);

    //getUsers();
    int users = getUserCount();

    Intent intent;
    PendingIntent pendingIntent;

    // Clicking on the icon opens up the main activity
    intent = new Intent(context, AuthenticatorActivity.class);
    pendingIntent = PendingIntent.getActivity(context, 0, intent, 0);
    view.setOnClickPendingIntent(R.id.authenticator_icon, pendingIntent);

    if (users < 2) {
      // if we only have one user, we can get rid of the up/down buttons and
      // reclaim screen real-estate.      
      view.setViewVisibility(R.id.button_frame, View.GONE);
      
      if (users == 0) {
        view.setTextViewText(R.id.usernameview, context.getResources().getString(
            R.string.uninitialized_widget_user));
        view.setViewVisibility(R.id.pinview, View.GONE);
        
        intent = new Intent(context, AuthenticatorActivity.class);
        pendingIntent = PendingIntent.getActivity(context, 0, intent, 0);
        view.setOnClickPendingIntent(R.id.usernameview, pendingIntent);
        return view;
      }
    } else {
      view.setViewVisibility(R.id.button_frame, View.VISIBLE);

      // Clicking up will display the previous configured user.
      intent = new Intent(context, WidgetReceiver.class);
      intent.setAction(WidgetReceiver.NEXT_USER);
      pendingIntent = PendingIntent.getBroadcast(context, 0, intent, 0);
      view.setOnClickPendingIntent(R.id.widget_up, pendingIntent);
    }

    // show the current user
    String userDisplay = getCurrentUser();
    if (userDisplay.length() > mMaxUserNameLength) {
      userDisplay = userDisplay.substring(0, mMaxUserNameLength);
    }
    view.setTextViewText(R.id.usernameview, userDisplay);
    
    String pinValue = getCurrentPin(context, getCurrentUser());
    view.setTextViewText(R.id.pinview, pinValue);
    view.setViewVisibility(R.id.pinview, View.VISIBLE);

    return view;
  }
  
  /**
   * schedule the service which will keep the pin updated.
   * 
   * @param context the Context of this widget.
   */
  private void schedule(Context context) {
    Intent intent = new Intent();
    intent.setClass(context, UserPinService.class);
    PendingIntent pendingIntent = PendingIntent.getService(context,
        0, intent, 0);
    AlarmManager alarmManager = (AlarmManager) context.getSystemService(
        Context.ALARM_SERVICE);
    alarmManager.setInexactRepeating(AlarmManager.ELAPSED_REALTIME, 
        SystemClock.elapsedRealtime(), updatePeriod, pendingIntent);
  }

  /**
   * Returns the next account to be displayed, when the up/down 
   * buttons are pushed,
   * 
   *  @param index the direction to increment
   */
  public static String getNextUser(int index) {
    mUsersIdx = (mUsersIdx + index + mUsers.length) % mUsers.length;
    return mUsers[mUsersIdx];
  }
 
  /**
   * Return the currently selected account when the account frame is
   * pressed.
   */
  public static String getCurrentUser() {
    return mUsers[mUsersIdx];
  }
  
  /**
   * The WidgetReceiver handles the widget keypress events.
   * 
   * @author pmoody@google.com (Peter Moody)
   */
  public static class WidgetReceiver extends BroadcastReceiver {

    public static final String NEXT_USER = "next_user";
    public static final String APPWIDGET_UPDATE = 
      "com.google.android.apps.authenticator.AuthenticatorWidget.APPWIDGET_UPDATE";

    @Override
    public void onReceive(Context context, Intent intent) {

      String action = intent.getAction();
      RemoteViews remoteView = new RemoteViews(context.getPackageName(), R.layout.widget_main);

      String user = null;
      String pinValue = null;
      if (NEXT_USER.equals(action)) {
        getNextUser(1);
        remoteView = setupButtons(context);
      } else if (APPWIDGET_UPDATE.equals(action)) {
        remoteView = setupButtons(context);
      }
      refreshWidget(context, remoteView);
    }
  }
  
  /**
   * The UserPinService keeps the displayed pin current
   * 
   * @author pmoody@google.com (Peter Moody)
   */
  public static class UserPinService extends Service {

    @Override
    public void onStart(Intent intent, int startId) {
      if (getUserCount() == 0) {
        stopSelf();
        return;
      }
      RemoteViews update = buildUpdate(this);
      refreshWidget(this, update);
    }
    
    private RemoteViews buildUpdate(Context context) {
      RemoteViews update = new RemoteViews(context.getPackageName(), 
          R.layout.widget_main);
      
      String user = getCurrentUser();
      String pinValue = getCurrentPin(context, user);
      update.setTextViewText(R.id.pinview, pinValue);

      return update;
    }
    
    @Override
    public IBinder onBind(Intent intent) {
      return null;
    }
  }
}
