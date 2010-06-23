// Copyright (C) 2010 Google Inc.

package com.google.android.apps.authenticator;

import android.view.accessibility.AccessibilityEvent;
import android.widget.ListView;

import java.util.List;

/**
 * Wraps AccessibilityEvent for backwards compatibility with Android versions 
 * earlier than 1.6. For more details see
 * http://android-developers.blogspot.com/2009/04/backward-compatibility-for-android.html 
 *  
 * @author adhintz@google.com (Drew Hintz)
 */

public class WrapAccessibilityEvent {
  private AccessibilityEvent mInstance;
  
  /* class initialization fails when this throws an exception */
  static {
    try {
      Class.forName("android.view.accessibility.AccessibilityEvent");
    } catch (ClassNotFoundException e) {
      throw new RuntimeException(e);
    }
  }
  
  /* calling here forces class initialization */
  public static void checkAvailable() {}
  
  public static final int TYPE_VIEW_SELECTED = AccessibilityEvent.TYPE_VIEW_SELECTED;

  public void setClassName(String name) {
    mInstance.setClassName(name);
  }

  public void setPackageName(String packageName) {
    mInstance.setPackageName(packageName);
  }

  public List<CharSequence> getText() {
    return mInstance.getText();
  }
  
  public static void sendEvent(ListView mUserList, int eventType) {
    mUserList.sendAccessibilityEvent(eventType);
  }
  
}
