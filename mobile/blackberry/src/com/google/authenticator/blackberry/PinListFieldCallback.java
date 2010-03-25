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

import net.rim.device.api.system.Bitmap;
import net.rim.device.api.ui.Font;
import net.rim.device.api.ui.Graphics;
import net.rim.device.api.ui.component.ListField;
import net.rim.device.api.ui.component.ListFieldCallback;

/**
 * A tuple of user, OTP value, and type, that represents a particular user.
 */
class PinInfo {
  public String mPin; // calculated OTP, or a placeholder if not calculated
  public String mUser;
  public boolean mIsHotp = false; // used to see if button needs to be displayed
}

/**
 * BlackBerry port of {@code PinListAdapter}.
 */
public class PinListFieldCallback implements ListFieldCallback {

  private static final int PADDING = 4;

  private final Font mUserFont;
  private final Font mPinFont;
  private final Bitmap mIcon;
  private final int mRowHeight;

  private final PinInfo[] mItems;

  public PinListFieldCallback(PinInfo[] items) {
    super();
    mItems = items;
    mUserFont = Font.getDefault().derive(Font.ITALIC);
    mPinFont = Font.getDefault();
    mIcon = Bitmap.getBitmapResource("ic_lock_lock.png");
    mRowHeight = computeRowHeight();
  }

  private int computeRowHeight() {
    int textHeight = mUserFont.getHeight() + mPinFont.getHeight();
    int iconHeight = mIcon.getHeight();
    return PADDING + Math.max(textHeight, iconHeight) + PADDING;
  }

  public int getRowHeight() {
    return mRowHeight;
  }

  /**
   * {@inheritDoc}
   */
  public void drawListRow(ListField listField, Graphics graphics, int index,
      int y, int width) {
    PinInfo item = mItems[index];
    
    int iconWidth = mIcon.getWidth();
    int iconHeight = mIcon.getHeight();
    int iconX = width - PADDING - iconWidth; 
    int iconY = y + Math.max(0, (mRowHeight - iconHeight) / 2);
    graphics.drawBitmap(iconX, iconY, iconWidth, iconHeight, mIcon, 0, 0);
    
    int textWidth = Math.max(0, width - iconWidth - PADDING * 3);
    int textX = PADDING;
    int textY = y + PADDING;
    int flags = Graphics.ELLIPSIS;
    Font savedFont = graphics.getFont();
    graphics.setFont(mUserFont);
    graphics.drawText(item.mUser, textX, textY, flags, textWidth);
    textY += mUserFont.getHeight();
    graphics.setFont(mPinFont);
    graphics.drawText(item.mPin, textX, textY, flags, textWidth);
    graphics.setFont(savedFont);
  }

  /**
   * {@inheritDoc}
   */
  public Object get(ListField listField, int index) {
    return mItems[index];
  }

  /**
   * {@inheritDoc}
   */
  public int getPreferredWidth(ListField listField) {
    return Integer.MAX_VALUE;
  }

  /**
   * {@inheritDoc}
   */
  public int indexOfList(ListField listField, String prefix, int start) {
    for (int i = start; i < mItems.length; i++) {
      PinInfo item = mItems[i];
      // Check if username starts with prefix (ignoring case)
      if (item.mUser.regionMatches(true, 0, prefix, 0, prefix.length())) {
        return i;
      }
    }
    return -1;
  }
}
