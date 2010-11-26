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

import net.rim.device.api.i18n.ResourceBundle;
import net.rim.device.api.system.Clipboard;
import net.rim.device.api.ui.ContextMenu;
import net.rim.device.api.ui.MenuItem;
import net.rim.device.api.ui.Screen;
import net.rim.device.api.ui.UiApplication;
import net.rim.device.api.ui.component.Dialog;
import net.rim.device.api.ui.component.ListField;
import net.rim.device.api.ui.component.ListFieldCallback;

import com.google.authenticator.blackberry.resource.AuthenticatorResource;

/**
 * BlackBerry port of {@code PinListAdapter}.
 */
public class PinListField extends ListField implements AuthenticatorResource {

  private static ResourceBundle sResources = ResourceBundle.getBundle(
      BUNDLE_ID, BUNDLE_NAME);

  /**
   * {@inheritDoc}
   */
  public int moveFocus(int amount, int status, int time) {
    invalidate(getSelectedIndex());
    return super.moveFocus(amount, status, time);
  }

  /**
   * {@inheritDoc}
   */
  public void onUnfocus() {
    super.onUnfocus();
    invalidate();
  }

  /**
   * {@inheritDoc}
   */
  protected void makeContextMenu(ContextMenu contextMenu) {
    super.makeContextMenu(contextMenu);
    ListFieldCallback callback = getCallback();
    final int selectedIndex = getSelectedIndex();
    final PinInfo item = (PinInfo) callback.get(this, selectedIndex);
    if (item.mIsHotp) {
      MenuItem hotpItem = new MenuItem(sResources, COUNTER_PIN, 0, 0) {
        public void run() {
          AuthenticatorScreen screen = (AuthenticatorScreen) getScreen();
          String user = item.mUser;
          String pin = screen.computeAndDisplayPin(user, selectedIndex, true);
          item.mPin = pin;
          invalidate(selectedIndex);
        }
      };
      contextMenu.addItem(hotpItem);
    }

    MenuItem copyItem = new MenuItem(sResources, COPY_TO_CLIPBOARD, 0, 0) {
      public void run() {
        Clipboard clipboard = Clipboard.getClipboard();
        clipboard.put(item.mPin);

        String message = sResources.getString(COPIED);
        Dialog.inform(message);
      }
    };
    MenuItem deleteItem = new MenuItem(sResources, DELETE, 0, 0) {
      public void run() {
        String message = (sResources.getString(DELETE_MESSAGE) + "\n" + item.mUser);
        int defaultChoice = Dialog.NO;
        if (Dialog.ask(Dialog.D_YES_NO, message, defaultChoice) == Dialog.YES) {
          AccountDb.delete(item.mUser);
          AuthenticatorScreen screen = (AuthenticatorScreen) getScreen();
          screen.refreshUserList();
        }
      }
    };

    contextMenu.addItem(copyItem);
    if (item.mIsHotp) {
      MenuItem checkCodeItem = new MenuItem(sResources, CHECK_CODE_MENU_ITEM, 0, 0) {
        public void run() {
          pushScreen(new CheckCodeScreen(item.mUser));
        }
      };
      contextMenu.addItem(checkCodeItem);
    }
    contextMenu.addItem(deleteItem);
  }

  void pushScreen(Screen s) {
    Screen screen = getScreen();
    UiApplication app = (UiApplication) screen.getApplication();
    app.pushScreen(s);
  }
}
