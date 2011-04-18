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
import net.rim.device.api.system.ApplicationDescriptor;
import net.rim.device.api.ui.Color;
import net.rim.device.api.ui.Field;
import net.rim.device.api.ui.FieldChangeListener;
import net.rim.device.api.ui.Graphics;
import net.rim.device.api.ui.component.ButtonField;
import net.rim.device.api.ui.component.EditField;
import net.rim.device.api.ui.component.LabelField;
import net.rim.device.api.ui.component.ObjectChoiceField;
import net.rim.device.api.ui.container.HorizontalFieldManager;
import net.rim.device.api.ui.container.MainScreen;
import net.rim.device.api.ui.container.VerticalFieldManager;

import com.google.authenticator.blackberry.AccountDb.OtpType;
import com.google.authenticator.blackberry.resource.AuthenticatorResource;

/**
 * BlackBerry port of {@code EnterKeyActivity}.
 */
public class EnterKeyScreen extends MainScreen implements AuthenticatorResource,
    FieldChangeListener {

  private static ResourceBundle sResources = ResourceBundle.getBundle(
      BUNDLE_ID, BUNDLE_NAME);

  private static final int MIN_KEY_BYTES = 10;

  private static final boolean INTEGRITY_CHECK_ENABLED = false;

  private LabelField mDescriptionText;
  private LabelField mStatusText;
  private LabelField mVersionText;
  private EditField mAccountName;
  private EditField mKeyEntryField;
  private ObjectChoiceField mType;
  private ButtonField mClearButton;
  private ButtonField mSubmitButton;
  private ButtonField mCancelButton;

  private int mStatusColor;

  public EnterKeyScreen() {
    setTitle(sResources.getString(ENTER_KEY_TITLE));
    VerticalFieldManager manager = new VerticalFieldManager();
    mDescriptionText = new LabelField(sResources.getString(ENTER_KEY_HELP));
    mAccountName = new EditField(EditField.NO_NEWLINE);
    mAccountName.setLabel(sResources.getString(ENTER_ACCOUNT_LABEL));
    mKeyEntryField = new EditField(EditField.NO_NEWLINE);
    mKeyEntryField.setLabel(sResources.getString(ENTER_KEY_LABEL));
    mType = new ObjectChoiceField(sResources.getString(TYPE_PROMPT), OtpType
        .values());
    mStatusText = new LabelField() {
      protected void paint(Graphics graphics) {
        int savedColor = graphics.getColor();
        graphics.setColor(mStatusColor);
        super.paint(graphics);
        graphics.setColor(savedColor);
      }
    };
    mKeyEntryField.setChangeListener(this);
    manager.add(mDescriptionText);
    manager.add(new LabelField()); // Spacer
    manager.add(mAccountName);
    manager.add(mKeyEntryField);
    manager.add(mStatusText);
    manager.add(mType);

    HorizontalFieldManager buttons = new HorizontalFieldManager(FIELD_HCENTER);
    mSubmitButton = new ButtonField(sResources.getString(SUBMIT),
        ButtonField.CONSUME_CLICK);
    mClearButton = new ButtonField(sResources.getString(CLEAR),
        ButtonField.CONSUME_CLICK);
    mCancelButton = new ButtonField(sResources.getString(CANCEL),
        ButtonField.CONSUME_CLICK);
    mSubmitButton.setChangeListener(this);
    mClearButton.setChangeListener(this);
    mCancelButton.setChangeListener(this);
    buttons.add(mSubmitButton);
    buttons.add(mClearButton);
    buttons.add(mCancelButton);

    ApplicationDescriptor applicationDescriptor = ApplicationDescriptor
        .currentApplicationDescriptor();
    String version = applicationDescriptor.getVersion();
    mVersionText = new LabelField(version, FIELD_RIGHT | FIELD_BOTTOM);
    add(manager);
    add(buttons);
    add(mVersionText);
  }

  /*
   * Either return a check code or an error message
   */
  private boolean validateKeyAndUpdateStatus(boolean submitting) {
    String userEnteredKey = mKeyEntryField.getText();
    try {
      byte[] decoded = Base32String.decode(userEnteredKey);
      if (decoded.length < MIN_KEY_BYTES) {
        // If the user is trying to submit a key that's too short, then
        // display a message saying it's too short.
        mStatusText.setText(submitting ? sResources.getString(ENTER_KEY_VALUE_TOO_SHORT) : "");
        mStatusColor = Color.BLACK;
        return false;
      } else {
        if (INTEGRITY_CHECK_ENABLED) {
          String checkCode = CheckCodeScreen.getCheckCode(mKeyEntryField.getText());
          mStatusText.setText(sResources.getString(ENTER_KEY_INTEGRITY_CHECK_VALUE) + checkCode);
          mStatusColor = Color.GREEN;
        } else {
          mStatusText.setText("");
        }
        return true;
      }
    } catch (Base32String.DecodingException e) {
      mStatusText.setText(sResources.getString(ENTER_KEY_INVALID_FORMAT));
      mStatusColor = Color.RED;
      return false;
    } catch (RuntimeException e) {
      mStatusText.setText(sResources.getString(ENTER_KEY_UNEXPECTED_PROBLEM));
      mStatusColor = Color.RED;
      return false;
    }
  }

  /**
   * {@inheritDoc}
   */
  public void fieldChanged(Field field, int context) {
    if (field == mSubmitButton) {
      if (validateKeyAndUpdateStatus(true)) {
        AuthenticatorScreen.saveSecret(mAccountName.getText(), mKeyEntryField
            .getText(), null, (OtpType) mType.getChoice(mType
            .getSelectedIndex()));
        close();
      }
    } else if (field == mClearButton) {
      mStatusText.setText("");
      mAccountName.setText("");
      mKeyEntryField.setText("");
    } else if (field == mCancelButton) {
      close();
    } else if (field == mKeyEntryField) {
      validateKeyAndUpdateStatus(false);
    }
  }

  /**
   * {@inheritDoc}
   */
  protected boolean onSavePrompt() {
    // Disable prompt when the user hits the back button
    return false;
  }
}
