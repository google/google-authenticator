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
import net.rim.device.api.system.Bitmap;
import net.rim.device.api.ui.Manager;
import net.rim.device.api.ui.component.BitmapField;
import net.rim.device.api.ui.component.LabelField;
import net.rim.device.api.ui.component.RichTextField;
import net.rim.device.api.ui.container.HorizontalFieldManager;
import net.rim.device.api.ui.container.MainScreen;

import org.bouncycastle.crypto.Mac;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.params.KeyParameter;

import com.google.authenticator.blackberry.resource.AuthenticatorResource;

/**
 * BlackBerry port of {@code CheckCodeActivity}.
 */
public class CheckCodeScreen extends MainScreen implements AuthenticatorResource {

  private static final boolean SHOW_INSTRUCTIONS = false;

  private static ResourceBundle sResources = ResourceBundle.getBundle(
      BUNDLE_ID, BUNDLE_NAME);

  private RichTextField mCheckCodeTextView;
  private LabelField mCodeTextView;
  private LabelField mVersionText;
  private Manager mCodeArea;
  private String mUser;

  static String getCheckCode(String secret)
      throws Base32String.DecodingException {
    final byte[] keyBytes = Base32String.decode(secret);
    Mac mac = new HMac(new SHA1Digest());
    mac.init(new KeyParameter(keyBytes));
    PasscodeGenerator pcg = new PasscodeGenerator(mac);
    return pcg.generateResponseCode(0L);
  }

  public CheckCodeScreen(String user) {
    mUser = user;
    setTitle(sResources.getString(CHECK_CODE_TITLE));
    mCheckCodeTextView = new RichTextField();
    mCheckCodeTextView.setText(sResources.getString(CHECK_CODE));

    mCodeArea = new HorizontalFieldManager(FIELD_HCENTER);

    Bitmap bitmap = Bitmap.getBitmapResource("ic_lock_lock.png");
    BitmapField icon = new BitmapField(bitmap, FIELD_VCENTER);

    mCodeTextView = new LabelField("", FIELD_VCENTER);
    mCodeArea.add(icon);
    mCodeArea.add(mCodeTextView);

    ApplicationDescriptor applicationDescriptor = ApplicationDescriptor
        .currentApplicationDescriptor();
    String version = applicationDescriptor.getVersion();
    mVersionText = new LabelField(version, FIELD_RIGHT | FIELD_BOTTOM);

    add(mCheckCodeTextView);
    add(mCodeArea);
    add(mVersionText);
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

  private void onResume() {
    String secret = AuthenticatorScreen.getSecret(mUser);
    if (secret == null || secret.length() == 0) {
      // If the user started up this app but there is no secret key yet,
      // then tell the user to visit a web page to get the secret key.
      tellUserToGetSecretKey();
      return;
    }
    String checkCode = null;
    String errorMessage = null;
    try {
      checkCode = getCheckCode(secret);
    } catch (RuntimeException e) {
      errorMessage = sResources.getString(GENERAL_SECURITY_EXCEPTION);
    } catch (Base32String.DecodingException e) {
      errorMessage = sResources.getString(DECODING_EXCEPTION);
    }
    if (errorMessage != null) {
      mCheckCodeTextView.setText(errorMessage);
      FieldUtils.setVisible(mCheckCodeTextView, true);
      FieldUtils.setVisible(mCodeArea, false);
    } else {
      mCodeTextView.setText(checkCode);
      String checkCodeMessage = sResources.getString(CHECK_CODE);
      mCheckCodeTextView.setText(checkCodeMessage);
      FieldUtils.setVisible(mCheckCodeTextView, SHOW_INSTRUCTIONS);
      FieldUtils.setVisible(mCodeArea, true);
    }
  }

  /**
   * Tells the user to visit a web page to get a secret key.
   */
  private void tellUserToGetSecretKey() {
    String message = sResources.getString(NOT_INITIALIZED);
    mCheckCodeTextView.setText(message);
    FieldUtils.setVisible(mCheckCodeTextView, true);
    FieldUtils.setVisible(mCodeArea, false);
  }
}
