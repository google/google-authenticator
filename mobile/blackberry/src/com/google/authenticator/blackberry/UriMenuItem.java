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
import net.rim.device.api.system.ApplicationManager;
import net.rim.device.api.system.ApplicationManagerException;
import net.rim.device.api.system.CodeModuleManager;
import net.rim.device.api.ui.MenuItem;

import com.google.authenticator.blackberry.resource.AuthenticatorResource;

/**
 * A context menu item for shared secret URLs found in other applications (such
 * as the SMS app).
 */
public class UriMenuItem extends MenuItem implements AuthenticatorResource {

  private static ResourceBundle sResources = ResourceBundle.getBundle(
      BUNDLE_ID, BUNDLE_NAME);

  private String mUri;

  public UriMenuItem(String uri) {
    super(sResources, ENTER_KEY_MENU_ITEM, 5, 5);
    mUri = uri;
  }

  /**
   * {@inheritDoc}
   */
  public void run() {
    try {
      ApplicationManager manager = ApplicationManager.getApplicationManager();
      int moduleHandle = CodeModuleManager
          .getModuleHandleForClass(AuthenticatorApplication.class);
      String moduleName = CodeModuleManager.getModuleName(moduleHandle);
      manager.launch(moduleName + "?uri&" + Uri.encode(mUri));
    } catch (ApplicationManagerException e) {
      e.printStackTrace();
    }
  }
}
