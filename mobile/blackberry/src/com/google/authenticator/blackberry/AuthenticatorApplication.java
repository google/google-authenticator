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

import net.rim.device.api.system.RuntimeStore;
import net.rim.device.api.ui.UiApplication;
import net.rim.device.api.util.StringPattern;
import net.rim.device.api.util.StringPatternRepository;

/**
 * Main entry point.
 */
public class AuthenticatorApplication extends UiApplication {

  public static final long FACTORY_ID = 0xdee739761f1b0a72L;

  private static boolean sInitialized;

  public static void main(String[] args) {
    if (args != null && args.length >= 1 && "startup".equals(args[0])) {
      // This entry-point is invoked when the device is rebooted.
      registerStringPattern();
    } else if (args != null && args.length >= 2 && "uri".equals(args[0])) {
      // This entry-point is invoked when the user clicks on a URI containing
      // the shared secret.
      String uriString = Uri.decode(args[1]);
      startApplication(Uri.parse(uriString));
    } else {
      // The default entry point starts the user interface.
      startApplication(null);
    }
  }

  /**
   * Registers pattern matcher so that this application can handle certain URI
   * schemes referenced in other applications.
   */
  private static void registerStringPattern() {
    if (!sInitialized) {
      RuntimeStore runtimeStore = RuntimeStore.getRuntimeStore();
      UriActiveFieldCookieFactory factory = new UriActiveFieldCookieFactory();
      runtimeStore.put(FACTORY_ID, factory);

      StringPattern pattern = new UriStringPattern();
      StringPatternRepository.addPattern(pattern);

      sInitialized = true;
    }
  }

  private static void startApplication(Uri uri) {
    UiApplication app = new AuthenticatorApplication();
    AuthenticatorScreen screen = new AuthenticatorScreen();
    app.pushScreen(screen);
    if (uri != null) {
      screen.parseSecret(uri);
      screen.refreshUserList();
    }
    app.enterEventDispatcher();
  }
}
