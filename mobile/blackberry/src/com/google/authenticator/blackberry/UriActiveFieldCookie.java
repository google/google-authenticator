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

import java.util.Vector;

import net.rim.device.api.ui.MenuItem;
import net.rim.device.api.ui.component.ActiveFieldCookie;
import net.rim.device.api.ui.component.CookieProvider;

/**
 * Handler for input events and context menus on URLs containing shared secrets.
 */
public class UriActiveFieldCookie implements ActiveFieldCookie {
  private String mUrl;

  public UriActiveFieldCookie(String data) {
    mUrl = data;
  }

  /**
   * {@inheritDoc}
   */
  public boolean invokeApplicationKeyVerb() {
    return false;
  }

  public MenuItem getFocusVerbs(CookieProvider provider, Object context,
      Vector items) {
    items.addElement(new UriMenuItem(mUrl));
    return (MenuItem) items.elementAt(0);
  }
}
