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

import net.rim.device.api.ui.component.ActiveFieldContext;
import net.rim.device.api.util.Factory;

/**
 * Factory for {@link UriActiveFieldCookie} instances.
 */
public class UriActiveFieldCookieFactory implements Factory {

  /**
   * {@inheritDoc}
   */
  public Object createInstance(Object initialData) {
    if (initialData instanceof ActiveFieldContext) {
      ActiveFieldContext context = (ActiveFieldContext) initialData;
      String data = (String) context.getData();
      return new UriActiveFieldCookie(data);
    }
    return null;
  }
}
