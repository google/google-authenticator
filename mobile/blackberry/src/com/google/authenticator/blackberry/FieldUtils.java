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

import net.rim.device.api.ui.Field;
import net.rim.device.api.ui.Manager;
import net.rim.device.api.ui.component.NullField;

/**
 * Utility methods for using BlackBerry {@link Field Fields}.
 */
public class FieldUtils {
  
  public static boolean isVisible(Field field) {
    return field.getManager() != null;
  }

  /**
   * BlackBerry {@link Field Fields} do not support invisibility, so swap in an
   * invisible placeholder to simulate invisibility.
   * <p>
   * The placeholder field is stored with {@link Field#setCookie(Object)}.
   * <p>
   * The non-placeholder field must be added to a {@link Manager} before marking
   * is as <em>invisible</em> so that the implementation knows where to insert
   * the placeholder.
   * 
   * @param field
   *          the field to toggle.
   * @param visible
   *          the new visibility.
   */
  public static void setVisible(Field field, boolean visible) {
    NullField peer = (NullField) field.getCookie();
    if (visible && !isVisible(field)) {
      if (peer == null) {
        throw new IllegalStateException("Placeholder missing");
      }
      Manager manager = peer.getManager();
      manager.replace(peer, field);
    } else if (!visible && isVisible(field)) {
      if (peer == null) {
        peer = new NullField();
        field.setCookie(peer);
      }
      Manager manager = field.getManager();
      manager.replace(field, peer);
    }
  }

  FieldUtils() {
  }
}
