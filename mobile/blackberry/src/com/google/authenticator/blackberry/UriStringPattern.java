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

import net.rim.device.api.util.AbstractString;
import net.rim.device.api.util.StringPattern;

/**
 * Searches for URIs matching one of the following:
 * 
 * <pre>
 * https://www.google.com/accounts/KeyProv?user=username#secret
 * totp://username@domain#secret  
 * otpauth://totp/user@example.com?secret=FFF...
 * otpauth://hotp/user@example.com?secret=FFF...&amp;counter=123
 * </pre>
 * 
 * <strong>Important Note:</strong> HTTP/HTTPS URIs may be ignored by the
 * platform because they are already handled by the browser.
 */
public class UriStringPattern extends StringPattern {

  /**
   * A list of URI prefixes that should be matched.
   */
  private static final String[] PREFIXES = {
      "https://www.google.com/accounts/KeyProv?", "totp://", "otpauth://totp/",
      "otpauth://hotp/" };

  public UriStringPattern() {
  }

  /**
   * {@inheritDoc}
   */
  public boolean findMatch(AbstractString str, int beginIndex, int maxIndex,
      StringPattern.Match match) {
    prefixes: for (int i = 0; i < PREFIXES.length; i++) {
      String prefix = PREFIXES[i];
      if (maxIndex - beginIndex < prefix.length()) {
        continue prefixes;
      }

      characters: for (int a = beginIndex; a < maxIndex; a++) {
        for (int b = 0; b < prefix.length(); b++) {
          if (str.charAt(a + b) != prefix.charAt(b)) {
            continue characters;
          }
        }
        int uriStart = a;
        while (a < maxIndex && !isWhitespace(str.charAt(a))) {
          a++;
        }
        int uriEnd = a;
        
        match.id = AuthenticatorApplication.FACTORY_ID;
        match.beginIndex = uriStart;
        match.endIndex = uriEnd;
        match.prefixLength = 0;
        return true;
      }
    }
    return false;
  }
}