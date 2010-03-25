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

/**
 * A <em>very</em> simple re-implementation of {@code android.text.Html}.
 */
public class Html {

  /**
   * Replaces all instances of {@code target} with {@code replacement} in the
   * given {@code buffer}.
   * 
   * See unit tests for edge cases.
   * 
   * @param target
   *          the {@link String} to be replaced.
   * @param replacement
   *          the {@link String} to replace {@code target} with.
   * @param buffer
   *          the buffer in which to perform the replacements.
   * @return the number of replacements that were made.
   * @throws NullPointerException
   *           if any of the parameters are null.
   */
  private static int replace(String target, String replacement,
      StringBuffer buffer) {
    int replacementCount = 0;

    final int targetLength = target.length();
    final int replacementLength = replacement.length();
    i: for (int i = 0; i <= buffer.length() - targetLength;) {
      for (int j = 0; j < targetLength; j++) {
        if (buffer.charAt(i + j) != target.charAt(j)) {
          i++;
          continue i;
        }
      }
      buffer.delete(i, i + targetLength);
      buffer.insert(i, replacement);
      replacementCount++;
      i += replacementLength;

      if (targetLength == 0) {
        // Increment i to avoid inserting infinite replacements at this point.
        i++;
      }
    }

    return replacementCount;
  }

  /**
   * Converts a limited subset of HTML mark-up in the given text to mark-up that
   * is natively supported by this platform.
   * 
   * @param source
   *          the HTML source.
   * @return native text.
   */
  public static String fromHtml(String source) {
    StringBuffer buffer = new StringBuffer(source);
    replace("<br>", "\n", buffer);
    return buffer.toString();
  }
  
  private Html() {
  }
}
