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
 * Encodes arbitrary byte arrays as case-insensitive base-32 strings using
 *  the legacy encoding scheme.
 */

public class Base32Legacy extends Base32String {
  // 32 alpha-numeric characters. Excluding 0, 1, O, and I
  private static final Base32Legacy INSTANCE = 
    new Base32Legacy("23456789ABCDEFGHJKLMNPQRSTUVWXYZ");

  static Base32String getInstance() {
    return INSTANCE;
  }

  protected Base32Legacy(String alphabet) {
    super(alphabet);
  }
  
  public static byte[] decode(String encoded) throws DecodingException {
    return getInstance().decodeInternal(encoded);
  }

  public static String encode(byte[] data) {
    return getInstance().encodeInternal(data);
  } 
}