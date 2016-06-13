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

import java.util.Hashtable;

/**
 * Encodes arbitrary byte arrays as case-insensitive base-32 strings  
 */
public class Base32String {
  // singleton
  
  private static final Base32String INSTANCE = 
    new Base32String("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"); // RFC 4648/3548

  static Base32String getInstance() { 
    return INSTANCE;
  }
  
  // 32 alpha-numeric characters.
  private String ALPHABET;
  private char[] DIGITS;
  private int MASK;
  private int SHIFT;
  private Hashtable CHAR_MAP;

  static final String SEPARATOR = "-";

  protected Base32String(String alphabet) {
    this.ALPHABET = alphabet;
    DIGITS = ALPHABET.toCharArray();
    MASK = DIGITS.length - 1;
    SHIFT = numberOfTrailingZeros(DIGITS.length);
    CHAR_MAP = new Hashtable();
    for (int i = 0; i < DIGITS.length; i++) {
      CHAR_MAP.put(new Character(DIGITS[i]), new Integer(i));
    }
  }

  /**
   * Counts the number of 1 bits in the specified integer; this is also
   * referred to as population count.
   *
   * @param i
   *            the integer to examine.
   * @return the number of 1 bits in {@code i}.
   */
  private static int bitCount(int i) {
      i -= ((i >> 1) & 0x55555555);
      i = (i & 0x33333333) + ((i >> 2) & 0x33333333);
      i = (((i >> 4) + i) & 0x0F0F0F0F);
      i += (i >> 8);
      i += (i >> 16);
      return (i & 0x0000003F);
  }

  /**
   * Determines the number of trailing zeros in the specified integer after
   * the {@link #lowestOneBit(int) lowest one bit}.
   *
   * @param i
   *            the integer to examine.
   * @return the number of trailing zeros in {@code i}.
   */
  private static int numberOfTrailingZeros(int i) {
      return bitCount((i & -i) - 1);
  }

  public static byte[] decode(String encoded) throws DecodingException {
    return getInstance().decodeInternal(encoded);
  }
  
  private static String canonicalize(String str) {
    int length = str.length();
    StringBuffer buffer = new StringBuffer();
    for (int i = 0; i < length; i++) {
      char c = str.charAt(i);
      if (SEPARATOR.indexOf(c) == -1 && c != ' ') {
        buffer.append(Character.toUpperCase(c));
      }
    }
    return buffer.toString().trim();
  }

  protected byte[] decodeInternal(String encoded) throws DecodingException {
    // Remove whitespace and separators
    encoded = canonicalize(encoded);
    // Canonicalize to all upper case
    encoded = encoded.toUpperCase();
    if (encoded.length() == 0) {
      return new byte[0];
    }
    int encodedLength = encoded.length();
    int outLength = encodedLength * SHIFT / 8;
    byte[] result = new byte[outLength];
    int buffer = 0;
    int next = 0;
    int bitsLeft = 0;
    for (int i = 0, n = encoded.length(); i < n; i++) {
      Character c = new Character(encoded.charAt(i));
      if (!CHAR_MAP.containsKey(c)) {
        throw new DecodingException("Illegal character: " + c);
      }
      buffer <<= SHIFT;
      buffer |= ((Integer) CHAR_MAP.get(c)).intValue() & MASK;
      bitsLeft += SHIFT;
      if (bitsLeft >= 8) {
        result[next++] = (byte) (buffer >> (bitsLeft - 8));
        bitsLeft -= 8;
      }
    }
    // We'll ignore leftover bits for now. 
    // 
    // if (next != outLength || bitsLeft >= SHIFT) {
    //  throw new DecodingException("Bits left: " + bitsLeft);
    // }
    return result;
  }

  public static String encode(byte[] data) {
    return getInstance().encodeInternal(data);
  }

  protected String encodeInternal(byte[] data) {
    if (data.length == 0) {
      return "";
    }

    // SHIFT is the number of bits per output character, so the length of the
    // output is the length of the input multiplied by 8/SHIFT, rounded up.
    if (data.length >= (1 << 28)) {
      // The computation below will fail, so don't do it.
      throw new IllegalArgumentException();
    }

    int outputLength = (data.length * 8 + SHIFT - 1) / SHIFT;
    StringBuffer result = new StringBuffer(outputLength);

    int buffer = data[0];
    int next = 1;
    int bitsLeft = 8;
    while (bitsLeft > 0 || next < data.length) {
      if (bitsLeft < SHIFT) {
        if (next < data.length) {
          buffer <<= 8;
          buffer |= (data[next++] & 0xff);
          bitsLeft += 8;
        } else {
          int pad = SHIFT - bitsLeft;
          buffer <<= pad;
          bitsLeft += pad;
        }
      }
      int index = MASK & (buffer >> (bitsLeft - SHIFT));
      bitsLeft -= SHIFT;
      result.append(DIGITS[index]);
    }
    return result.toString();
  }
  
  static class DecodingException extends Exception {
    public DecodingException(String message) {
      super(message);
    }
  }
}
