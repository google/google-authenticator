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

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInput;
import java.io.DataInputStream;
import java.io.DataOutput;
import java.io.DataOutputStream;
import java.io.IOException;

import org.bouncycastle.crypto.Mac;

/**
 * An implementation of the HOTP generator specified by RFC 4226. Generates
 * short passcodes that may be used in challenge-response protocols or as
 * timeout passcodes that are only valid for a short period.
 *
 * The default passcode is a 6-digit decimal code and the default timeout
 * period is 5 minutes.
 */
public class PasscodeGenerator {
  /** Default decimal passcode length */
  private static final int PASS_CODE_LENGTH = 6;

  /** Default passcode timeout period (in seconds) */
  private static final int INTERVAL = 30;

  /** The number of previous and future intervals to check */
  private static final int ADJACENT_INTERVALS = 1;

  private static final int PIN_MODULO = pow(10, PASS_CODE_LENGTH);
  
  private static final int pow(int a, int b) {
    int result = 1;
    for (int i = 0; i < b; i++) {
      result *= a;
    }
    return result;
  }

  private final Signer signer;
  private final int codeLength;
  private final int intervalPeriod;

  /*
   * Using an interface to allow us to inject different signature
   * implementations.
   */
  interface Signer {
    byte[] sign(byte[] data);
  }

  /**
   * @param mac A {@link Mac} used to generate passcodes
   */
  public PasscodeGenerator(Mac mac) {
    this(mac, PASS_CODE_LENGTH, INTERVAL);
  }

  /**
   * @param mac A {@link Mac} used to generate passcodes
   * @param passCodeLength The length of the decimal passcode
   * @param interval The interval that a passcode is valid for
   */
  public PasscodeGenerator(final Mac mac, int passCodeLength, int interval) {
    this(new Signer() {
      public byte[] sign(byte[] data){
        mac.reset();
        mac.update(data, 0, data.length);
        int length = mac.getMacSize();
        byte[] out = new byte[length];
        mac.doFinal(out, 0);
        mac.reset();
        return out;
      }
    }, passCodeLength, interval);
  }

  public PasscodeGenerator(Signer signer, int passCodeLength, int interval) {
    this.signer = signer;
    this.codeLength = passCodeLength;
    this.intervalPeriod = interval;
  }

  private String padOutput(int value) {
    String result = Integer.toString(value);
    for (int i = result.length(); i < codeLength; i++) {
      result = "0" + result;
    }
    return result;
  }

  /**
   * @return A decimal timeout code
   */
  public String generateTimeoutCode() {
    return generateResponseCode(clock.getCurrentInterval());
  }

  /**
   * @param challenge A long-valued challenge
   * @return A decimal response code
   * @throws GeneralSecurityException If a JCE exception occur
   */
  public String generateResponseCode(long challenge) {
    ByteArrayOutputStream out = new ByteArrayOutputStream();
    DataOutput dout = new DataOutputStream(out);
    try {
      dout.writeLong(challenge);
    } catch (IOException e) {
      // This should never happen with a ByteArrayOutputStream
      throw new RuntimeException("Unexpected IOException");
    }
    byte[] value = out.toByteArray();
    return generateResponseCode(value);
  }

  /**
   * @param challenge An arbitrary byte array used as a challenge
   * @return A decimal response code
   * @throws GeneralSecurityException If a JCE exception occur
   */
  public String generateResponseCode(byte[] challenge) {
    byte[] hash = signer.sign(challenge);

    // Dynamically truncate the hash
    // OffsetBits are the low order bits of the last byte of the hash
    int offset = hash[hash.length - 1] & 0xF;
    // Grab a positive integer value starting at the given offset.
    int truncatedHash = hashToInt(hash, offset) & 0x7FFFFFFF;
    int pinValue = truncatedHash % PIN_MODULO;
    return padOutput(pinValue);
  }

  /**
   * Grabs a positive integer value from the input array starting at
   * the given offset.
   * @param bytes the array of bytes
   * @param start the index into the array to start grabbing bytes
   * @return the integer constructed from the four bytes in the array
   */
  private int hashToInt(byte[] bytes, int start) {
    DataInput input = new DataInputStream(
        new ByteArrayInputStream(bytes, start, bytes.length - start));
    int val;
    try {
      val = input.readInt();
    } catch (IOException e) {
      throw new IllegalStateException(String.valueOf(e));
    }
    return val;
  }

  /**
   * @param challenge A challenge to check a response against
   * @param response A response to verify
   * @return True if the response is valid
   */
  public boolean verifyResponseCode(long challenge, String response) {
    String expectedResponse = generateResponseCode(challenge);
    return expectedResponse.equals(response);
  }

  /**
   * Verify a timeout code. The timeout code will be valid for a time
   * determined by the interval period and the number of adjacent intervals
   * checked.
   *
   * @param timeoutCode The timeout code
   * @return True if the timeout code is valid
   */
  public boolean verifyTimeoutCode(String timeoutCode) {
    return verifyTimeoutCode(timeoutCode, ADJACENT_INTERVALS,
        ADJACENT_INTERVALS);
  }

  /**
   * Verify a timeout code. The timeout code will be valid for a time
   * determined by the interval period and the number of adjacent intervals
   * checked.
   *
   * @param timeoutCode The timeout code
   * @param pastIntervals The number of past intervals to check
   * @param futureIntervals The number of future intervals to check
   * @return True if the timeout code is valid
   */
  public boolean verifyTimeoutCode(String timeoutCode, int pastIntervals,
      int futureIntervals) {
    long currentInterval = clock.getCurrentInterval();
    String expectedResponse = generateResponseCode(currentInterval);
    if (expectedResponse.equals(timeoutCode)) {
      return true;
    }
    for (int i = 1; i <= pastIntervals; i++) {
      String pastResponse = generateResponseCode(currentInterval - i);
      if (pastResponse.equals(timeoutCode)) {
        return true;
      }
    }
    for (int i = 1; i <= futureIntervals; i++) {
      String futureResponse = generateResponseCode(currentInterval + i);
      if (futureResponse.equals(timeoutCode)) {
        return true;
      }
    }
    return false;
  }

  private IntervalClock clock = new IntervalClock() {
    /*
     * @return The current interval
     */
    public long getCurrentInterval() {
      long currentTimeSeconds = System.currentTimeMillis() / 1000;
      return currentTimeSeconds / getIntervalPeriod();
    }

    public int getIntervalPeriod() {
      return intervalPeriod;
    }
  };

  // To facilitate injecting a mock clock
  interface IntervalClock {
    int getIntervalPeriod();
    long getCurrentInterval();
  }
}
