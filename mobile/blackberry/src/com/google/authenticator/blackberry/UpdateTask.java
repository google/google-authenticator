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

import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.Reader;

import javax.microedition.io.Connector;
import javax.microedition.io.HttpConnection;

import net.rim.device.api.i18n.Locale;
import net.rim.device.api.system.Application;
import net.rim.device.api.system.ApplicationDescriptor;
import net.rim.device.api.system.ApplicationManager;
import net.rim.device.api.system.Branding;
import net.rim.device.api.system.DeviceInfo;

/**
 * Checks for software updates and invokes a callback if one is found.
 */
public class UpdateTask extends Thread {

  private static String getApplicationVersion() {
    ApplicationDescriptor app = ApplicationDescriptor
        .currentApplicationDescriptor();
    return app.getVersion();
  }

  private static String getPlatformVersion() {
    ApplicationManager manager = ApplicationManager.getApplicationManager();
    ApplicationDescriptor[] applications = manager.getVisibleApplications();
    for (int i = 0; i < applications.length; i++) {
      ApplicationDescriptor application = applications[i];
      String moduleName = application.getModuleName();
      if (moduleName.equals("net_rim_bb_ribbon_app")) {
        return application.getVersion();
      }
    }
    return null;
  }

  private static String getUserAgent() {
    String deviceName = DeviceInfo.getDeviceName();
    String version = getPlatformVersion();
    String profile = System.getProperty("microedition.profiles");
    String configuration = System.getProperty("microedition.configuration");
    String applicationVersion = getApplicationVersion();
    int vendorId = Branding.getVendorId();
    return "BlackBerry" + deviceName + "/" + version + " Profile/" + profile
        + " Configuration/" + configuration + " VendorID/" + vendorId
        + " Application/" + applicationVersion;
  }
  
  private static String getLanguage() {
    Locale locale = Locale.getDefault();
    return locale.getLanguage();
  }

  private static String getEncoding(HttpConnection c) throws IOException {
    String enc = "ISO-8859-1";
    String contentType = c.getHeaderField("Content-Type");
    if (contentType != null) {
      String prefix = "charset=";
      int beginIndex = contentType.indexOf(prefix);
      if (beginIndex != -1) {
        beginIndex += prefix.length();
        int endIndex = contentType.indexOf(';', beginIndex);
        if (endIndex != -1) {
          enc = contentType.substring(beginIndex, endIndex);
        } else {
          enc = contentType.substring(beginIndex);
        }
      }
    }
    return enc.trim();
  }

  private static HttpConnection connect(String url) throws IOException {
    if (DeviceInfo.isSimulator()) {
      url += ";deviceside=true";
    } else {
      url += ";deviceside=false;ConnectionType=mds-public";
    }
    return (HttpConnection) Connector.open(url);
  }

  private final UpdateCallback mCallback;

  public UpdateTask(UpdateCallback callback) {
    if (callback == null) {
      throw new NullPointerException();
    }
    mCallback = callback;
  }
  
  private String getMIDletVersion(Reader reader) throws IOException {
    BufferedReader r = new BufferedReader(reader);
    String prefix = "MIDlet-Version:";
    for (String line = r.readLine(); line != null; line = r.readLine()) {
      if (line.startsWith(prefix)) {
        int beginIndex = prefix.length();
        String value = line.substring(beginIndex);
        return value.trim();
      }
    }
    return null;
  }

  /**
   * {@inheritDoc}
   */
  public void run() {
    try {
      // Visit the original download URL and read the JAD;
      // if the MIDlet-Version has changed, invoke the callback.
      String url = Build.DOWNLOAD_URL;
      String applicationVersion = getApplicationVersion();
      String userAgent = getUserAgent();
      String language = getLanguage();
      for (int redirectCount = 0; redirectCount < 10; redirectCount++) {
        HttpConnection c = null;
        InputStream s = null;
        try {
          c = connect(url);
          c.setRequestMethod(HttpConnection.GET);
          c.setRequestProperty("User-Agent", userAgent);
          c.setRequestProperty("Accept-Language", language);

          int responseCode = c.getResponseCode();
          if (responseCode == HttpConnection.HTTP_MOVED_PERM
              || responseCode == HttpConnection.HTTP_MOVED_TEMP) {
            String location = c.getHeaderField("Location");
            if (location != null) {
              url = location;
              continue;
            } else {
              throw new IOException("Location header missing");
            }
          } else if (responseCode != HttpConnection.HTTP_OK) {
            throw new IOException("Unexpected response code: " + responseCode);
          }
          s = c.openInputStream();
          String enc = getEncoding(c);
          Reader reader = new InputStreamReader(s, enc);
          final String version = getMIDletVersion(reader);
          if (version == null) {
            throw new IOException("MIDlet-Version not found");
          } else if (!version.equals(applicationVersion)) {
            Application application = Application.getApplication();
            application.invokeLater(new Runnable() {
              public void run() {
                mCallback.onUpdate(version);
              }
            });
          } else {
            // Already running latest version
          }
        } finally {
          if (s != null) {
            s.close();
          }
          if (c != null) {
            c.close();
          }
        }
      }
    } catch (Exception e) {
      System.out.println(e);
    }
  }
}
