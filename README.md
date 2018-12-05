# Google Authenticator OpenSource

The Google Authenticator project includes implementations of one-time passcode
generators for several mobile platforms. One-time passcodes are generated using
open standards developed by the
[Initiative for Open Authentication (OATH)](http://www.openauthentication.org/)
(which is unrelated to [OAuth](http://oauth.net/)).

This GitHub project is specifically for the Google Authenticator apps which
target the Blackberry and iOS mobile platforms.

Other related Google Authenticator opensource projects can be found as noted
below:
- [Android app](https://github.com/google/google-authenticator-android).
- [Pluggable Authentication Module](https://github.com/google/google-authenticator-libpam), aka PAM.

There are **no account backups** in any of the apps by design.

These apps are not on the app stores, and their code has diverged from what's in
the app stores, so patches here won't necessarily show up in those versions.

These implementations support the HMAC-Based One-time Password (HOTP) algorithm
specified in [RFC 4226](https://tools.ietf.org/html/rfc4226) and the Time-based
One-time Password (TOTP) algorithm specified
in [RFC 6238](https://tools.ietf.org/html/rfc6238).

Further documentation is available in
the [Wiki](https://github.com/google/google-authenticator/wiki).
