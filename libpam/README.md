# Google Authenticator PAM module

Example PAM module demonstrating two-factor authentication.

## Build & install
```shell
./bootstrap.sh
./configure
make
sudo make install
```

If you don't have access to "sudo", you have to manually become "root" prior
to calling "make install".

## Setting up the PAM module for your system

For highest security, make sure that both password and OTP are being requested
even if password and/or OTP are incorrect. This means that *at least* the first
of `pam_unix.so` (or whatever other module is used to verify passwords) and
`pam_google_authenticator.so` should be set as `required`, not `requisite`. It
probably can't hurt to have both be `required`, but it could depend on the rest
of your PAM config.

If you use HOTP (counter based as opposed to time based) then add the option
`no_increment_hotp` to make sure the counter isn't incremented for failed
attempts.

Add this line to your PAM configuration file:

`  auth required pam_google_authenticator.so no_increment_hotp`

## Setting up a user

Run the `google-authenticator` binary to create a new secret key in your home
directory. These settings will be stored in `~/.google_authenticator`.

If your system supports the "libqrencode" library, you will be shown a QRCode
that you can scan using the Android "Google Authenticator" application.

If your system does not have this library, you can either follow the URL that
`google-authenticator` outputs, or you have to manually enter the alphanumeric
secret key into the Android "Google Authenticator" application.

In either case, after you have added the key, click-and-hold until the context
menu shows. Then check that the key's verification value matches (this feature
might not be available in all builds of the Android application).

Each time you log into your system, you will now be prompted for your TOTP code
(time based one-time-password) or HOTP (counter-based), depending on options
given to `google-authenticator`, after having entered your normal user id and
your normal UNIX account password.

During the initial roll-out process, you might find that not all users have
created a secret key yet. If you would still like them to be able to log
in, you can pass the "nullok" option on the module's command line:

`  auth required pam_google_authenticator.so nullok`

## Encrypted home directories

If your system encrypts home directories until after your users entered their
password, you either have to re-arrange the entries in the PAM configuration
file to decrypt the home directory prior to asking for the OTP code, or
you have to store the secret file in a non-standard location:

`  auth required pam_google_authenticator.so secret=/var/unencrypted-home/${USER}/.google_authenticator`

would be a possible choice. Make sure to set appropriate permissions. You also
have to tell your users to manually move their .google_authenticator file to
this location.

In addition to "${USER}", the `secret=` option also recognizes both "~" and
`${HOME}` as short-hands for the user's home directory.

When using the `secret=` option, you might want to also set the `user=`
option. The latter forces the PAM module to switch to a dedicated hard-coded
user id prior to doing any file operations. When using the `user=` option, you
must not include "~" or "${HOME}" in the filename.

The `user=` option can also be useful if you want to authenticate users who do
not have traditional UNIX accounts on your system.

## Module options

### secret=/path/to/secret/file

See "encrypted home directories", above.

### authtok_prompt=prompt

Overrides default token prompt. If you want to include spaces in the prompt,
wrap the whole argument in square brackets:

`  auth required pam_google_authenticator.so [authtok_prompt=Your secret token: ]`

### user=some-user

Force the PAM module to switch to a hard-coded user id prior to doing any file
operations. Commonly used with `secret=`.

### no_strict_owner

DANGEROUS OPTION!

By default the PAM module requires that the secrets file must be owned the user
logging in (or if `user=` is specified, owned by that user). This option
disables that check.

This option can be used to allow daemons not running as root to still handle
configuration files not owned by that user, for example owned by the users
themselves.

### allowed_perm=0nnn

DANGEROUS OPTION!

By default, the PAM module requires the secrets file to be readable only by the
owner of the file (mode 0600 by default). In situations where the module is used
in a non-default configuration, an administrator may need more leanient file
permissions, or a specific setting for their use case.

### debug

Enable more verbose log messages in syslog.

### try_first_pass / use_first_pass / forward_pass

Some PAM clients cannot prompt the user for more than just the password. To
work around this problem, this PAM module supports stacking. If you pass the
`forward_pass` option, the `pam_google_authenticator` module queries the user
for both the system password and the verification code in a single prompt.
It then forwards the system password to the next PAM module, which will have
to be configured with the `use_first_pass` option.

In turn, `pam_google_authenticator` module also supports both the standard
`use_first_pass` and `try_first_pass` options. But most users would not need
to set those on the `pam_google_authenticator`.

### noskewadj

If you discover that your TOTP code never works, this is most commonly the
result of the clock on your server being different from the one on your Android
device. The PAM module makes an attempt to compensate for time skew. You can
teach it about the amount of skew that you are experiencing, by trying to log
it three times in a row. Make sure you always wait 30s (but not longer), so
that you get three distinct TOTP codes.

Some administrators prefer that time skew isn't adjusted automatically, as
doing so results in a slightly less secure system configuration. If you want
to disable it, you can do so on the module command line:

`  auth required pam_google_authenticator.so noskewadj`

### no_increment_hotp

Don't increment the counter for failed HOTP attempts. This is important if log
attempts with failed passwords still get an OTP prompt.

### nullok

Allow users to log in without OTP, if they haven't set up OTP yet.

### echo_verification_code

By default, the PAM module does not echo the verification code when it is
entered by the user. In some situations, the administrator might prefer a
different behavior. Pass the `echo_verification_code` option to the module
in order to enable echoing.

If you would like verification codes that are counter based instead of
timebased, use the `google-authenticator` binary to generate a secret key in
your home directory with the proper option.  In this mode, clock skew is
irrelevant and the window size option now applies to how many codes beyond the
current one that would be accepted, to reduce synchronization problems.
