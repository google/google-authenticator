## Building a Google-Authenticator RPM

Please note the RPM does not require QR-Encode as a dependency,
As technically the module builds fine without it. But in all likely-
hood you will need it in an actual deployment. Building a QR-Encode
RPM is outside the scope of this documentation, see the in-repo
documentation for instructions. https://github.com/fukuchi/libqrencode

If you are using RPMs in your testing a new build number option has
been added to the spec file IE: --define '_release #' to where # is
a build number. This will generate a RPM in the  namespace:
google-authenticator-1.01-#.el6.x86_64.rpm where # is your specified
build number. If no _release is set the build is defaulted to 1.
Example:

```
rpmbuild -ba contrib/rpm.spec --define '_release 8'
```

This will generate an rpm of:

```
google-authenticator-1.01-8.el6.x86_64.rpm
```

### Requirements

  * gcc
  * libtool
  * autoconf
  * automake
  * libpam-devel
  * rpm-builder
  * qr-encode (optional)


### Process

```shell
git clone https://github.com/google/google-authenticator.git
cd google-authenticator/libpam
./bootstrap.sh
./configure
make dist
cp google-autheticator-#.##.tar.gz ~/rpmbuild/SOURCES/
rpmbuild -ba contrib/rpm.spec
```
