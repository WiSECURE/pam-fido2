*This module is under development, and welcome to any contribution. Note that the contributions should be under GPLv3, which is shown in the `LICENSE` file.*

# PAM FIDO2

A PAM module using FIDO2, which enables Linux users to login (and to do much more) with a FIDO2-compatible token.

# Prerequisite

Refer to [libfido2 document](https://github.com/Yubico/libfido2/blob/master/README.adoc) to install the library.
```
sudo apt install libfido2-1 libfido2-dev libfido2-doc
```

or build it manually:

```
sudo apt install cmake pkg-config
git clone https://github.com/Yubico/libfido2
cd libfido2 && cmake -B build
sudo make -C build install
```

```
sudo apt install libpam0g-dev
```

# How to Build the module

```
make
```

# How to Setup

For example, we setup a service named 'myapp' with pam authentication:

```
# /etc/pam.d/myapp
auth	sufficient			/path/to/pam-fido2/build/pam_fido2.so
```

# How to Run Example

```
sudo apt install python3-pip
sudo pip3 install python-pam

python3 example/app-authentication/app.py
```

# Reference

* [FIDO Alliance Specifications Overview](https://fidoalliance.org/specifications/)
* [WiSECURE Technologies](https://www.wisecure-tech.com/)
* [Yubico/libfido2](https://github.com/Yubico/libfido2)
* [The Linux-PAM Guides](http://www.linux-pam.org/Linux-PAM-html/)
