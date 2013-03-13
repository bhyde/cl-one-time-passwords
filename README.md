# Introduction

OTP, one time passwords, provide a way to do authentication based on a shared secret without revealing that secret on the communciation channel.

Two well specified ways of generating OTPs are:
 * HOTP - An HMAC-Based One-Time Password Algorithm, i.e. RFC 4226
 * TOTP - Time-Based One-Time Password Algorithm , i.e. RFC 6238

These are commonly used as one factor in two factor authentication
systems.  For example Google uses these.  For example Google's
Authenticator App for most smart phones will generate one time
passwords once it has been configured with the shared secret(s) for
your account(s).

Cl-otp implements HOTP and TOTP in Common Lisp.

# Example

1) Load the code into your lisp image.
2) Share a secret with Google's Authenticator App on your smart phone by scanning this QDR code:
![QR Code](https://www.evernote.com/shard/s2/sh/a06dfefd-2a09-4e34-989b-3ebf421fffc0/f07c628ab49bacd1816622196521e754/res/9b7af78e-2495-4cfe-a2e2-1083fce8babe/skitch.png?resizeSmall&width=832 "otpauth://totp/test@example.com?secret=jbswy3dpehpk3pxpjbswy3dpehpk3pxp")

3) Compair the values that Authenticator is generating with the ones this code generates:
```common-lisp
  (totp:totp "48656C6C6F21DEADBEEF48656C6C6F21DEADBEEF")
```

They ought to be the same, but if your phone and computer clock are out of sync by a N seconds then every 30 seconds for N seconds they won't be the same.

That QR encodes this URL otpauth://totp/test@example.com?secret=jbswy3dpehpk3pxpjbswy3dpehpk3pxp
where the secret is the base32 encoding of the secret we passed to totp:totp in step 3, there the value was a 40 character hex number, i.e. 20 bytes.

# API

```common-lisp
hotp:*digits*
```
The number of digits to return in the htop values, defaults to six.  See the RFC for details.

```common-lisp
hotp:*hmac-sha-mode*
```
The kind of hmac to use.  This defaults to :sha1.  You can set other values
ironclad supports; but my testing currrently indicates it doesn't work.  This
isn't part of the HOTP spec, but the TOTP spec extends HTOP ... even if nobody
usest this extension.

```common-lisp
(htop:hotp <secret> <counter>)
```
<secret> is a string of 20 characters hex digits; more if your using a different hmac sha.
```common-lisp
totp:*time-zero*
```
Defaults to zero, a unix time.  See the RFC for details.
```common-lisp
totp:*time-step-in-seconds*
```
Defaults to 30, a unix time interval.  See the RFC for details.

```common-lisp
(totp:totp <secret> &optional offset unix-time)
```
<secret> as in htop:htop.  The offset defaults to zero.  The unix-time defaults
to the current unix-time.  The offset is used to get totp values nearby times
slots, it is in seconds.

# See also:
+ HOTP RFC4226 http://tools.ietf.org/html/rfc4226
+ TOTP RFC6238 http://tools.ietf.org/html/rfc6238
+ Code for Google's Authenticator App is available: https://code.google.com/p/google-authenticator/
+ Check your app store for the actuall application. [http://support.google.com/accounts/bin/answer.py?hl=en&answer=1066447 list here].

# Warning
This code as not yet been used in production.  I look forward to reports back from the field.  :)
