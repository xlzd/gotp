# GOTP - The Golang One-Time Password Library

[![build-status][build-status]][build-status] ![MIT License][license-badge]

GOTP is a Golang package for generating and verifying one-time passwords. It can be used to implement two-factor (2FA) or multi-factor (MFA) authentication methods in anywhere that requires users to log in.

Open MFA standards are defined in [RFC 4226][RFC 4226] (HOTP: An HMAC-Based One-Time Password Algorithm) and in [RFC 6238][RFC 6238] (TOTP: Time-Based One-Time Password Algorithm). GOTP implements server-side support for both of these standards.

GOTP was inspired by [PyOTP][PyOTP].


## Installation

```
$ go get github.com/xlzd/gotp
```

## Usage

Check API docs at https://godoc.org/github.com/xlzd/gotp

### Time-based OTPs

```
totp := gotp.NewDefaultTOTP("4S62BZNFXXSZLCRO")
otp.Now()  // current otp '123456'
otp.At(1524486261)  // otp of timestamp 1524486261 '123456'

# OTP verified for a given timestamp
totp.Verify('492039', 1524486261)  // true
totp.Verify('492039', 1520000000)  // false

// generate a provisioning uri
totp.ProvisioningUri("demoAccountName", "issuerName") // otpauth://totp/issuerName:demoAccountName?secret=4S62BZNFXXSZLCRO&issuer=issuerName
```

### Counter-based OTPs

```
hotp := gotp.NewDefaultHOTP("4S62BZNFXXSZLCRO")
hotp.At(0)  // '944181'
hotp.At(1)  // '770975'

# OTP verified for a given timestamp
hotp.Verify('944181', 0)  // true
hotp.Verify('944181', 1)  // false

// generate a provisioning uri
hotp.ProvisioningUri("demoAccountName", "issuerName", 1) // otpauth://hotp/issuerName:demoAccountName?secret=4S62BZNFXXSZLCRO&counter=1&issuer=issuerName
```

# License

GOTP is licensed under the [MIT License][License]


[build-status]: https://travis-ci.org/xlzd/gotp.svg?branch=master
[license-badge]:   https://img.shields.io/badge/license-MIT-000000.svg
[RFC 4226]: https://tools.ietf.org/html/rfc4226 "RFC 4226"
[RFC 6238]: https://tools.ietf.org/html/rfc6238 "RFC 6238"
[PyOTP]: https://github.com/pyotp/pyotp
[License]: https://github.com/xlzd/gotp/blob/master/LICENSE
