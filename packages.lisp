(in-package "COMMON-LISP-USER")

(defpackage "CL-HOTP"
  (:nicknames "HOTP")
  (:use "COMMON-LISP")
  (:export "*DIGITS*"
           "*HMAC-SHA-MODE*"
	   "*LOOKAHEAD-WINDOW*"
           "HOTP"
	   "VERIFY"))

(defpackage "CL-TOTP"
  (:nicknames "TOTP")
  (:use "COMMON-LISP")
  (:export "*TIME-ZERO*"
           "*TIME-STEP-IN-SECONDS*"
	   "*VERIFICATION-WINDOW-SECONDS*"
           "TOTP"
	   "VERIFY"))
