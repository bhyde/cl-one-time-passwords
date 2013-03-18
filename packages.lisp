(in-package "COMMON-LISP-USER")

(defpackage "CL-HOTP"
  (:nicknames "HOTP")
  (:use "COMMON-LISP")
  (:export "*DIGITS*"
           "*HMAC-SHA-MODE*"
           "HOTP"))

(defpackage "CL-TOTP"
  (:nicknames "TOTP")
  (:use "COMMON-LISP")
  (:export "*TIME-ZERO*"
           "*TIME-STEP-IN-SECONDS*" 
           "TOTP"))
