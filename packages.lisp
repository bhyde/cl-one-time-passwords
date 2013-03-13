(in-package "COMMON-LISP-USER")

(defpackage "CL-HOTP"
  (:nicknames "HOTP")
  (:export "*DIGITS*"
           "*HMAC-SHA-MODE*"
           "HOTP"))

(defpackage "CL-TOTP"
  (:nicknames "TOTP")
  (:export "*TIME-ZERO*"
           "*TIME-STEP-IN-SECONDS*" 
           "TOTP"))
