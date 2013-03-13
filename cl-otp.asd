(defsystem cl-otp
  :author "Ben Hyde <bhyde@pobox.com>"
  :license "Apache 2.0"
  :description
  "One time passwords (hotp rfc4226, totp rfc6238) as used in two factor authentication systems such as Google's."
  :depends-on (ironclad)
  :serial t
  :components ((:file "packages")
               (:file "hotp")
               (:file "totp")))
