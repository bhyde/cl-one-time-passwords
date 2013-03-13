(defsystem cl-otp
  :depends-on (ironclad)
  :components ((:file "packages")
               (:file "hotc")
               (:file "totc")))
