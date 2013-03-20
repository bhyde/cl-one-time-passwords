; -*- mode:common-lisp -*-
(defsystem cl-one-time-passwords-test
  :author "Ben Hyde <bhyde@pobox.com>"
  :license "Apache 2.0"
  :description "Test cl-one-time-passwords"
  :depends-on (cl-one-time-passwords fiveam)
  :serial t
  :components ((:file "tests")))
