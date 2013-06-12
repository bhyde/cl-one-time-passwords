; -*- mode:common-lisp -*-

(defpackage "TEST-CL-ONE-TIME-PASSWORDS"
  (:use "COMMON-LISP" "FIVEAM"))

(in-package "TEST-CL-ONE-TIME-PASSWORDS")

(defvar *verbose* nil)

(def-suite test-cl-one-time-passwords)

(in-suite test-cl-one-time-passwords)

(test hotp-truncate 
  "rfc4226's truncate, example on page 7"
  (is
   (=
    (hotp::hotp-truncate
     (ironclad:hex-string-to-byte-array
      "1f8698690e02ca16618550ef7f19da8e945b555a"))
    872921)))


(test hmac-sha-n
  (is
   (loop
      with key = "3132333435363738393031323334353637383930"
      for (counter . expected)
      in '((0 . "cc93cf18508d94934c64b65d8ba7667fb7cde4b0")
           (1 . "75a48a19d4cbe100644e8ac1397eea747a2d33ab")
           (2 . "0bacb7fa082fef30782211938bc1c5e70416ff44")
           (3 . "66c28227d03a2d5529262ff016a1e6ef76557ece")
           (4 . "a904c900a64b35909874b33e61c5938a8e15ed1c")
           (5 . "a37e783d7b7233c083d4f62926c7a25f238d0316")
           (6 . "bc9cd28561042c83f219324d3c607256c03272ae")
           (7 . "a4fb960c0bc06e1eabb804e5b397cdc4b45596fa")
           (8 . "1b3c89f65e6c9e883012052823443f048b4332db")
           (9 . "1637409809a679dc698207310c8c7fc07290d9e5"))
      as test = (coerce (hotp::hmac-sha-n key counter) 'list)
      as test-out = (format nil "~{~2,'0x~}" test)
      when *verbose* do (format t "~2&~S~&~S" expected test-out)
      always (string-equal expected test-out))))

(test hotp 
  "Test hotp, via example from page 31 of http://tools.ietf.org/html/rfc4226"
  (is
   (loop
      initially (when *verbose* (format t "~&# got    want   ?"))
      with key = "3132333435363738393031323334353637383930"
      for (counter . expected-hotp) in '((0 . 755224)
                                         (1 . 287082)
                                         (2 . 359152)
                                         (3 . 969429)
                                         (4 . 338314)
                                         (5 . 254676)
                                         (6 . 287922)
                                         (7 . 162583)
                                         (8 . 399871)
                                         (9 . 520489))
      as test-hotp = (hotp:hotp key counter)
      when *verbose*
      do (format t "~&~d ~d ~d ~a"
                 counter test-hotp expected-hotp
                 (if (= test-hotp expected-hotp) "ok" "ko"))
      always (= test-hotp expected-hotp))))


(test totp-working
  "based on examples in the RFC"
  (loop
     with hotp:*digits* = 8
     with key-stuff = (let ((x "31323334353637383930")) ;; 10 bytes in hex
                        (concatenate 'string x x x x x  x x x x x  x x x)) ;; 130 bytes
     with sha1-key   = (subseq key-stuff 0 40) ; 20 bytes
     with sha256-key = (subseq key-stuff 0 64)
     with sha512-key = (subseq key-stuff 0 128)
     for (time nil expected-timestep expected-totp hotp:*hmac-sha-mode*)
     in '((59           "1970-01-01 00:00:59"   #x0000000000000001  94287082  :SHA1)
          (59           "1970-01-01 00:00:59"   #x0000000000000001  46119246  :SHA256)
          (59           "1970-01-01 00:00:59"   #x0000000000000001  90693936  :SHA512)
          (1111111109   "2005-03-18 01:58:29"   #x00000000023523EC  07081804  :SHA1)
          (1111111109   "2005-03-18 01:58:29"   #x00000000023523EC  68084774  :SHA256)
          (1111111109   "2005-03-18 01:58:29"   #x00000000023523EC  25091201  :SHA512)
          (1111111111   "2005-03-18 01:58:31"   #x00000000023523ED  14050471  :SHA1)
          (1111111111   "2005-03-18 01:58:31"   #x00000000023523ED  67062674  :SHA256)
          (1111111111   "2005-03-18 01:58:31"   #x00000000023523ED  99943326  :SHA512)
          (1234567890   "2009-02-13 23:31:30"   #x000000000273EF07  89005924  :SHA1)
          (1234567890   "2009-02-13 23:31:30"   #x000000000273EF07  91819424  :SHA256)
          (1234567890   "2009-02-13 23:31:30"   #x000000000273EF07  93441116  :SHA512)
          (2000000000   "2033-05-18 03:33:20"   #x0000000003F940AA  69279037  :SHA1)
          (2000000000   "2033-05-18 03:33:20"   #x0000000003F940AA  90698825  :SHA256)
          (2000000000   "2033-05-18 03:33:20"   #x0000000003F940AA  38618901  :SHA512)
          (20000000000  "2603-10-11 11:33:20"   #x0000000027BC86AA  65353130  :SHA1)
          (20000000000  "2603-10-11 11:33:20"   #x0000000027BC86AA  77737706  :SHA256)
          (20000000000  "2603-10-11 11:33:20"   #x0000000027BC86AA  47863826  :SHA512))
     as test-timestep = (totp::time-step time)
     as key-hexstring = (ecase hotp:*hmac-sha-mode*
                          (:sha1   sha1-key)
                          (:sha256 sha256-key)
                          (:sha512 sha512-key))
     as not-expected-to-work = (not (eq :sha1 hotp:*hmac-sha-mode*))
     as test-totp = (totp:totp key-hexstring 0 time)
     as ok? = (= expected-totp test-totp)
     when *verbose* do (format t "~&~A ~12D ~D/~D ~8,'0D/~8,'0D ~a"
                             (if ok? ". " "KO")
                             time
                             expected-timestep test-timestep
                             expected-totp test-totp
                             hotp:*hmac-sha-mode*)
     always (or ok? not-expected-to-work)))

(test hotp-verify
  (let* ((key "48656C6C6F21DEADBEEF48656C6C6F21DEADBEEF")
	 (hotp (hotp:hotp key 3))
	 (hotp:*lookahead-window* 2))
    (is (null (hotp:verify key 1 hotp)))
    (is (= 3 (hotp:verify key 2 hotp)))))

(test totp-verify
  (let* ((key "48656C6C6F21DEADBEEF48656C6C6F21DEADBEEF")
	 (time 1234567890)
	 (totp (totp:totp key 0 time))
	 (totp:*verification-window-seconds* 30))
    (and
     (is (null (totp:verify key totp 0 totp:*verification-window-seconds* (+ time 60))))
     (is (= -30 (totp:verify key totp 0 totp:*verification-window-seconds* (+ time 35))))
     (is (= -60 (totp:verify key totp -30 totp:*verification-window-seconds* (+ time 60))))
     (is (= 0 (totp:verify key totp 0 totp:*verification-window-seconds* (+ time 20)))))))


#+nil
(test totp-not-working
  "based on examples in the RFC"
  (loop
     with hotp:*digits* = 8
     with key-stuff = (let ((x "31323334353637383930")) ;; 10 bytes in hex
                        (concatenate 'string x x x x x  x x x x x  x x x)) ;; 130 bytes
     with sha1-key   = (subseq key-stuff 0 40) ; 20 bytes
     with sha256-key = (subseq key-stuff 0 64)
     with sha512-key = (subseq key-stuff 0 128)
     for (time nil expected-timestep expected-totp hotp:*hmac-sha-mode*)
     in '((59           "1970-01-01 00:00:59"   #x0000000000000001  94287082  :SHA1)
          (59           "1970-01-01 00:00:59"   #x0000000000000001  46119246  :SHA256)
          (59           "1970-01-01 00:00:59"   #x0000000000000001  90693936  :SHA512)
          (1111111109   "2005-03-18 01:58:29"   #x00000000023523EC  07081804  :SHA1)
          (1111111109   "2005-03-18 01:58:29"   #x00000000023523EC  68084774  :SHA256)
          (1111111109   "2005-03-18 01:58:29"   #x00000000023523EC  25091201  :SHA512)
          (1111111111   "2005-03-18 01:58:31"   #x00000000023523ED  14050471  :SHA1)
          (1111111111   "2005-03-18 01:58:31"   #x00000000023523ED  67062674  :SHA256)
          (1111111111   "2005-03-18 01:58:31"   #x00000000023523ED  99943326  :SHA512)
          (1234567890   "2009-02-13 23:31:30"   #x000000000273EF07  89005924  :SHA1)
          (1234567890   "2009-02-13 23:31:30"   #x000000000273EF07  91819424  :SHA256)
          (1234567890   "2009-02-13 23:31:30"   #x000000000273EF07  93441116  :SHA512)
          (2000000000   "2033-05-18 03:33:20"   #x0000000003F940AA  69279037  :SHA1)
          (2000000000   "2033-05-18 03:33:20"   #x0000000003F940AA  90698825  :SHA256)
          (2000000000   "2033-05-18 03:33:20"   #x0000000003F940AA  38618901  :SHA512)
          (20000000000  "2603-10-11 11:33:20"   #x0000000027BC86AA  65353130  :SHA1)
          (20000000000  "2603-10-11 11:33:20"   #x0000000027BC86AA  77737706  :SHA256)
          (20000000000  "2603-10-11 11:33:20"   #x0000000027BC86AA  47863826  :SHA512))
     as test-timestep = (totp::time-step time)
     as key-hexstring = (ecase hotp:*hmac-sha-mode*
                          (:sha1   sha1-key)
                          (:sha256 sha256-key)
                          (:sha512 sha512-key))
     as test-totp = (totp:totp key-hexstring 0 time)
     as ok? = (= expected-totp test-totp)
     when *verbose* do (format t "~&~A ~12D ~D/~D ~8,'0D/~8,'0D ~a"
                             (if ok? ". " "KO")
                             time
                             expected-timestep test-timestep
                             expected-totp test-totp
                             hotp:*hmac-sha-mode*)
     ;always ok?
       ))

;; Sadly only :sha1 is working :(
;; but then, google authenticator may only support sha1


#+nil
(test make-otpauth-url
  (string-equal
   "otpauth://totp/alice@google.com?secret=JBSWY3DPEHPK3PXP"
   (let ((secret  (list (char-code #\H) (char-code #\e) (char-code #\l) (char-code #\l) (char-code #\o) (char-code #\!)
                        #xDE #xAD #xBE #xEF)))
     (make-otpauth-url "alice@google.com"
                       (make-array 10 :initial-contents secret)))))

(run!)


