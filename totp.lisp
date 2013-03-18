(in-package "CL-TOTP")

(defconstant .unix-epoch-zero. 2208988800)
  ;; 00:00:00 UTC on 1 January 1970
  ;; (encode-universal-time 0 0 0 1 1 1970 0)
  ;; --> 2208988800

(defvar *time-zero* 0) ; aka the unix epoch zero
(defvar *time-step-in-seconds* 30)

(defmacro time-step (unix-time)
  `(floor (- ,unix-time *time-zero*) *time-step-in-seconds*))

(defun totp (key-hexstring &optional (offset 0) (time (- (get-universal-time) .unix-epoch-zero. offset)))
  (hotp:hotp key-hexstring (time-step time)))

#+nil
(defun test-totp (&optional (verbose t))
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
     as test-timestep = (time-step time)
     as key-hexstring = (ecase hotp:*hmac-sha-mode*
                          (:sha1   sha1-key)
                          (:sha256 sha256-key)
                          (:sha512 sha512-key))
     as test-totp = (totp key-hexstring 0 time)
     as ok? = (= expected-totp test-totp)
     when verbose do (format t "~&~A ~12D ~D/~D ~8,'0D/~8,'0D ~a"
                             (if ok? ". " "KO")
                             time
                             expected-timestep test-timestep
                             expected-totp test-totp
                             hotp:*hmac-sha-mode*)
     ;always ok?
       ))

;; Sadly only :sha1 is working :(
;; but then, google authenticator may only support sha1


;;;; otpauth urls' you'd need to ahve cl-base32 loaded for these to work

#+nil
(defun make-otpauth-url (identity key-bytes)
  (declare (type key-bytes (array 20 '(unsigned-byte 8))))
  (format nil "otpauth://totp/~a?secret=~a"
          identity
          (cl-base32:bytes-to-base32 key-bytes)))

#+nil
(defun test-make-otpauth-url ()
  (string-equal
   "otpauth://totp/alice@google.com?secret=JBSWY3DPEHPK3PXP"
   (let ((secret  (list (char-code #\H) (char-code #\e) (char-code #\l) (char-code #\l) (char-code #\o) (char-code #\!)
                        #xDE #xAD #xBE #xEF)))
     (make-otpauth-url "alice@google.com"
                       (make-array 10 :initial-contents secret)))))

;;  A test url: otpauth://totp/test@example.com?secret=jbswy3dpehpk3pxpjbswy3dpehpk3pxp
;;  you can make a QR code from that at <http://www.qrstuff.com/> and load it into 
;; Google's Authenticator.  The TOTP codes it starts generating can also be generated
;; via (totp "48656C6C6F21DEADBEEF48656C6C6F21DEADBEEF")
;; fyi (format t "~{~2,'0x~}" (coerce (cl-base32:base32-to-bytes "jbswy3dpehpk3pxpjbswy3dpehpk3pxp") 'list))
;; is "48656C6C6F21DEADBEEF48656C6C6F21DEADBEEF"
