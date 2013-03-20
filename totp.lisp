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
