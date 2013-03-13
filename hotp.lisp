(in-package "CL-HOTP")

; see: http://tools.ietf.org/html/rfc4226

(defvar *digits* 6)

(defvar *hmac-sha-mode* :sha1)

(defun hotp (key-string counter)
  (hotp-truncate (hmac-sha-n key-string counter)))

(defun hotp-truncate (20-bytes)
  (flet ((dt (ht)
           (let* ((byte19 (aref ht 19))
                  (byte-offset (ldb (byte 4 0) byte19))
                  (result 0))
             (setf (ldb (byte 7 24) result) (aref ht byte-offset))
             (setf (ldb (byte 8 16) result) (aref ht (+ 1 byte-offset)))
             (setf (ldb (byte 8  8) result) (aref ht (+ 2 byte-offset)))
             (setf (ldb (byte 8  0) result) (aref ht (+ 3 byte-offset)))
             result)))
    (let ((sbits (dt 20-bytes)))
      (mod sbits
           (svref #(1 10 100 1000 10000 100000 1000000 10000000 100000000) *digits*)))))

(defun hmac-sha-n (key-string counter)
  (loop 
     with counter-bytes = #.(make-array 8 :element-type '(unsigned-byte 8))
       with hmac = (ironclad:make-hmac 
                    (ironclad:hex-string-to-byte-array key-string) 
                    *hmac-sha-mode*)
       finally
       (ironclad:update-hmac hmac counter-bytes)
       (return (ironclad:hmac-digest hmac))
       for i from 7 downto 0
       for offset from 0 by 8
       do (setf (aref counter-bytes i) (ldb (byte 8 offset) counter))))

;;;; Tests from the spec.

#+test
(defun test-hotp-truncate ()
  ;; From page 7 of http://tools.ietf.org/html/rfc4226
  (=
   (hotp-truncate
    (ironclad:hex-string-to-byte-array "1f8698690e02ca16618550ef7f19da8e945b555a"))
   872921))

#+nil
(defun test-hmac-sha-n (&optional (verbose t))
  ;; From page 31 of http://tools.ietf.org/html/rfc4226 
  (loop
     with key = "3132333435363738393031323334353637383930"
     for (counter . expected) in '((0 . "cc93cf18508d94934c64b65d8ba7667fb7cde4b0")
                                   (1 . "75a48a19d4cbe100644e8ac1397eea747a2d33ab")
                                   (2 . "0bacb7fa082fef30782211938bc1c5e70416ff44")
                                   (3 . "66c28227d03a2d5529262ff016a1e6ef76557ece")
                                   (4 . "a904c900a64b35909874b33e61c5938a8e15ed1c")
                                   (5 . "a37e783d7b7233c083d4f62926c7a25f238d0316")
                                   (6 . "bc9cd28561042c83f219324d3c607256c03272ae")
                                   (7 . "a4fb960c0bc06e1eabb804e5b397cdc4b45596fa")
                                   (8 . "1b3c89f65e6c9e883012052823443f048b4332db")
                                   (9 . "1637409809a679dc698207310c8c7fc07290d9e5"))
     as test = (coerce (hmac-sha-n key counter) 'list)
     as test-out = (format nil "~{~2,'0x~}" test)
     when verbose do (format t "~2&~S~&~S" expected test-out)
     always (string-equal expected test-out)))

#+nil
(defun test-hotp (&optional (verbose t))
  ;; From page 31 of http://tools.ietf.org/html/rfc4226 
  (loop
     initially (when verbose (format t "~&# got    want   ?"))
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
     as test-hotp = (hotp key counter)
     when verbose 
     do (format t "~&~d ~d ~d ~a"
                counter test-hotp expected-hotp
                (if (= test-hotp expected-hotp) "ok" "ko"))
     always (= test-hotp expected-hotp)))
