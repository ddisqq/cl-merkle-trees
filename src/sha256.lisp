;; Copyright (c) 2024-2026 Parkian Company LLC. All rights reserved.
;; SPDX-License-Identifier: BSD-3-Clause

;;;; sha256.lisp - Pure Common Lisp SHA-256 Implementation
;;;; Copyright (c) 2024-2026 Parkian Company LLC. All rights reserved.
;;;; SPDX-License-Identifier: BSD-3-Clause
;;;;
;;;; Pure CL SHA-256 implementation for Merkle tree hashing.
;;;; No external dependencies - completely standalone.
;;;;
;;;; Reference: NIST FIPS 180-4 Secure Hash Standard

(in-package #:cl-merkle-trees)

(declaim (optimize (speed 3) (safety 1) (debug 0)))

;;; ============================================================================
;;; SHA-256 Constants
;;; ============================================================================

(defparameter +sha256-k+
  #(#x428a2f98 #x71374491 #xb5c0fbcf #xe9b5dba5
    #x3956c25b #x59f111f1 #x923f82a4 #xab1c5ed5
    #xd807aa98 #x12835b01 #x243185be #x550c7dc3
    #x72be5d74 #x80deb1fe #x9bdc06a7 #xc19bf174
    #xe49b69c1 #xefbe4786 #x0fc19dc6 #x240ca1cc
    #x2de92c6f #x4a7484aa #x5cb0a9dc #x76f988da
    #x983e5152 #xa831c66d #xb00327c8 #xbf597fc7
    #xc6e00bf3 #xd5a79147 #x06ca6351 #x14292967
    #x27b70a85 #x2e1b2138 #x4d2c6dfc #x53380d13
    #x650a7354 #x766a0abb #x81c2c92e #x92722c85
    #xa2bfe8a1 #xa81a664b #xc24b8b70 #xc76c51a3
    #xd192e819 #xd6990624 #xf40e3585 #x106aa070
    #x19a4c116 #x1e376c08 #x2748774c #x34b0bcb5
    #x391c0cb3 #x4ed8aa4a #x5b9cca4f #x682e6ff3
    #x748f82ee #x78a5636f #x84c87814 #x8cc70208
    #x90befffa #xa4506ceb #xbef9a3f7 #xc67178f2)
  "SHA-256 round constants (first 32 bits of fractional parts of cube roots of first 64 primes).")

(defparameter +sha256-h0+
  #(#x6a09e667 #xbb67ae85 #x3c6ef372 #xa54ff53a
    #x510e527f #x9b05688c #x1f83d9ab #x5be0cd19)
  "SHA-256 initial hash values (first 32 bits of fractional parts of square roots of first 8 primes).")

;;; ============================================================================
;;; 32-bit Arithmetic
;;; ============================================================================

(declaim (inline mod32 add32 rotr32 shr32))

(defun mod32 (x)
  "Reduce X to 32 bits."
  (logand x #xFFFFFFFF))

(defun add32 (&rest args)
  "Add arguments modulo 2^32."
  (mod32 (apply #'+ args)))

(defun rotr32 (x n)
  "Rotate 32-bit integer X right by N bits."
  (declare (type (unsigned-byte 32) x)
           (type (integer 0 31) n))
  (logior (mod32 (ash x (- n)))
          (mod32 (ash x (- 32 n)))))

(defun shr32 (x n)
  "Shift 32-bit integer X right by N bits."
  (declare (type (unsigned-byte 32) x)
           (type (integer 0 31) n))
  (ash x (- n)))

;;; ============================================================================
;;; SHA-256 Functions (FIPS 180-4, Section 4.1.2)
;;; ============================================================================

(declaim (inline sha256-ch sha256-maj sha256-bsig0 sha256-bsig1 sha256-ssig0 sha256-ssig1))

(defun sha256-ch (x y z)
  "Ch(x,y,z) = (x AND y) XOR (NOT x AND z)"
  (logxor (logand x y)
          (logand (mod32 (lognot x)) z)))

(defun sha256-maj (x y z)
  "Maj(x,y,z) = (x AND y) XOR (x AND z) XOR (y AND z)"
  (logxor (logand x y)
          (logand x z)
          (logand y z)))

(defun sha256-bsig0 (x)
  "BSIG0(x) = ROTR^2(x) XOR ROTR^13(x) XOR ROTR^22(x)"
  (logxor (rotr32 x 2)
          (rotr32 x 13)
          (rotr32 x 22)))

(defun sha256-bsig1 (x)
  "BSIG1(x) = ROTR^6(x) XOR ROTR^11(x) XOR ROTR^25(x)"
  (logxor (rotr32 x 6)
          (rotr32 x 11)
          (rotr32 x 25)))

(defun sha256-ssig0 (x)
  "SSIG0(x) = ROTR^7(x) XOR ROTR^18(x) XOR SHR^3(x)"
  (logxor (rotr32 x 7)
          (rotr32 x 18)
          (shr32 x 3)))

(defun sha256-ssig1 (x)
  "SSIG1(x) = ROTR^17(x) XOR ROTR^19(x) XOR SHR^10(x)"
  (logxor (rotr32 x 17)
          (rotr32 x 19)
          (shr32 x 10)))

;;; ============================================================================
;;; SHA-256 Block Processing
;;; ============================================================================

(defun sha256-process-block (h block)
  "Process a single 512-bit (64-byte) message block.
   H is the current hash state (8 x 32-bit words).
   BLOCK is a 64-byte array."
  (declare (type (simple-array (unsigned-byte 32) (8)) h)
           (type (simple-array (unsigned-byte 8) (64)) block))

  ;; Prepare the message schedule W
  (let ((w (make-array 64 :element-type '(unsigned-byte 32) :initial-element 0)))
    (declare (type (simple-array (unsigned-byte 32) (64)) w))

    ;; W[0..15]: Copy block as 32-bit big-endian words
    (loop for idx from 0 below 16
          for i = (* idx 4)
          do (setf (aref w idx)
                   (logior (ash (aref block i) 24)
                           (ash (aref block (+ i 1)) 16)
                           (ash (aref block (+ i 2)) 8)
                           (aref block (+ i 3)))))

    ;; W[16..63]: Expand message schedule
    (loop for idx from 16 below 64
          do (setf (aref w idx)
                   (add32 (sha256-ssig1 (aref w (- idx 2)))
                          (aref w (- idx 7))
                          (sha256-ssig0 (aref w (- idx 15)))
                          (aref w (- idx 16)))))

    ;; Initialize working variables
    (let ((a (aref h 0))
          (b (aref h 1))
          (c (aref h 2))
          (d (aref h 3))
          (e (aref h 4))
          (f (aref h 5))
          (g (aref h 6))
          (hv (aref h 7)))

      ;; 64 rounds
      (loop for round from 0 below 64
            do (let* ((temp1 (add32 hv
                                    (sha256-bsig1 e)
                                    (sha256-ch e f g)
                                    (aref +sha256-k+ round)
                                    (aref w round)))
                      (temp2 (add32 (sha256-bsig0 a)
                                    (sha256-maj a b c))))
                 ;; Update working variables
                 (setf hv g
                       g f
                       f e
                       e (add32 d temp1)
                       d c
                       c b
                       b a
                       a (add32 temp1 temp2))))

      ;; Add to hash value
      (setf (aref h 0) (add32 (aref h 0) a)
            (aref h 1) (add32 (aref h 1) b)
            (aref h 2) (add32 (aref h 2) c)
            (aref h 3) (add32 (aref h 3) d)
            (aref h 4) (add32 (aref h 4) e)
            (aref h 5) (add32 (aref h 5) f)
            (aref h 6) (add32 (aref h 6) g)
            (aref h 7) (add32 (aref h 7) hv)))))

;;; ============================================================================
;;; SHA-256 Message Padding
;;; ============================================================================

(defun sha256-pad (message)
  "Pad MESSAGE according to SHA-256 specification.
   Returns a new byte vector that is a multiple of 64 bytes."
  (let* ((msg-len (length message))
         (msg-bits (* msg-len 8))
         ;; Padding: original message + 1 byte (0x80) + zeros + 8 bytes (bit length)
         ;; Total length must be multiple of 64 (512 bits)
         (padded-len (let ((min-len (+ msg-len 1 8)))
                       (* 64 (ceiling min-len 64))))
         (result (make-array padded-len :element-type '(unsigned-byte 8) :initial-element 0)))

    ;; Copy original message
    (replace result message)

    ;; Append bit '1' (0x80)
    (setf (aref result msg-len) #x80)

    ;; Append original length as 64-bit big-endian integer
    (setf (aref result (- padded-len 8)) (ldb (byte 8 56) msg-bits)
          (aref result (- padded-len 7)) (ldb (byte 8 48) msg-bits)
          (aref result (- padded-len 6)) (ldb (byte 8 40) msg-bits)
          (aref result (- padded-len 5)) (ldb (byte 8 32) msg-bits)
          (aref result (- padded-len 4)) (ldb (byte 8 24) msg-bits)
          (aref result (- padded-len 3)) (ldb (byte 8 16) msg-bits)
          (aref result (- padded-len 2)) (ldb (byte 8 8) msg-bits)
          (aref result (- padded-len 1)) (ldb (byte 8 0) msg-bits))

    result))

;;; ============================================================================
;;; SHA-256 Public API
;;; ============================================================================

(defun sha256 (data)
  "Compute SHA-256 hash of DATA (byte vector or string).
   Returns a 32-byte hash digest."
  (let* ((input (etypecase data
                  ((simple-array (unsigned-byte 8) (*)) data)
                  (string (let ((result (make-array (length data)
                                                    :element-type '(unsigned-byte 8))))
                            (loop for i from 0 below (length data)
                                  do (setf (aref result i) (char-code (char data i))))
                            result))
                  (vector (coerce data '(simple-array (unsigned-byte 8) (*))))))
         ;; Initialize hash state
         (h (make-array 8 :element-type '(unsigned-byte 32)))
         ;; Pad the message
         (padded (sha256-pad input)))

    ;; Copy initial hash values
    (replace h +sha256-h0+)

    ;; Process each 64-byte block
    (loop for offset from 0 below (length padded) by 64
          for block = (make-array 64 :element-type '(unsigned-byte 8)
                                  :displaced-to padded
                                  :displaced-index-offset offset)
          ;; Need to copy since displaced arrays may not be simple
          for block-copy = (make-array 64 :element-type '(unsigned-byte 8))
          do (replace block-copy block)
             (sha256-process-block h block-copy))

    ;; Produce the final hash (big-endian)
    (let ((result (make-array 32 :element-type '(unsigned-byte 8))))
      (loop for i from 0 below 8
            for word = (aref h i)
            for j = (* i 4)
            do (setf (aref result j) (ldb (byte 8 24) word)
                     (aref result (+ j 1)) (ldb (byte 8 16) word)
                     (aref result (+ j 2)) (ldb (byte 8 8) word)
                     (aref result (+ j 3)) (ldb (byte 8 0) word)))
      result)))

(defun sha256d (data)
  "Compute double SHA-256: SHA256(SHA256(data)).
   Standard hash for Bitcoin/Merkle tree operations.
   Returns a 32-byte hash digest."
  (sha256 (sha256 data)))

;;; ============================================================================
;;; Utility Functions
;;; ============================================================================

(defun bytes-to-hex (bytes)
  "Convert byte vector to lowercase hexadecimal string."
  (with-output-to-string (s)
    (loop for byte across bytes
          do (format s "~(~2,'0x~)" byte))))

(defun hex-to-bytes (hex-string)
  "Convert hexadecimal string to byte vector."
  (declare (type string hex-string))
  (let* ((len (length hex-string))
         (result (make-array (floor len 2) :element-type '(unsigned-byte 8))))
    (loop for i from 0 below len by 2
          for j from 0
          do (setf (aref result j)
                   (parse-integer hex-string :start i :end (+ i 2) :radix 16)))
    result))

;;; End of sha256.lisp
