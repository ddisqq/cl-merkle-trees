;;;; Copyright (c) 2024-2026 Parkian Company LLC. All rights reserved.
;;;; SPDX-License-Identifier: BSD-3-Clause
;;;;
;;;; Hash functions for Merkle trees

(in-package :cl-merkle-trees)

;;; ============================================================================
;;; SHA-256 Constants
;;; ============================================================================

(defconstant +sha256-k+
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
  "SHA-256 round constants.")

(defconstant +sha256-initial-hash+
  #(#x6a09e667 #xbb67ae85 #x3c6ef372 #xa54ff53a
    #x510e527f #x9b05688c #x1f83d9ab #x5be0cd19)
  "SHA-256 initial hash values.")

;;; ============================================================================
;;; Bit Operations
;;; ============================================================================

(declaim (inline rotr32 shr32 u32+))

(defun rotr32 (x n)
  "Rotate right 32-bit."
  (declare (type (unsigned-byte 32) x)
           (type (integer 0 31) n))
  (logior (ash x (- n)) (logand #xFFFFFFFF (ash x (- 32 n)))))

(defun shr32 (x n)
  "Shift right 32-bit."
  (declare (type (unsigned-byte 32) x)
           (type (integer 0 31) n))
  (ash x (- n)))

(defun u32+ (&rest args)
  "Add with 32-bit wraparound."
  (logand #xFFFFFFFF (apply #'+ args)))

;;; ============================================================================
;;; SHA-256 Implementation
;;; ============================================================================

(defun sha256-pad-message (message)
  "Pad message according to SHA-256 specification."
  (let* ((msg-bytes (etypecase message
                      (string (map 'vector #'char-code message))
                      (vector message)))
         (msg-len (length msg-bytes))
         (bit-len (* msg-len 8))
         ;; Padded length: msg + 1 + padding + 8 bytes for length
         (padded-len (* 64 (ceiling (+ msg-len 9) 64)))
         (result (make-array padded-len :element-type '(unsigned-byte 8)
                                        :initial-element 0)))
    ;; Copy message
    (replace result msg-bytes)
    ;; Append 1 bit (0x80)
    (setf (aref result msg-len) #x80)
    ;; Append length in bits (big-endian, 64-bit)
    (loop for i from 0 below 8 do
      (setf (aref result (- padded-len 1 i))
            (logand #xFF (ash bit-len (* -8 i)))))
    result))

(defun sha256-process-block (block hash)
  "Process one 64-byte block."
  (let ((w (make-array 64 :element-type '(unsigned-byte 32)))
        (h (copy-seq hash)))
    ;; Prepare message schedule
    (loop for i from 0 below 16 do
      (setf (aref w i)
            (logior (ash (aref block (* i 4)) 24)
                    (ash (aref block (+ (* i 4) 1)) 16)
                    (ash (aref block (+ (* i 4) 2)) 8)
                    (aref block (+ (* i 4) 3)))))
    (loop for i from 16 below 64 do
      (let* ((s0 (logxor (rotr32 (aref w (- i 15)) 7)
                         (rotr32 (aref w (- i 15)) 18)
                         (shr32 (aref w (- i 15)) 3)))
             (s1 (logxor (rotr32 (aref w (- i 2)) 17)
                         (rotr32 (aref w (- i 2)) 19)
                         (shr32 (aref w (- i 2)) 10))))
        (setf (aref w i) (u32+ (aref w (- i 16)) s0 (aref w (- i 7)) s1))))
    ;; Initialize working variables
    (let ((a (aref h 0)) (b (aref h 1)) (c (aref h 2)) (d (aref h 3))
          (e (aref h 4)) (f (aref h 5)) (g (aref h 6)) (hh (aref h 7)))
      ;; Main loop
      (loop for i from 0 below 64 do
        (let* ((S1 (logxor (rotr32 e 6) (rotr32 e 11) (rotr32 e 25)))
               (ch (logxor (logand e f) (logand (lognot e) g)))
               (temp1 (u32+ hh S1 ch (aref +sha256-k+ i) (aref w i)))
               (S0 (logxor (rotr32 a 2) (rotr32 a 13) (rotr32 a 22)))
               (maj (logxor (logand a b) (logand a c) (logand b c)))
               (temp2 (u32+ S0 maj)))
          (setf hh g
                g f
                f e
                e (u32+ d temp1)
                d c
                c b
                b a
                a (u32+ temp1 temp2))))
      ;; Add compressed chunk to current hash
      (setf (aref h 0) (u32+ (aref h 0) a)
            (aref h 1) (u32+ (aref h 1) b)
            (aref h 2) (u32+ (aref h 2) c)
            (aref h 3) (u32+ (aref h 3) d)
            (aref h 4) (u32+ (aref h 4) e)
            (aref h 5) (u32+ (aref h 5) f)
            (aref h 6) (u32+ (aref h 6) g)
            (aref h 7) (u32+ (aref h 7) hh)))
    h))

(defun sha256 (message)
  "Compute SHA-256 hash of message. Returns 32-byte vector."
  (let ((padded (sha256-pad-message message))
        (hash (copy-seq +sha256-initial-hash+)))
    ;; Process each 64-byte block
    (loop for i from 0 below (length padded) by 64 do
      (let ((block (subseq padded i (+ i 64))))
        (setf hash (sha256-process-block block hash))))
    ;; Convert to bytes
    (let ((result (make-array 32 :element-type '(unsigned-byte 8))))
      (loop for i from 0 below 8 do
        (setf (aref result (* i 4)) (logand #xFF (ash (aref hash i) -24))
              (aref result (+ (* i 4) 1)) (logand #xFF (ash (aref hash i) -16))
              (aref result (+ (* i 4) 2)) (logand #xFF (ash (aref hash i) -8))
              (aref result (+ (* i 4) 3)) (logand #xFF (aref hash i))))
      result)))

(defun sha256-bytes (bytes)
  "Compute SHA-256 of byte vector."
  (sha256 bytes))

;;; ============================================================================
;;; Merkle-specific Hash Functions
;;; ============================================================================

(defun hash-combine (left right)
  "Combine two hashes into one (internal node)."
  (let ((combined (make-array 64 :element-type '(unsigned-byte 8))))
    (replace combined left)
    (replace combined right :start1 32)
    (sha256 combined)))

(defun hash-leaf (data)
  "Hash leaf data with domain separation."
  (let* ((data-bytes (etypecase data
                       (string (map 'vector #'char-code data))
                       (vector data)
                       (integer (integer-to-hash data))))
         (prefixed (make-array (1+ (length data-bytes))
                               :element-type '(unsigned-byte 8))))
    ;; Prefix with 0x00 for leaf
    (setf (aref prefixed 0) #x00)
    (replace prefixed data-bytes :start1 1)
    (sha256 prefixed)))

(defun hash-node (left right)
  "Hash internal node with domain separation."
  (let ((prefixed (make-array 65 :element-type '(unsigned-byte 8))))
    ;; Prefix with 0x01 for internal node
    (setf (aref prefixed 0) #x01)
    (replace prefixed left :start1 1)
    (replace prefixed right :start1 33)
    (sha256 prefixed)))

;;; ============================================================================
;;; Utility Functions
;;; ============================================================================

(defun bytes-to-hex (bytes)
  "Convert byte vector to hexadecimal string."
  (with-output-to-string (s)
    (loop for b across bytes do
      (format s "~2,'0x" b))))

(defun hex-to-bytes (hex-string)
  "Convert hexadecimal string to byte vector."
  (let* ((len (/ (length hex-string) 2))
         (result (make-array len :element-type '(unsigned-byte 8))))
    (loop for i from 0 below len do
      (setf (aref result i)
            (parse-integer hex-string :start (* i 2) :end (* (1+ i) 2)
                                      :radix 16)))
    result))

(defun hash-to-integer (hash)
  "Convert 32-byte hash to integer."
  (let ((result 0))
    (loop for b across hash do
      (setf result (logior (ash result 8) b)))
    result))

(defun integer-to-hash (n)
  "Convert integer to 32-byte hash."
  (let ((result (make-array 32 :element-type '(unsigned-byte 8)
                               :initial-element 0)))
    (loop for i from 31 downto 0
          while (> n 0) do
      (setf (aref result i) (logand n #xFF))
      (setf n (ash n -8)))
    result))
