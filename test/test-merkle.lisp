;;;; test-merkle.lisp - Test Suite for cl-merkle-trees
;;;; Copyright (c) 2024-2026 Parkian Company LLC. All rights reserved.
;;;; SPDX-License-Identifier: BSD-3-Clause

(in-package #:cl-merkle-trees.test)

;;; ============================================================================
;;; Test Infrastructure
;;; ============================================================================

(defvar *test-count* 0)
(defvar *pass-count* 0)
(defvar *fail-count* 0)

(defmacro deftest (name &body body)
  "Define a test case."
  `(defun ,name ()
     (incf *test-count*)
     (handler-case
         (progn ,@body
                (incf *pass-count*)
                (format t "  PASS: ~A~%" ',name))
       (error (e)
         (incf *fail-count*)
         (format t "  FAIL: ~A - ~A~%" ',name e)))))

(defmacro assert-true (form &optional message)
  "Assert that FORM evaluates to true."
  `(unless ,form
     (error "Assertion failed~@[: ~A~]" ,message)))

(defmacro assert-equal (expected actual &optional message)
  "Assert that EXPECTED equals ACTUAL."
  `(unless (equalp ,expected ,actual)
     (error "Expected ~S but got ~S~@[: ~A~]" ,expected ,actual ,message)))

;;; ============================================================================
;;; SHA-256 Tests
;;; ============================================================================

(deftest test-sha256-empty
  "SHA256 of empty input should match known value."
  (let ((hash (sha256 (make-array 0 :element-type '(unsigned-byte 8)))))
    (assert-equal "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
                  (bytes-to-hex hash))))

(deftest test-sha256-abc
  "SHA256 of 'abc' should match NIST test vector."
  (let ((hash (sha256 "abc")))
    (assert-equal "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
                  (bytes-to-hex hash))))

(deftest test-sha256d-empty
  "Double SHA256 of empty input."
  (let ((hash (sha256d (make-array 0 :element-type '(unsigned-byte 8)))))
    (assert-equal 32 (length hash) "SHA256d should return 32 bytes")))

(deftest test-sha256d-abc
  "Double SHA256 of 'abc'."
  (let ((hash (sha256d "abc")))
    ;; SHA256(SHA256("abc"))
    (assert-equal "4f8b42c22dd3729b519ba6f68d2da7cc5b2d606d05daed5ad5128cc03e6c6358"
                  (bytes-to-hex hash))))

;;; ============================================================================
;;; Merkle Tree Construction Tests
;;; ============================================================================

(deftest test-merkle-root-empty
  "Merkle root of empty list should be 32 zero bytes."
  (let ((root (compute-merkle-root nil)))
    (assert-equal 32 (length root))
    (assert-true (every #'zerop root))))

(deftest test-merkle-root-single
  "Merkle root of single item should be that item."
  (let* ((hash (sha256 "test"))
         (root (compute-merkle-root (list hash))))
    (assert-equal hash root)))

(deftest test-merkle-root-two-items
  "Merkle root of two items."
  (let* ((h0 (sha256 "tx0"))
         (h1 (sha256 "tx1"))
         (root (compute-merkle-root (list h0 h1)))
         (expected (merkle-hash-pair h0 h1)))
    (assert-equal expected root)))

(deftest test-merkle-root-three-items
  "Merkle root of three items (tests duplicate-last rule)."
  (let* ((h0 (sha256 "tx0"))
         (h1 (sha256 "tx1"))
         (h2 (sha256 "tx2"))
         (root (compute-merkle-root (list h0 h1 h2)))
         ;; Level 1: [Hash(h0,h1), Hash(h2,h2)]
         (hash01 (merkle-hash-pair h0 h1))
         (hash22 (merkle-hash-pair h2 h2))
         ;; Level 2: [Hash(hash01,hash22)]
         (expected (merkle-hash-pair hash01 hash22)))
    (assert-equal expected root)))

(deftest test-merkle-root-four-items
  "Merkle root of four items (balanced tree)."
  (let* ((h0 (sha256 "tx0"))
         (h1 (sha256 "tx1"))
         (h2 (sha256 "tx2"))
         (h3 (sha256 "tx3"))
         (root (compute-merkle-root (list h0 h1 h2 h3)))
         (hash01 (merkle-hash-pair h0 h1))
         (hash23 (merkle-hash-pair h2 h3))
         (expected (merkle-hash-pair hash01 hash23)))
    (assert-equal expected root)))

(deftest test-build-merkle-tree
  "Build complete merkle tree and verify structure."
  (let* ((h0 (sha256 "tx0"))
         (h1 (sha256 "tx1"))
         (h2 (sha256 "tx2"))
         (h3 (sha256 "tx3"))
         (tree (build-merkle-tree (list h0 h1 h2 h3))))
    ;; Should have 3 levels: leaves, parents, root
    (assert-equal 3 (length tree))
    ;; Level 0: 4 leaves
    (assert-equal 4 (length (first tree)))
    ;; Level 1: 2 parents
    (assert-equal 2 (length (second tree)))
    ;; Level 2: 1 root
    (assert-equal 1 (length (third tree)))))

(deftest test-merkle-tree-depth
  "Test merkle tree depth calculation."
  (assert-equal 0 (merkle-tree-depth 0))
  (assert-equal 0 (merkle-tree-depth 1))
  (assert-equal 2 (merkle-tree-depth 2))
  (assert-equal 3 (merkle-tree-depth 4))
  (assert-equal 4 (merkle-tree-depth 8)))

;;; ============================================================================
;;; Merkle Proof Tests
;;; ============================================================================

(deftest test-merkle-proof-generation
  "Generate and verify merkle proof for first transaction."
  (let* ((h0 (sha256 "tx0"))
         (h1 (sha256 "tx1"))
         (h2 (sha256 "tx2"))
         (h3 (sha256 "tx3"))
         (hashes (list h0 h1 h2 h3))
         (root (compute-merkle-root hashes))
         (proof (compute-merkle-proof hashes 0)))
    (assert-true proof "Proof should not be nil")
    (assert-equal h0 (merkle-proof-tx-hash proof))
    (assert-equal 0 (merkle-proof-index proof))
    ;; Should have 2 siblings for 4 items (log2(4) = 2)
    (assert-equal 2 (length (merkle-proof-siblings proof)))
    ;; Verify the proof
    (assert-true (verify-merkle-proof proof root))))

(deftest test-merkle-proof-all-positions
  "Verify merkle proofs work for all positions."
  (let* ((hashes (loop for i from 0 below 8
                       collect (sha256 (format nil "tx~D" i))))
         (root (compute-merkle-root hashes)))
    (loop for i from 0 below 8
          do (let ((proof (compute-merkle-proof hashes i)))
               (assert-true (verify-merkle-proof proof root)
                            (format nil "Proof for index ~D should verify" i))))))

(deftest test-merkle-proof-invalid-root
  "Proof should fail verification against wrong root."
  (let* ((h0 (sha256 "tx0"))
         (h1 (sha256 "tx1"))
         (hashes (list h0 h1))
         (proof (compute-merkle-proof hashes 0))
         (wrong-root (sha256 "wrong")))
    (assert-true (not (verify-merkle-proof proof wrong-root))
                 "Proof should not verify against wrong root")))

(deftest test-merkle-proof-invalid-index
  "compute-merkle-proof should return NIL for invalid index."
  (let* ((h0 (sha256 "tx0"))
         (hashes (list h0)))
    (assert-true (null (compute-merkle-proof hashes 1))
                 "Invalid index should return NIL")
    (assert-true (null (compute-merkle-proof nil 0))
                 "Empty list should return NIL")))

(deftest test-merkle-proof-odd-count
  "Verify proof works with odd number of transactions."
  (let* ((hashes (loop for i from 0 below 5
                       collect (sha256 (format nil "tx~D" i))))
         (root (compute-merkle-root hashes)))
    (loop for i from 0 below 5
          do (let ((proof (compute-merkle-proof hashes i)))
               (assert-true (verify-merkle-proof proof root)
                            (format nil "Proof for index ~D (odd count) should verify" i))))))

;;; ============================================================================
;;; Utility Tests
;;; ============================================================================

(deftest test-bytes-to-hex
  "Test byte vector to hex string conversion."
  (assert-equal "00ff10" (bytes-to-hex (make-array 3 :element-type '(unsigned-byte 8)
                                                    :initial-contents '(0 255 16)))))

(deftest test-hex-to-bytes
  "Test hex string to byte vector conversion."
  (let ((bytes (hex-to-bytes "00ff10")))
    (assert-equal 3 (length bytes))
    (assert-equal 0 (aref bytes 0))
    (assert-equal 255 (aref bytes 1))
    (assert-equal 16 (aref bytes 2))))

(deftest test-hex-roundtrip
  "Test hex encode/decode roundtrip."
  (let* ((original (make-array 8 :element-type '(unsigned-byte 8)
                               :initial-contents '(1 2 3 4 5 255 254 253)))
         (hex (bytes-to-hex original))
         (decoded (hex-to-bytes hex)))
    (assert-true (equalp original decoded) "Roundtrip should preserve bytes")))

;;; ============================================================================
;;; Test Runner
;;; ============================================================================

(defun run-tests ()
  "Run all tests and report results."
  (setf *test-count* 0
        *pass-count* 0
        *fail-count* 0)

  (format t "~%Running cl-merkle-trees tests...~%~%")

  ;; SHA-256 tests
  (format t "SHA-256 Tests:~%")
  (test-sha256-empty)
  (test-sha256-abc)
  (test-sha256d-empty)
  (test-sha256d-abc)

  ;; Merkle tree construction tests
  (format t "~%Merkle Tree Construction Tests:~%")
  (test-merkle-root-empty)
  (test-merkle-root-single)
  (test-merkle-root-two-items)
  (test-merkle-root-three-items)
  (test-merkle-root-four-items)
  (test-build-merkle-tree)
  (test-merkle-tree-depth)

  ;; Merkle proof tests
  (format t "~%Merkle Proof Tests:~%")
  (test-merkle-proof-generation)
  (test-merkle-proof-all-positions)
  (test-merkle-proof-invalid-root)
  (test-merkle-proof-invalid-index)
  (test-merkle-proof-odd-count)

  ;; Utility tests
  (format t "~%Utility Tests:~%")
  (test-bytes-to-hex)
  (test-hex-to-bytes)
  (test-hex-roundtrip)

  ;; Summary
  (format t "~%========================================~%")
  (format t "Tests: ~D, Passed: ~D, Failed: ~D~%"
          *test-count* *pass-count* *fail-count*)
  (format t "========================================~%")

  (values (zerop *fail-count*) *test-count* *pass-count* *fail-count*))

;;; End of test-merkle.lisp
