;;;; package.lisp - Package Definition
;;;; Copyright (c) 2024-2026 Parkian Company LLC. All rights reserved.
;;;; SPDX-License-Identifier: BSD-3-Clause

(defpackage #:cl-merkle-trees
  (:use #:cl)
  (:export
   ;; SHA-256 (inlined for standalone use)
   #:sha256
   #:sha256d

   ;; Merkle tree construction
   #:compute-merkle-root
   #:build-merkle-tree
   #:merkle-hash-pair
   #:merkle-level
   #:merkle-tree-depth
   #:merkle-tree-size

   ;; Merkle proofs
   #:merkle-proof
   #:make-merkle-proof
   #:merkle-proof-tx-hash
   #:merkle-proof-siblings
   #:merkle-proof-index
   #:compute-merkle-proof
   #:verify-merkle-proof

   ;; Utilities
   #:bytes-to-hex
   #:hex-to-bytes))

(defpackage #:cl-merkle-trees.test
  (:use #:cl #:cl-merkle-trees)
  (:export #:run-tests))
