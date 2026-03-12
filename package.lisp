;;;; Copyright (c) 2024-2026 Parkian Company LLC. All rights reserved.
;;;; SPDX-License-Identifier: BSD-3-Clause
;;;;
;;;; Package definition for cl-merkle-trees

(defpackage :cl-merkle-trees
  (:use :cl)
  (:nicknames :merkle)
  (:export
   ;; Hash functions
   #:sha256
   #:sha256-bytes
   #:hash-combine
   #:hash-leaf
   #:hash-node

   ;; Tree construction
   #:make-merkle-tree
   #:merkle-tree
   #:merkle-tree-root
   #:merkle-tree-leaves
   #:merkle-tree-height
   #:merkle-tree-size

   ;; Tree operations
   #:tree-insert
   #:tree-update
   #:tree-get-leaf
   #:tree-leaf-index

   ;; Proofs
   #:make-merkle-proof
   #:merkle-proof
   #:merkle-proof-leaf
   #:merkle-proof-index
   #:merkle-proof-siblings
   #:generate-proof
   #:verify-proof
   #:verify-proof-with-root

   ;; Multi-proofs
   #:generate-multi-proof
   #:verify-multi-proof
   #:batch-verify-proofs

   ;; Sparse Merkle trees
   #:make-sparse-merkle-tree
   #:sparse-merkle-tree
   #:smt-root
   #:smt-get
   #:smt-set
   #:smt-delete
   #:smt-generate-proof
   #:smt-verify-proof
   #:smt-verify-non-membership

   ;; Accumulators
   #:make-merkle-accumulator
   #:merkle-accumulator
   #:accumulator-root
   #:accumulator-size
   #:accumulator-append
   #:accumulator-generate-proof
   #:accumulator-verify-proof

   ;; Utilities
   #:bytes-to-hex
   #:hex-to-bytes
   #:hash-to-integer
   #:integer-to-hash))
