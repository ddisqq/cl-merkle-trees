;;;; Copyright (c) 2024-2026 Parkian Company LLC. All rights reserved.
;;;; SPDX-License-Identifier: BSD-3-Clause

(asdf:defsystem #::cl-merkle-trees
  :description "Pure Common Lisp Merkle tree implementation with proofs"
  :author "Parkian Company LLC"
  :license "BSD-3-Clause"
  :version "0.1.0"
  :depends-on ()
  :serial t
  :components
  ((:file "package")
   (:module "src"
    :components
    ((:file "hash")
     (:file "tree")
     (:file "proof")
     (:file "sparse")
     (:file "accumulator")))))

(asdf:defsystem #:cl-merkle-trees/test
  :description "Tests for cl-merkle-trees"
  :depends-on (#:cl-merkle-trees)
  :serial t
  :components ((:module "test"
                :components ((:file "test-merkle"))))
  :perform (asdf:test-op (o c)
             (let ((result (uiop:symbol-call :cl-merkle-trees.test :run-tests)))
               (unless result
                 (error "Tests failed")))))
