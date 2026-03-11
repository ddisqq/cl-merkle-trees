;;;; cl-merkle-trees.asd - ASDF System Definition
;;;; Copyright (c) 2024-2026 Parkian Company LLC. All rights reserved.
;;;; SPDX-License-Identifier: BSD-3-Clause

(defsystem "cl-merkle-trees"
  :description "Pure Common Lisp Merkle tree implementation with SHA256d hashing"
  :version "1.0.0"
  :author "Parkian Company LLC"
  :license "BSD-3-Clause"
  :depends-on ()  ; No external dependencies
  :serial t
  :components ((:file "package")
               (:module "src"
                :serial t
                :components ((:file "sha256")
                             (:file "merkle")
                             (:file "proof"))))
  :in-order-to ((test-op (test-op "cl-merkle-trees/test"))))

(defsystem "cl-merkle-trees/test"
  :description "Tests for cl-merkle-trees"
  :depends-on ("cl-merkle-trees")
  :components ((:module "test"
                :components ((:file "test-merkle"))))
  :perform (test-op (op c)
             (uiop:symbol-call :cl-merkle-trees.test :run-tests)))
