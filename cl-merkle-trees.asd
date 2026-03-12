;;;; Copyright (c) 2024-2026 Parkian Company LLC. All rights reserved.
;;;; SPDX-License-Identifier: BSD-3-Clause

(defsystem :cl-merkle-trees
  :description "Pure Common Lisp Merkle tree implementation with proofs"
  :author "Parkian Company LLC"
  :license "BSD-3-Clause"
  :version "1.0.0"
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
