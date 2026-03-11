;;;; merkle.lisp - Merkle Tree Construction
;;;; Copyright (c) 2024-2026 Parkian Company LLC. All rights reserved.
;;;; SPDX-License-Identifier: BSD-3-Clause
;;;;
;;;; Bitcoin-compatible Merkle tree construction using SHA256d hashing.
;;;; Implements the duplicate-last-element rule for odd-sized levels.

(in-package #:cl-merkle-trees)

;;; ============================================================================
;;; Merkle Tree Algorithm
;;; ============================================================================
;;;
;;; A Merkle tree is a binary hash tree used to efficiently verify data integrity
;;; and prove inclusion of specific items in a dataset.
;;;
;;; TREE STRUCTURE:
;;;
;;;                    Root Hash
;;;                        |
;;;           +------------+------------+
;;;          /                            \
;;;     Hash01                        Hash23
;;;      |                              |
;;;    +--+--+                        +--+--+
;;;   /      \                      /      \
;;; Hash0  Hash1                  Hash2  Hash3
;;;  |       |                     |       |
;;; Tx0    Tx1                    Tx2    Tx3
;;;
;;; PROPERTIES:
;;; - Balanced binary tree constructed bottom-up
;;; - Each non-leaf node = SHA256d(left_child || right_child)
;;; - Odd number of nodes at any level: duplicate the last node
;;;
;;; ============================================================================

(declaim (optimize (speed 3) (safety 1)))

(defun zero-bytes (length)
  "Create a byte vector filled with zeros."
  (make-array length :element-type '(unsigned-byte 8) :initial-element 0))

(defun merkle-hash-pair (left right)
  "Hash two 32-byte nodes together for the Merkle tree.
   Computes SHA256d(left || right) where || is concatenation."
  (declare (optimize (speed 3) (safety 1)))
  (let ((buffer (make-array 64 :element-type '(unsigned-byte 8))))
    (replace buffer left :start1 0)
    (replace buffer right :start1 32)
    (sha256d buffer)))

(defun merkle-level (hashes)
  "Compute one level of the Merkle tree from the level below.

   Takes a list of hashes and pairs them up, hashing each pair:
   - [H0, H1, H2, H3] -> [Hash(H0,H1), Hash(H2,H3)]

   Duplicate-last-element handling for odd counts:
   - [H0, H1, H2] -> [Hash(H0,H1), Hash(H2,H2)]"
  (declare (optimize (speed 3) (safety 1)))
  (let ((result '()))
    (loop for (left right) on hashes by #'cddr
          do (push (merkle-hash-pair left (or right left)) result))
    (nreverse result)))

(defun compute-merkle-root (tx-hashes)
  "Compute the Merkle root from a list of transaction hashes.
   TX-HASHES should be a list of 32-byte vectors.

   Algorithm:
   1. Start with transaction hashes as leaf nodes (level 0)
   2. Pair adjacent nodes and hash them to create parent level
   3. If odd number of nodes, duplicate the last one
   4. Repeat until only one node remains (the root)

   Edge cases:
   - Empty list: returns 32 zero bytes
   - Single hash: returns that hash (already the root)"
  (declare (optimize (speed 3) (safety 1)))
  (when (null tx-hashes)
    (return-from compute-merkle-root (zero-bytes 32)))

  (when (= (length tx-hashes) 1)
    (return-from compute-merkle-root (first tx-hashes)))

  ;; Build the tree level by level, bottom-up
  (let ((level (copy-list tx-hashes)))
    (loop while (> (length level) 1)
          do (setf level (merkle-level level)))
    (first level)))

(defun merkle-tree-depth (n)
  "Calculate the depth of a Merkle tree with N leaves.
   Returns 0 for n <= 1."
  (if (<= n 1)
      0
      (1+ (ceiling (log n 2)))))

(defun merkle-tree-size (n)
  "Calculate the total number of nodes in a Merkle tree with N leaves."
  (if (<= n 1)
      n
      (let ((leaves (expt 2 (ceiling (log n 2)))))
        (1- (* 2 leaves)))))

(defun build-merkle-tree (tx-hashes)
  "Build a complete Merkle tree and return all nodes.
   Returns a list of levels, where each level is a list of hashes.

   Return format: ((level-0) (level-1) ... (root))
   Where level-0 is the leaves (transaction hashes) and the last
   level contains only the root.

   Example with 4 transactions:
     Level 0: (H0 H1 H2 H3)           ; Leaves
     Level 1: (Hash01 Hash23)         ; Parents
     Level 2: (Root)                  ; Root"
  (when (null tx-hashes)
    (return-from build-merkle-tree nil))

  (let ((levels (list tx-hashes)))
    (loop while (> (length (first levels)) 1)
          do (push (merkle-level (first levels)) levels))
    (nreverse levels)))

;;; End of merkle.lisp
