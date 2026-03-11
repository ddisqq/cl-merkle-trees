;;;; proof.lisp - Merkle Proof Generation and Verification
;;;; Copyright (c) 2024-2026 Parkian Company LLC. All rights reserved.
;;;; SPDX-License-Identifier: BSD-3-Clause
;;;;
;;;; SPV (Simplified Payment Verification) proof generation and verification.
;;;; Allows verification of transaction inclusion with O(log n) data.

(in-package #:cl-merkle-trees)

;;; ============================================================================
;;; Merkle Proof Structure
;;; ============================================================================

(defstruct merkle-proof
  "A Merkle proof for a transaction (SPV proof).

   TX-HASH: The hash of the transaction being proven (32 bytes)

   SIBLINGS: List of (hash . is-right) pairs, one per tree level
            - hash: The sibling node needed to compute parent
            - is-right: T if sibling is on the right, NIL if on left

   INDEX: Position of transaction in block (0-based)

   Proof size: O(log n) where n is number of transactions.
   A block with 2000 txs needs only ~11 sibling hashes."
  (tx-hash nil :type (or null (vector (unsigned-byte 8))))
  (siblings '() :type list)
  (index 0 :type fixnum))

;;; ============================================================================
;;; Proof Generation
;;; ============================================================================

(defun compute-merkle-proof (tx-hashes tx-index)
  "Compute a Merkle proof for the transaction at TX-INDEX.

   Algorithm:
   1. Start at leaf level with the target transaction
   2. For each level going up the tree:
      a. Find the sibling of the current node
      b. Record (sibling-hash . position)
      c. Move to parent node at next level
   3. Continue until reaching root

   Example: Proving Tx1 (index 1) in [Tx0, Tx1, Tx2, Tx3]
     Level 0: Index 1 -> Sibling is index 0 (Hash0, position left)
     Level 1: Index 0 -> Sibling is index 1 (Hash23, position right)
     Proof: [(Hash0 . NIL), (Hash23 . T)]

   Returns: merkle-proof structure, or NIL if invalid index."
  (when (or (null tx-hashes) (>= tx-index (length tx-hashes)))
    (return-from compute-merkle-proof nil))

  (let ((siblings '())
        (level (coerce tx-hashes 'vector))
        (index tx-index))

    ;; Build proof by tracking the path from leaf to root
    (loop while (> (length level) 1)
          do (let* (;; Find sibling index: if we're even, sibling is +1; if odd, -1
                    (sibling-index (if (evenp index) (1+ index) (1- index)))
                    ;; Get sibling hash, or duplicate current if sibling doesn't exist
                    (sibling (if (< sibling-index (length level))
                                 (aref level sibling-index)
                                 (aref level index)))  ; Duplicate-last-element rule
                    ;; Track if sibling is on right (we're on left if even index)
                    (is-right (evenp index)))

               ;; Record this sibling for the proof
               (push (cons sibling is-right) siblings)

               ;; Move to parent level
               (setf level (coerce (merkle-level (coerce level 'list)) 'vector)
                     index (floor index 2))))

    (make-merkle-proof
     :tx-hash (nth tx-index tx-hashes)
     :siblings (nreverse siblings)
     :index tx-index)))

;;; ============================================================================
;;; Proof Verification
;;; ============================================================================

(defun verify-merkle-proof (proof merkle-root)
  "Verify a Merkle proof against a known root.

   Algorithm:
   1. Start with the transaction hash from the proof
   2. For each sibling in the proof (bottom-up):
      a. Hash current with sibling in correct order
      b. Result becomes new current hash
   3. Compare final hash with the merkle root

   Hash ordering:
   - is-right = T: Hash(current, sibling) - we're on left
   - is-right = NIL: Hash(sibling, current) - we're on right

   Returns: T if proof is valid, NIL otherwise."
  (declare (optimize (speed 3) (safety 1)))
  (when (null proof)
    (return-from verify-merkle-proof nil))

  (let ((current (merkle-proof-tx-hash proof)))
    ;; Walk up the tree, hashing with each sibling
    (dolist (sibling-pair (merkle-proof-siblings proof))
      (let ((sibling (car sibling-pair))
            (is-right (cdr sibling-pair)))
        ;; Hash in correct order based on position
        (setf current (if is-right
                          (merkle-hash-pair current sibling)
                          (merkle-hash-pair sibling current)))))

    ;; Final hash should equal the merkle root
    (equalp current merkle-root)))

;;; End of proof.lisp
