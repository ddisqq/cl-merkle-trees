;;;; Copyright (c) 2024-2026 Parkian Company LLC. All rights reserved.
;;;; SPDX-License-Identifier: BSD-3-Clause
;;;;
;;;; Merkle proofs

(in-package :cl-merkle-trees)

;;; ============================================================================
;;; Proof Structure
;;; ============================================================================

(defstruct merkle-proof
  "Merkle inclusion proof."
  (leaf nil)                          ; Leaf hash
  (index 0 :type integer)             ; Leaf index
  (siblings nil :type list)           ; Sibling hashes along path
  (directions nil :type list))        ; 0=left, 1=right for each level

;;; ============================================================================
;;; Proof Generation
;;; ============================================================================

(defun generate-proof (tree index)
  "Generate Merkle proof for leaf at index."
  (let* ((n (merkle-tree-size tree))
         (height (merkle-tree-height tree))
         (nodes (merkle-tree-nodes tree))
         (padded-n (ash 1 height))
         (total-nodes (1- (* 2 padded-n))))
    (when (or (< index 0) (>= index n))
      (error "Index ~a out of bounds (0..~a)" index (1- n)))
    (let ((leaf (tree-get-leaf tree index))
          (siblings nil)
          (directions nil)
          (node-idx (+ (- total-nodes padded-n) index)))
      ;; Walk up tree collecting siblings
      (dotimes (i height)
        (declare (ignore i))
        (let* ((is-right (oddp node-idx))
               (sibling-idx (if is-right (1- node-idx) (1+ node-idx))))
          (push (aref nodes sibling-idx) siblings)
          (push (if is-right 1 0) directions)
          ;; Move to parent
          (setf node-idx (floor (1- node-idx) 2))))
      (make-merkle-proof :leaf leaf
                         :index index
                         :siblings (nreverse siblings)
                         :directions (nreverse directions)))))

;;; ============================================================================
;;; Proof Verification
;;; ============================================================================

(defun verify-proof (tree proof)
  "Verify Merkle proof against tree root."
  (verify-proof-with-root (merkle-tree-root tree) proof))

(defun verify-proof-with-root (root proof)
  "Verify Merkle proof against given root."
  (let ((current (merkle-proof-leaf proof))
        (siblings (merkle-proof-siblings proof))
        (directions (merkle-proof-directions proof)))
    (loop for sibling in siblings
          for dir in directions do
      (setf current
            (if (zerop dir)
                (hash-node current sibling)
                (hash-node sibling current))))
    (equalp current root)))

;;; ============================================================================
;;; Multi-Proofs
;;; ============================================================================

(defstruct multi-proof
  "Proof for multiple leaves."
  (indices nil :type list)            ; Leaf indices
  (leaves nil :type list)             ; Leaf hashes
  (decommitment nil :type list))      ; Minimal set of nodes needed

(defun generate-multi-proof (tree indices)
  "Generate proof for multiple leaves."
  (let* ((height (merkle-tree-height tree))
         (nodes (merkle-tree-nodes tree))
         (padded-n (ash 1 height))
         (total-nodes (1- (* 2 padded-n)))
         ;; Track which nodes are needed vs provided
         (needed (make-hash-table))
         (provided (make-hash-table))
         (leaves nil))
    ;; Mark leaves as provided
    (dolist (idx indices)
      (let ((node-idx (+ (- total-nodes padded-n) idx)))
        (setf (gethash node-idx provided) t)
        (push (tree-get-leaf tree idx) leaves)))
    (setf leaves (nreverse leaves))
    ;; Walk up marking needed nodes
    (dolist (idx indices)
      (let ((node-idx (+ (- total-nodes padded-n) idx)))
        (dotimes (i height)
          (declare (ignore i))
          (let* ((is-right (oddp node-idx))
                 (sibling-idx (if is-right (1- node-idx) (1+ node-idx)))
                 (parent-idx (floor (1- node-idx) 2)))
            (unless (gethash sibling-idx provided)
              (setf (gethash sibling-idx needed) t))
            ;; Parent is now "provided" (will be computed)
            (setf (gethash parent-idx provided) t)
            (setf node-idx parent-idx)))))
    ;; Collect decommitment
    (let ((decommitment nil))
      (maphash (lambda (idx val)
                 (declare (ignore val))
                 (push (cons idx (aref nodes idx)) decommitment))
               needed)
      (make-multi-proof :indices indices
                        :leaves leaves
                        :decommitment (sort decommitment #'> :key #'car)))))

(defun verify-multi-proof (root multi-proof height)
  "Verify multi-proof against root."
  (let* ((padded-n (ash 1 height))
         (total-nodes (1- (* 2 padded-n)))
         (indices (multi-proof-indices multi-proof))
         (leaves (multi-proof-leaves multi-proof))
         (decommitment (multi-proof-decommitment multi-proof))
         ;; Build hash table of known values
         (known (make-hash-table)))
    ;; Add leaves
    (loop for idx in indices
          for leaf in leaves do
      (setf (gethash (+ (- total-nodes padded-n) idx) known) leaf))
    ;; Add decommitment
    (dolist (entry decommitment)
      (setf (gethash (car entry) known) (cdr entry)))
    ;; Compute up to root
    (loop for level from (1- height) downto 0 do
      (let ((level-start (1- (ash 1 level)))
            (level-size (ash 1 level)))
        (loop for i from 0 below level-size do
          (let* ((node-idx (+ level-start i))
                 (left-idx (+ (* 2 node-idx) 1))
                 (right-idx (+ (* 2 node-idx) 2))
                 (left (gethash left-idx known))
                 (right (gethash right-idx known)))
            (when (and left right)
              (setf (gethash node-idx known)
                    (hash-node left right)))))))
    (equalp (gethash 0 known) root)))

(defun batch-verify-proofs (tree proofs)
  "Verify multiple single proofs efficiently."
  (let ((root (merkle-tree-root tree)))
    (every (lambda (proof) (verify-proof-with-root root proof)) proofs)))
