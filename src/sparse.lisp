;;;; Copyright (c) 2024-2026 Parkian Company LLC. All rights reserved.
;;;; SPDX-License-Identifier: BSD-3-Clause
;;;;
;;;; Sparse Merkle trees

(in-package :cl-merkle-trees)

;;; ============================================================================
;;; Sparse Merkle Tree
;;; ============================================================================

(defparameter *smt-depth* 256
  "Default sparse Merkle tree depth (256 for SHA-256 keys).")

(defstruct (sparse-merkle-tree (:constructor %make-sparse-merkle-tree))
  "Sparse Merkle tree for key-value storage."
  (depth *smt-depth* :type integer)   ; Tree depth
  (root nil)                          ; Root hash
  (store (make-hash-table :test 'equalp) :type hash-table)  ; Node storage
  (default-hashes nil :type vector))  ; Pre-computed empty subtree hashes

;;; ============================================================================
;;; Default Hash Computation
;;; ============================================================================

(defun compute-default-hashes (depth)
  "Pre-compute hashes of empty subtrees at each level."
  (let ((defaults (make-array (1+ depth))))
    ;; Level 0: empty leaf
    (setf (aref defaults 0)
          (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0))
    ;; Each level: hash of two children from previous level
    (loop for i from 1 to depth do
      (setf (aref defaults i)
            (hash-node (aref defaults (1- i)) (aref defaults (1- i)))))
    defaults))

;;; ============================================================================
;;; Tree Construction
;;; ============================================================================

(defun make-sparse-merkle-tree (&key (depth *smt-depth*))
  "Create empty sparse Merkle tree."
  (let ((defaults (compute-default-hashes depth)))
    (%make-sparse-merkle-tree :depth depth
                              :root (aref defaults depth)
                              :store (make-hash-table :test 'equalp)
                              :default-hashes defaults)))

;;; ============================================================================
;;; Key/Path Operations
;;; ============================================================================

(defun key-to-path (key depth)
  "Convert key (hash) to bit path."
  (let ((key-int (if (integerp key) key (hash-to-integer key))))
    (loop for i from (1- depth) downto 0
          collect (logand 1 (ash key-int (- i))))))

(defun path-node-key (path level)
  "Generate storage key for node at path/level."
  (cons level (subseq path 0 level)))

;;; ============================================================================
;;; Tree Operations
;;; ============================================================================

(defun smt-get-node (smt path level)
  "Get node hash at path/level, or default if empty."
  (let ((key (path-node-key path level)))
    (or (gethash key (sparse-merkle-tree-store smt))
        (aref (sparse-merkle-tree-default-hashes smt) level))))

(defun smt-set-node (smt path level hash)
  "Set node hash at path/level."
  (let ((key (path-node-key path level))
        (default (aref (sparse-merkle-tree-default-hashes smt) level)))
    (if (equalp hash default)
        ;; Remove if setting to default (sparse storage)
        (remhash key (sparse-merkle-tree-store smt))
        (setf (gethash key (sparse-merkle-tree-store smt)) hash))))

(defun smt-root (smt)
  "Get tree root hash."
  (sparse-merkle-tree-root smt))

(defun smt-get (smt key)
  "Get value at key (returns leaf hash or nil)."
  (let* ((depth (sparse-merkle-tree-depth smt))
         (path (key-to-path key depth))
         (leaf (smt-get-node smt path 0))
         (default (aref (sparse-merkle-tree-default-hashes smt) 0)))
    (if (equalp leaf default) nil leaf)))

(defun smt-set (smt key value)
  "Set value at key, return new SMT (immutable)."
  (let* ((depth (sparse-merkle-tree-depth smt))
         (path (key-to-path key depth))
         (value-hash (if (null value)
                         (aref (sparse-merkle-tree-default-hashes smt) 0)
                         (hash-leaf value)))
         ;; Copy store for immutability
         (new-store (make-hash-table :test 'equalp))
         (new-smt (%make-sparse-merkle-tree
                   :depth depth
                   :root nil
                   :store new-store
                   :default-hashes (sparse-merkle-tree-default-hashes smt))))
    ;; Copy existing nodes
    (maphash (lambda (k v) (setf (gethash k new-store) v))
             (sparse-merkle-tree-store smt))
    ;; Set leaf
    (smt-set-node new-smt path 0 value-hash)
    ;; Update path to root
    (loop for level from 1 to depth do
      (let* ((bit (nth (- depth level) path))
             (sibling-path (copy-list path))
             (child-hash (smt-get-node new-smt path (1- level)))
             (sibling-hash (progn
                             (setf (nth (- depth level) sibling-path)
                                   (- 1 bit))
                             (smt-get-node new-smt sibling-path (1- level))))
             (parent-hash (if (zerop bit)
                              (hash-node child-hash sibling-hash)
                              (hash-node sibling-hash child-hash))))
        (smt-set-node new-smt path level parent-hash)))
    ;; Set root
    (setf (sparse-merkle-tree-root new-smt)
          (smt-get-node new-smt path depth))
    new-smt))

(defun smt-delete (smt key)
  "Delete key from SMT (set to empty)."
  (smt-set smt key nil))

;;; ============================================================================
;;; Proofs
;;; ============================================================================

(defstruct smt-proof
  "Sparse Merkle tree proof."
  (key nil)                           ; Key being proven
  (value nil)                         ; Value (nil for non-membership)
  (siblings nil :type list))          ; Sibling hashes along path

(defun smt-generate-proof (smt key)
  "Generate proof for key (membership or non-membership)."
  (let* ((depth (sparse-merkle-tree-depth smt))
         (path (key-to-path key depth))
         (value (smt-get smt key))
         (siblings nil))
    ;; Collect siblings along path
    (loop for level from 0 below depth do
      (let* ((bit (nth (- depth level 1) path))
             (sibling-path (copy-list path)))
        (setf (nth (- depth level 1) sibling-path) (- 1 bit))
        (push (smt-get-node smt sibling-path level) siblings)))
    (make-smt-proof :key key
                    :value value
                    :siblings (nreverse siblings))))

(defun smt-verify-proof (root proof depth)
  "Verify SMT proof against root."
  (let* ((key (smt-proof-key proof))
         (value (smt-proof-value proof))
         (siblings (smt-proof-siblings proof))
         (path (key-to-path key depth))
         (current (or value
                      (make-array 32 :element-type '(unsigned-byte 8)
                                     :initial-element 0))))
    (loop for level from 0 below depth
          for sibling in siblings do
      (let ((bit (nth (- depth level 1) path)))
        (setf current
              (if (zerop bit)
                  (hash-node current sibling)
                  (hash-node sibling current)))))
    (equalp current root)))

(defun smt-verify-non-membership (root proof depth)
  "Verify that key is NOT in the tree."
  (and (null (smt-proof-value proof))
       (smt-verify-proof root proof depth)))
