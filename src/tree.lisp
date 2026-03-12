;;;; Copyright (c) 2024-2026 Parkian Company LLC. All rights reserved.
;;;; SPDX-License-Identifier: BSD-3-Clause
;;;;
;;;; Merkle tree construction

(in-package :cl-merkle-trees)

;;; ============================================================================
;;; Merkle Tree Structure
;;; ============================================================================

(defstruct (merkle-tree (:constructor %make-merkle-tree))
  "Binary Merkle tree."
  (root nil)                          ; Root hash (32 bytes)
  (leaves nil :type list)             ; Leaf hashes
  (nodes nil :type vector)            ; All nodes (for proof generation)
  (height 0 :type integer)            ; Tree height
  (size 0 :type integer))             ; Number of leaves

;;; ============================================================================
;;; Tree Construction
;;; ============================================================================

(defun next-power-of-2 (n)
  "Return smallest power of 2 >= n."
  (if (<= n 1)
      1
      (ash 1 (integer-length (1- n)))))

(defun make-merkle-tree (data-list &key (hash-fn #'hash-leaf))
  "Construct Merkle tree from list of data items.
   Returns merkle-tree structure."
  (when (null data-list)
    (return-from make-merkle-tree
      (%make-merkle-tree :root (make-array 32 :element-type '(unsigned-byte 8)
                                              :initial-element 0)
                         :leaves nil
                         :nodes (vector)
                         :height 0
                         :size 0)))
  (let* ((leaves (mapcar hash-fn data-list))
         (n (length leaves))
         (padded-n (next-power-of-2 n))
         (height (integer-length (1- padded-n)))
         ;; Pad to power of 2 with empty leaves
         (empty-leaf (make-array 32 :element-type '(unsigned-byte 8)
                                    :initial-element 0))
         (padded-leaves (append leaves
                                (loop repeat (- padded-n n)
                                      collect empty-leaf)))
         ;; Store all nodes level by level (leaves at end)
         (total-nodes (1- (* 2 padded-n)))
         (nodes (make-array total-nodes)))
    ;; Fill in leaves
    (loop for i from 0 below padded-n
          for leaf in padded-leaves do
      (setf (aref nodes (+ (- total-nodes padded-n) i)) leaf))
    ;; Build tree bottom-up
    (loop for level from (1- height) downto 0 do
      (let ((level-start (1- (ash 1 level)))
            (level-size (ash 1 level)))
        (loop for i from 0 below level-size do
          (let* ((node-idx (+ level-start i))
                 (left-idx (+ (* 2 node-idx) 1))
                 (right-idx (+ (* 2 node-idx) 2))
                 (left (aref nodes left-idx))
                 (right (aref nodes right-idx)))
            (setf (aref nodes node-idx) (hash-node left right))))))
    (%make-merkle-tree :root (aref nodes 0)
                       :leaves leaves
                       :nodes nodes
                       :height height
                       :size n)))

;;; ============================================================================
;;; Tree Operations
;;; ============================================================================

(defun tree-get-leaf (tree index)
  "Get leaf hash at index."
  (let ((n (merkle-tree-size tree)))
    (when (or (< index 0) (>= index n))
      (error "Index ~a out of bounds (0..~a)" index (1- n)))
    (nth index (merkle-tree-leaves tree))))

(defun tree-leaf-index (tree leaf-hash)
  "Find index of leaf with given hash."
  (position leaf-hash (merkle-tree-leaves tree)
            :test #'equalp))

(defun tree-update (tree index new-data &key (hash-fn #'hash-leaf))
  "Update leaf at index, return new tree.
   Original tree is not modified."
  (let* ((n (merkle-tree-size tree))
         (new-leaf (funcall hash-fn new-data))
         (leaves (copy-list (merkle-tree-leaves tree))))
    (when (or (< index 0) (>= index n))
      (error "Index ~a out of bounds (0..~a)" index (1- n)))
    (setf (nth index leaves) new-leaf)
    ;; Rebuild tree with new leaves
    (let* ((height (merkle-tree-height tree))
           (padded-n (ash 1 height))
           (empty-leaf (make-array 32 :element-type '(unsigned-byte 8)
                                      :initial-element 0))
           (padded-leaves (append leaves
                                  (loop repeat (- padded-n n)
                                        collect empty-leaf)))
           (total-nodes (1- (* 2 padded-n)))
           (nodes (make-array total-nodes)))
      ;; Fill leaves
      (loop for i from 0 below padded-n
            for leaf in padded-leaves do
        (setf (aref nodes (+ (- total-nodes padded-n) i)) leaf))
      ;; Rebuild tree
      (loop for level from (1- height) downto 0 do
        (let ((level-start (1- (ash 1 level)))
              (level-size (ash 1 level)))
          (loop for i from 0 below level-size do
            (let* ((node-idx (+ level-start i))
                   (left-idx (+ (* 2 node-idx) 1))
                   (right-idx (+ (* 2 node-idx) 2))
                   (left (aref nodes left-idx))
                   (right (aref nodes right-idx)))
              (setf (aref nodes node-idx) (hash-node left right))))))
      (%make-merkle-tree :root (aref nodes 0)
                         :leaves leaves
                         :nodes nodes
                         :height height
                         :size n))))

(defun tree-insert (tree new-data &key (hash-fn #'hash-leaf))
  "Insert new leaf, return new tree.
   May increase tree height if needed."
  (let ((new-leaves (append (merkle-tree-leaves tree)
                            (list (funcall hash-fn new-data)))))
    ;; Rebuild with new leaf
    (let* ((n (length new-leaves))
           (padded-n (next-power-of-2 n))
           (height (integer-length (1- padded-n)))
           (empty-leaf (make-array 32 :element-type '(unsigned-byte 8)
                                      :initial-element 0))
           (padded-leaves (append new-leaves
                                  (loop repeat (- padded-n n)
                                        collect empty-leaf)))
           (total-nodes (1- (* 2 padded-n)))
           (nodes (make-array total-nodes)))
      ;; Fill leaves
      (loop for i from 0 below padded-n
            for leaf in padded-leaves do
        (setf (aref nodes (+ (- total-nodes padded-n) i)) leaf))
      ;; Build tree
      (loop for level from (1- height) downto 0 do
        (let ((level-start (1- (ash 1 level)))
              (level-size (ash 1 level)))
          (loop for i from 0 below level-size do
            (let* ((node-idx (+ level-start i))
                   (left-idx (+ (* 2 node-idx) 1))
                   (right-idx (+ (* 2 node-idx) 2))
                   (left (aref nodes left-idx))
                   (right (aref nodes right-idx)))
              (setf (aref nodes node-idx) (hash-node left right))))))
      (%make-merkle-tree :root (aref nodes 0)
                         :leaves new-leaves
                         :nodes nodes
                         :height height
                         :size n))))
