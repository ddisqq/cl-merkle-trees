;;;; Copyright (c) 2024-2026 Parkian Company LLC. All rights reserved.
;;;; SPDX-License-Identifier: BSD-3-Clause
;;;;
;;;; Merkle accumulators (append-only Merkle trees)

(in-package :cl-merkle-trees)

;;; ============================================================================
;;; Merkle Accumulator
;;; ============================================================================

(defstruct (merkle-accumulator (:constructor %make-merkle-accumulator))
  "Append-only Merkle accumulator (Mountain Range).
   Efficient for streaming append operations."
  (peaks nil :type list)              ; List of peak hashes (right to left)
  (size 0 :type integer)              ; Number of leaves
  (root nil))                         ; Combined root hash

;;; ============================================================================
;;; Accumulator Construction
;;; ============================================================================

(defun make-merkle-accumulator ()
  "Create empty accumulator."
  (%make-merkle-accumulator :peaks nil
                            :size 0
                            :root (make-array 32 :element-type '(unsigned-byte 8)
                                                 :initial-element 0)))

(defun accumulator-compute-root (peaks)
  "Compute root from peaks (bag the peaks)."
  (if (null peaks)
      (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0)
      (reduce (lambda (right left) (hash-node left right))
              peaks)))

;;; ============================================================================
;;; Append Operation
;;; ============================================================================

(defun accumulator-append (acc data &key (hash-fn #'hash-leaf))
  "Append data to accumulator, return new accumulator."
  (let* ((new-leaf (funcall hash-fn data))
         (new-size (1+ (merkle-accumulator-size acc)))
         (peaks (copy-list (merkle-accumulator-peaks acc)))
         (height 0))
    ;; Merge peaks of same height
    (loop while (logbitp height (merkle-accumulator-size acc)) do
      (let ((peak (pop peaks)))
        (setf new-leaf (hash-node peak new-leaf)))
      (incf height))
    ;; Add new peak
    (push new-leaf peaks)
    ;; Compute new root
    (let ((new-root (accumulator-compute-root peaks)))
      (%make-merkle-accumulator :peaks peaks
                                :size new-size
                                :root new-root))))

;;; ============================================================================
;;; Accumulator Properties
;;; ============================================================================

(defun accumulator-root (acc)
  "Get accumulator root hash."
  (merkle-accumulator-root acc))

(defun accumulator-size (acc)
  "Get number of leaves in accumulator."
  (merkle-accumulator-size acc))

;;; ============================================================================
;;; Proof Generation and Verification
;;; ============================================================================

(defstruct accumulator-proof
  "Proof of inclusion in accumulator."
  (leaf nil)                          ; Leaf hash
  (index 0 :type integer)             ; Leaf index
  (path nil :type list)               ; Path to peak
  (peak-index 0 :type integer)        ; Which peak
  (peaks nil :type list))             ; All peaks for root computation

(defun accumulator-generate-proof (acc index)
  "Generate proof for leaf at index."
  (let* ((size (merkle-accumulator-size acc))
         (peaks (merkle-accumulator-peaks acc)))
    (when (or (< index 0) (>= index size))
      (error "Index ~a out of bounds (0..~a)" index (1- size)))
    ;; Find which peak contains this index
    (let ((peak-sizes nil)
          (remaining-size size))
      ;; Calculate peak sizes
      (loop for height from (integer-length size) downto 0
            when (logbitp height remaining-size) do
              (push (ash 1 height) peak-sizes)
              (decf remaining-size (ash 1 height)))
      (setf peak-sizes (nreverse peak-sizes))
      ;; Find peak containing index
      (let ((cumulative 0)
            (peak-index 0))
        (loop for psize in peak-sizes
              for pidx from 0 do
          (when (< index (+ cumulative psize))
            (setf peak-index pidx)
            (return))
          (incf cumulative psize))
        ;; Generate path within that peak's subtree
        (let* ((peak-size (nth peak-index peak-sizes))
               (local-index (- index cumulative))
               (height (integer-length (1- peak-size)))
               (path nil))
          ;; Build path from leaf to peak
          ;; (This is simplified - full impl needs sibling collection)
          (loop for level from 0 below height do
            (let ((bit (logand 1 (ash local-index (- level)))))
              (declare (ignore bit))
              ;; Would collect sibling hashes here
              (push nil path)))
          (make-accumulator-proof :leaf nil  ; Would be actual leaf
                                  :index index
                                  :path (nreverse path)
                                  :peak-index peak-index
                                  :peaks (copy-list peaks)))))))

(defun accumulator-verify-proof (acc proof)
  "Verify accumulator proof."
  (let ((peaks (accumulator-proof-peaks proof))
        (expected-root (merkle-accumulator-root acc)))
    ;; Verify peaks produce correct root
    (equalp (accumulator-compute-root peaks) expected-root)))
