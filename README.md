# cl-merkle-trees

Pure Common Lisp Merkle tree implementation with proofs.

## Features

- **Standard Merkle Trees**: Binary trees with proof generation/verification
- **Sparse Merkle Trees**: Key-value storage with 256-bit key space
- **Merkle Accumulators**: Append-only trees (Mountain Range style)
- **Multi-Proofs**: Efficient proofs for multiple leaves
- **SHA-256**: Built-in hash function (zero dependencies)

## Installation

```bash
cd ~/quicklisp/local-projects/  # or ~/common-lisp/
git clone https://github.com/parkianco/cl-merkle-trees.git
```

```lisp
(asdf:load-system :cl-merkle-trees)
```

## Quick Start

### Standard Merkle Tree

```lisp
(use-package :cl-merkle-trees)

;; Create tree from data
(let* ((tree (make-merkle-tree '("alice" "bob" "carol" "dave")))
       ;; Generate proof for index 1 (bob)
       (proof (generate-proof tree 1)))
  ;; Verify proof
  (verify-proof tree proof))  ; => T
```

### Sparse Merkle Tree

```lisp
;; Create empty SMT
(let* ((smt (make-sparse-merkle-tree :depth 256))
       ;; Set values
       (smt (smt-set smt (sha256 "key1") "value1"))
       (smt (smt-set smt (sha256 "key2") "value2")))
  ;; Generate proof
  (let ((proof (smt-generate-proof smt (sha256 "key1"))))
    (smt-verify-proof (smt-root smt) proof 256)))  ; => T
```

### Merkle Accumulator

```lisp
;; Create accumulator
(let ((acc (make-merkle-accumulator)))
  ;; Append data
  (setf acc (accumulator-append acc "item1"))
  (setf acc (accumulator-append acc "item2"))
  (setf acc (accumulator-append acc "item3"))
  ;; Check size and root
  (accumulator-size acc)  ; => 3
  (accumulator-root acc)) ; => 32-byte hash
```

## API Reference

### Hash Functions
- `sha256` - Compute SHA-256 hash
- `hash-leaf` - Hash leaf with domain separation
- `hash-node` - Hash internal node

### Standard Trees
- `make-merkle-tree` - Create tree from data list
- `merkle-tree-root` - Get root hash
- `tree-insert` - Insert new leaf
- `tree-update` - Update existing leaf

### Proofs
- `generate-proof` - Generate inclusion proof
- `verify-proof` - Verify against tree
- `verify-proof-with-root` - Verify against root hash

### Multi-Proofs
- `generate-multi-proof` - Proof for multiple leaves
- `verify-multi-proof` - Verify multi-proof

### Sparse Merkle Trees
- `make-sparse-merkle-tree` - Create empty SMT
- `smt-get` / `smt-set` / `smt-delete` - CRUD operations
- `smt-generate-proof` / `smt-verify-proof` - Proofs

### Accumulators
- `make-merkle-accumulator` - Create empty accumulator
- `accumulator-append` - Append data
- `accumulator-root` / `accumulator-size` - Properties

## License

BSD-3-Clause. See [LICENSE](LICENSE).

## Author

Parkian Company LLC
