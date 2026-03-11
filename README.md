# cl-merkle-trees

Pure Common Lisp Merkle tree implementation with SHA256d hashing.

## Features

- **Zero Dependencies**: Pure Common Lisp with no external libraries
- **Bitcoin-Compatible**: Uses SHA256d (double SHA-256) as specified in Bitcoin
- **SPV Proofs**: Generate and verify Merkle proofs for O(log n) inclusion verification
- **Portable**: Runs on any ANSI Common Lisp implementation

## Installation

Clone this repository and load via ASDF:

```lisp
(asdf:load-system "cl-merkle-trees")
```

## Usage

### Basic Merkle Tree

```lisp
(use-package :cl-merkle-trees)

;; Create some transaction hashes
(defvar *tx-hashes*
  (list (sha256 "tx0")
        (sha256 "tx1")
        (sha256 "tx2")
        (sha256 "tx3")))

;; Compute the Merkle root
(defvar *root* (compute-merkle-root *tx-hashes*))
(format t "Root: ~A~%" (bytes-to-hex *root*))
```

### Merkle Proofs (SPV Verification)

```lisp
;; Generate a proof for transaction at index 2
(defvar *proof* (compute-merkle-proof *tx-hashes* 2))

;; Verify the proof against the known root
(verify-merkle-proof *proof* *root*)  ; => T

;; Verification fails with wrong root
(verify-merkle-proof *proof* (sha256 "wrong"))  ; => NIL
```

### Building Complete Trees

```lisp
;; Build the full tree structure (all levels)
(defvar *tree* (build-merkle-tree *tx-hashes*))

;; tree is a list of levels: ((leaves) (parents) ... (root))
(length *tree*)           ; => 3 for 4 transactions
(length (first *tree*))   ; => 4 (leaves)
(length (third *tree*))   ; => 1 (root)
```

## API Reference

### Hash Functions

- `(sha256 data)` - Compute SHA-256 hash (32 bytes)
- `(sha256d data)` - Compute double SHA-256 (32 bytes)

### Tree Construction

- `(compute-merkle-root tx-hashes)` - Compute root from list of hashes
- `(build-merkle-tree tx-hashes)` - Build complete tree (all levels)
- `(merkle-hash-pair left right)` - Hash two nodes together
- `(merkle-level hashes)` - Compute one level from the level below

### Proofs

- `(compute-merkle-proof tx-hashes index)` - Generate inclusion proof
- `(verify-merkle-proof proof root)` - Verify proof against root

### Utilities

- `(bytes-to-hex bytes)` - Convert bytes to hex string
- `(hex-to-bytes string)` - Convert hex string to bytes
- `(merkle-tree-depth n)` - Calculate tree depth for n leaves
- `(merkle-tree-size n)` - Calculate total nodes for n leaves

## Algorithm Details

### Tree Structure

The Merkle tree is a balanced binary tree:
- Leaf nodes are transaction hashes
- Each parent is SHA256d(left-child || right-child)
- Odd-numbered levels duplicate the last element

```
                    Root
                     |
         +-----------+-----------+
         |                       |
      Hash01                  Hash23
         |                       |
    +----+----+             +----+----+
    |         |             |         |
  Hash0    Hash1          Hash2    Hash3
    |         |             |         |
   Tx0       Tx1           Tx2       Tx3
```

### Proof Size

Proofs are O(log n) in size:
- 4 transactions: 2 siblings
- 1000 transactions: ~10 siblings
- 1,000,000 transactions: ~20 siblings

## Testing

```lisp
(asdf:test-system "cl-merkle-trees")
```

Or run tests directly:

```lisp
(cl-merkle-trees.test:run-tests)
```

## License

BSD-3-Clause

Copyright (c) 2024-2026 Parkian Company LLC. All rights reserved.
