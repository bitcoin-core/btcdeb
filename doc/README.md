# Documentation for btcdeb

## Specific documentation

See [mock-values.md](mock-values.md) for information on how to use mock signatures/keys, and for hints on using inline operators such as `OP_DUP OP_HASH160 hash160(foo) OP_EQUALVERIFY`.

## Patch files

File starting with `patch-bitcoin-core-` can be used to patch a sub-set of the Bitcoin Core code base into an instance of btcdeb. For any release of btcdeb, the relevant files should be an exact match of the release version of btcdeb, or somthing is suspicious. (You need to ensure the patch itself is clean as well, of course.)
