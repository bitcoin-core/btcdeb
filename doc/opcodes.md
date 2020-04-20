# Opcodes

Opcodes are a central part of the script language in Bitcoin. In fact, everything is an opcode, split into two types: push opcodes, which put something on the stack, and action opcodes, which do something, often manipulating the data on the stack.

You can read more about Bitcoin Script here: https://en.bitcoin.it/wiki/Script

In btcdeb/btcc, you can express opcodes in two ways:

* By opcode name, e.g. `OP_TRUE`, where you can often (but not always) skip the `OP_` prefix (i.e. `TRUE`)
* By opcode hex code, using the `OP_x` (or simply `x`) prefix, e.g. `OP_xfe` OR `xfe`. This can also be used to express *non-existent opcodes*, such as `OP_xfe` for a template `OP_PUBKEY`, as used in earlier versions of Bitcoin Core

## Trivial

There were template opcodes e.g. `OP_PUBKEY` in Bitcoin Core, which were removed in 0.17.0, in pull request #13194 (https://github.com/bitcoin/bitcoin/pull/13194).
