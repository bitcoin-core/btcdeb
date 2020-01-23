# btcdeb

Bitcoin Script debugging utilities.

This is a set of tools used to debug or construct scripts for use in Bitcoin.

[![Build Status](https://travis-ci.org/kallewoof/btcdeb.svg?branch=master)](https://travis-ci.org/kallewoof/btcdeb)

## Preparation

Mac users need the macOS command line tools:

```
xcode-select --install
```

And [Homebrew](https://brew.sh/).

## Dependencies

btcdeb depends on the following:

* libtool
* libssl
* autoconf

Ubuntu/debian users can do: `apt-get install libtool libssl-dev autoconf` (with `sudo` prepended if necessary)

Mac users can do: `brew install libtool autoconf`

## Installation

On linux or mac, grab the source code and do:
```Bash
$ ./autogen.sh
$ ./configure
$ make
$ sudo make install
```

If any of those give an error, please file an issue and I'll take a look. It could
be a dependency that I forgot about.

## Emscripten

You can compile btcdeb tools into JavaScript using [emscripten](http://kripken.github.io/emscripten-site/).

After installing the SDK, compile btcdeb tools with the following commands:
```Bash
$ make clean
$ emconfigure ./configure
$ emmake make
$ for i in btcdeb btcc mastify merklebranch; do mv $i $i.bc && emcc -O2 $i.bc libbitcoin.a -o $i.js; done
```
and then instead of doing `./btcdeb` you do `node btcdeb.js` (or `mastify.js`, etc).

The last part is done because emscripten's `emcc` expects the input bytecode file to have the `.bc` extension, whereas the makefile generates files with no extension.

Note: most things work, but the console in btcdeb does not. You can work around this by doing `echo -n -e "step\n\n\n"` (with sufficient `\n`s).

## Script debugger

The `btcdeb` command can step through a Bitcoin Script and show stack content and operations on a per op level. 
```
btcdeb> help
step     Execute one instruction and iterate in the script.
rewind   Go back in time one instruction.
stack    Print stack content.
altstack Print altstack content.
vfexec   Print vfexec content.
exec     Execute command.
tf       Transform a value using a given function.
print    Print script.
help     Show help information.
```

(note this example will fail on the OP_CHECKSIG part; see "Signature checking" below).

```Bash
$ btcdeb '[OP_DUP OP_HASH160 897c81ac37ae36f7bc5b91356cfb0138bfacb3c1 OP_EQUALVERIFY OP_CHECKSIG]' 3045022100c7d8e302908fdc601b125c2734de63ed3bf54353e13a835313c2a2aa5e8f21810220131fad73787989d7fbbdbbd8420674f56bdf61fed5dc2653c826a4789c68501101 03b05bdbdf395e495a61add92442071e32703518b8fca3fc34149db4b56c93be42
valid script
5 op script loaded. type `help` for usage information
script                                                             |                                                             stack
-------------------------------------------------------------------+-------------------------------------------------------------------
OP_DUP                                                             | 03b05bdbdf395e495a61add92442071e32703518b8fca3fc34149db4b56c93be42
OP_HASH160                                                         | 3045022100c7d8e302908fdc601b125c2734de63ed3bf54353e13a835313c2a...
897c81ac37ae36f7bc5b91356cfb0138bfacb3c1                           |
OP_EQUALVERIFY                                                     |
OP_CHECKSIG                                                        |
#0001 OP_DUP
btcdeb>
```

### Signature checking

In order to run an OP_CHECKSIG command, the debugger needs to know about the transaction being checked, since it creates the signature hash from the transaction content. You can pass the transaction to `btcdeb` when you run it, using the `--tx=amount1,amount2:hexdata`, where `amountN` is the amount of the inputs of the transaction, and `hexdata` is the hexadecimal representation of the entire transaction (not just the transaction ID). For example, to verify transaction ID c2fdfbcbef9acb6107eb5d18c172f234ee694254be1128d29b85b80b9bad9b3a, the following will produce an output of TRUE.

```Bash
> $ btcdeb --tx=0.3315983:02000000013a9bad9b0bb8859bd22811be544269ee34f272c1185deb0761cb9aefcbfbfdc2000000006a47304402200cc8b0471a38edad2ff9f9799521b7d948054817793c980eaf3a6637ddfb939702201c1a801461d4c3cf4de4e7336454dba0dd70b89d71f221e991cb6a79df1a860d012102ce9f5972fe1473c9b6948949f676bbf7893a03c5b4420826711ef518ceefd8dcfeffffff0226f20b00000000001976a914d138551aa10d1f891ba02689390f32ce09b71c1788ac28b0ed01000000001976a914870c7d8085e1712539d8d78363865c42d2b5f75a88ac5b880800 '[OP_DUP OP_HASH160 1290b657a78e201967c22d8022b348bd5e23ce17 OP_EQUALVERIFY OP_CHECKSIG ]' 304402200cc8b0471a38edad2ff9f9799521b7d948054817793c980eaf3a6637ddfb939702201c1a801461d4c3cf4de4e7336454dba0dd70b89d71f221e991cb6a79df1a860d01 02ce9f5972fe1473c9b6948949f676bbf7893a03c5b4420826711ef518ceefd8dc
btcdeb -- type `btcdeb -h` for start up options
got transaction 7aba9a51fa8d8441c3e46b76e7dfeef2363d89e1b64fed142632e043cef7e24f:
CTransaction(hash=7aba9a51fa, ver=2, vin.size=1, vout.size=2, nLockTime=559195)
    CTxIn(COutPoint(c2fdfbcbef, 0), scriptSig=47304402200cc8b0471a38ed, nSequence=4294967294)
    CScriptWitness()
    CTxOut(nValue=0.00782886, scriptPubKey=76a914d138551aa10d1f891ba02689)
    CTxOut(nValue=0.32354344, scriptPubKey=76a914870c7d8085e1712539d8d783)

valid script
5 op script loaded. type `help` for usage information
script                                   |                                                             stack
-----------------------------------------+-------------------------------------------------------------------
OP_DUP                                   | 02ce9f5972fe1473c9b6948949f676bbf7893a03c5b4420826711ef518ceefd8dc
OP_HASH160                               | 304402200cc8b0471a38edad2ff9f9799521b7d948054817793c980eaf3a663...
1290b657a78e201967c22d8022b348bd5e23ce17 |
OP_EQUALVERIFY                           |
OP_CHECKSIG                              |
#0000 OP_DUP
btcdeb>
```

Alternatively, you can pass both the transaction (using `--tx=`) and the input transaction (using `--txin=`). In this case, if you do not provide any other parameters (script/stack data), `btcdeb` will automatically figure out the script and stack content for verifying the input specified by the `txin` hex. You also do not need to include the amounts when passing the `txin` explicitly.

```Bash
$ btcdeb --tx=010000000001019086ce64fce1bb086395faf6fac37c73f32ba4ea89330432bf8ee8035e9315aa0100000000ffffffff021353b9030000000017a914c3f413d0918853a8e23766678d2e3c2e5c8138bb8725e4973100000000220020701a8d401c84fb13e6baf169d59684e17abd9fa216c8cc5b9fc63d622ff8c58d040047304402207f874ef00f11dcc9a621acad9354f3fca1bf90c43878f607b7e2d358088487e7022052a01b47b8eef5e1c96a6affdc3dac46fdc11b60612464dc8c5921a852090d2701483045022100c56ab2abb17fdf565417228763bc9f2940a6465042fd62fbd9f4c7406345d7f702201cb1a56b45181f8347713627b325ec5df48fc1aee6bdaf937cbb804d7409b10c016952210375e00eb72e29da82b89367947f29ef34afb75e8654f6ea368e0acdfd92976b7c2103a1b26313f430c4b15bb1fdce663207659d8cac749a0e53d70eff01874496feff2103c96d495bfdd5ba4145e3e046fee45e84a8a48ad05bd8dbb395c011a32cf9f88053ae00000000 \
--txin=0100000000010170a6ee35199eae2d8ea659561374fa704f8fd95188ff5931157e4598dd0c44020100000000ffffffff0280f0fa02000000001976a914eec426a744f7a3b2ffd346925ac832e248834dd788ac4013543500000000220020701a8d401c84fb13e6baf169d59684e17abd9fa216c8cc5b9fc63d622ff8c58d04004730440220054c0b331a31496d9123aeabe8415b8d2f877f1cf67709120af4eb1e09de59e002206cdf84e733e23be531aff202f868d200773e22aa0037033a74fc6752df2fd19601483045022100b54fa12828d13b58cb654dd910b9e8b36d471d644d8f66516577990ca099ee19022048ea2ac78f964d1b823af70c13c5607a29b14bb2348022190b3c280f51ec5df2016952210375e00eb72e29da82b89367947f29ef34afb75e8654f6ea368e0acdfd92976b7c2103a1b26313f430c4b15bb1fdce663207659d8cac749a0e53d70eff01874496feff2103c96d495bfdd5ba4145e3e046fee45e84a8a48ad05bd8dbb395c011a32cf9f88053ae00000000
btcdeb -- type `./btcdeb -h` for start up options
got segwit transaction:
CTransaction(hash=bf19bb6924, ver=1, vin.size=1, vout.size=2, nLockTime=0)
    CTxIn(COutPoint(aa15935e03, 1), scriptSig=)
    CScriptWitness(, 304402207f874ef00f11dcc9a621acad9354f3fca1bf90c43878f607b7e2d358088487e7022052a01b47b8eef5e1c96a6affdc3dac46fdc11b60612464dc8c5921a852090d2701, 3045022100c56ab2abb17fdf565417228763bc9f2940a6465042fd62fbd9f4c7406345d7f702201cb1a56b45181f8347713627b325ec5df48fc1aee6bdaf937cbb804d7409b10c01, 52210375e00eb72e29da82b89367947f29ef34afb75e8654f6ea368e0acdfd92976b7c2103a1b26313f430c4b15bb1fdce663207659d8cac749a0e53d70eff01874496feff2103c96d495bfdd5ba4145e3e046fee45e84a8a48ad05bd8dbb395c011a32cf9f88053ae)
    CTxOut(nValue=0.62477075, scriptPubKey=a914c3f413d0918853a8e23766678d)
    CTxOut(nValue=8.32037925, scriptPubKey=0020701a8d401c84fb13e6baf169d5)

got input tx #0:
CTransaction(hash=aa15935e03, ver=1, vin.size=1, vout.size=2, nLockTime=0)
    CTxIn(COutPoint(02440cdd98, 1), scriptSig=)
    CScriptWitness(, 30440220054c0b331a31496d9123aeabe8415b8d2f877f1cf67709120af4eb1e09de59e002206cdf84e733e23be531aff202f868d200773e22aa0037033a74fc6752df2fd19601, 3045022100b54fa12828d13b58cb654dd910b9e8b36d471d644d8f66516577990ca099ee19022048ea2ac78f964d1b823af70c13c5607a29b14bb2348022190b3c280f51ec5df201, 52210375e00eb72e29da82b89367947f29ef34afb75e8654f6ea368e0acdfd92976b7c2103a1b26313f430c4b15bb1fdce663207659d8cac749a0e53d70eff01874496feff2103c96d495bfdd5ba4145e3e046fee45e84a8a48ad05bd8dbb395c011a32cf9f88053ae)
    CTxOut(nValue=0.50000000, scriptPubKey=76a914eec426a744f7a3b2ffd34692)
    CTxOut(nValue=8.94702400, scriptPubKey=0020701a8d401c84fb13e6baf169d5)

input tx index = 0; tx input vout = 1; value = 894702400
valid script
6 op script loaded. type `help` for usage information
script                                                             |                                                             stack
-------------------------------------------------------------------+-------------------------------------------------------------------
2                                                                  | 3045022100c56ab2abb17fdf565417228763bc9f2940a6465042fd62fbd9f4c...
0375e00eb72e29da82b89367947f29ef34afb75e8654f6ea368e0acdfd92976b7c | 304402207f874ef00f11dcc9a621acad9354f3fca1bf90c43878f607b7e2d35...
03a1b26313f430c4b15bb1fdce663207659d8cac749a0e53d70eff01874496feff |                                                                 0x
03c96d495bfdd5ba4145e3e046fee45e84a8a48ad05bd8dbb395c011a32cf9f880 |
3                                                                  |
OP_CHECKMULTISIG                                                   |
#0001 2
btcdeb>
```

## Script compiler

The `btcc` command can interpret a script in its human readable form and will
return a corresponding Bitcoin Script.

```Bash
$ btcc OP_DUP OP_HASH160 897c81ac37ae36f7bc5b91356cfb0138bfacb3c1 OP_EQUALVERIFY OP_CHECKSIG
76a914897c81ac37ae36f7bc5b91356cfb0138bfacb3c188ac
```

The above is the script pub key for a transaction in Bitcoin in human readable format turned into its hexadecimal representation.

## MAST stuff

`btcdeb` also has some stuff related to MAST (merkelized abstract syntax trees), based on the implementation by Mark Friedenbach, in the [mbv-taileval](https://github.com/kallewoof/btcdeb/tree/mbv-taileval) branch.

There are two commands, `merklebranch` and `mastify`.

The former is more low-level than the latter; `merklebranch` lets you give parameters for a MAST merkle tree, and it will produce the root/path/proof/etc
for that tree.

`mastify` lets you convert a regular Bitcoin Script into a MAST version. It works in two modes; general mode, where it simply gives you the needed stuff to fund, and execution mode, where it gives you the needed parameters to spend a previously funded MAST-ified output.

The mode is determined by whether you passed any parameters into `mastify` or not. No parameters means general mode, and one or more means execution mode.

Example:
```Bash
./mastify "[
OP_IF
  144
  OP_CHECKSEQUENCEVERIFY
  OP_DROP
  020c23a5f833b3cb2a29bf81e246886e0ea098989b359c401655c96d3f1a37567a
OP_ELSE
  0375ceeb0d9d99ff238f85aa5d18e318c7f0a84d3b7bec31a99df66df0bf887ee4
OP_ENDIF
OP_CHECKSIG
]"
```
will give you the fund information (0 parameters), and
```Bash
./mastify "[
OP_IF
  144
  OP_CHECKSEQUENCEVERIFY
  OP_DROP
  020c23a5f833b3cb2a29bf81e246886e0ea098989b359c401655c96d3f1a37567a
OP_ELSE
  0375ceeb0d9d99ff238f85aa5d18e318c7f0a84d3b7bec31a99df66df0bf887ee4
OP_ENDIF
OP_CHECKSIG
]" 0x 0x
```
will give you the spending information for the case where OP_IF returns `false` (change the second 0x to 01 instead, to see the `else` case).

Both `merklebranch` and `mastify` let you pipe the output directly into a btcdeb session; to do so, simply pass `--btcdeb` to the call to `merklebranch` or `mastify`, and pipe that to btcdeb:
```Bash
./btcdeb $(./mastify --btcdeb "[
OP_IF
  144
  OP_CHECKSEQUENCEVERIFY
  OP_DROP
  020c23a5f833b3cb2a29bf81e246886e0ea098989b359c401655c96d3f1a37567a
OP_ELSE
  0375ceeb0d9d99ff238f85aa5d18e318c7f0a84d3b7bec31a99df66df0bf887ee4
OP_ENDIF
OP_CHECKSIG
]" 0x 01)
```
