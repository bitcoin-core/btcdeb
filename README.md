# btcdeb

Bitcoin Script debugging utilities.

This is a set of tools used to debug or construct scripts for use in Bitcoin.

[![Build Status](https://travis-ci.org/kallewoof/btcdeb.svg?branch=master)](https://travis-ci.org/kallewoof/btcdeb)

## Dependencies

btcdeb depends on the following libraries:

* libssl
* libboost

Mac users can do `brew install boost`, ubuntu/debian users can do `apt-get install libboost-all-dev libssl-dev` (with `sudo` prepended if necessary).

## Installation

On linux or mac, grab the source code and do:
```Bash
$ ./autogen.sh
$ ./configure
$ make
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

## Script compiler

The `btcc` command can interpret a script in its human readable form and will
return a corresponding Bitcoin Script.

```Bash
$ btcc OP_DUP OP_HASH160 897c81ac37ae36f7bc5b91356cfb0138bfacb3c1 OP_EQUALVERIFY OP_CHECKSIG
76a914897c81ac37ae36f7bc5b91356cfb0138bfacb3c188ac
```

The above is the script pub key for a transaction in Bitcoin in human readable format turned into its hexadecimal representation.

## MAST stuff

btcdeb also has some stuff related to MAST (merkelized abstract syntax trees), based on the implementation by Mark Friedenbach.

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
