# btcdeb

Bitcoin Script debugging utilities.

This is a set of tools used to debug or construct scripts for use in Bitcoin.

[![Build Status](https://travis-ci.org/bitcoin-core/btcdeb.svg?branch=master)](https://travis-ci.org/bitcoin-core/btcdeb)

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
* automake/autoconf
* pkg-config

Ubuntu/debian users can do: `apt-get install libtool libssl-dev autoconf pkg-config` (with `sudo` prepended if necessary)

Mac users can do: `brew install libtool automake pkg-config`

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
$ for i in btcdeb btcc tap; do mv $i $i.bc && emcc -O2 $i.bc libbitcoin.a -o $i.js; done
```
and then instead of doing `./btcdeb` you do `node btcdeb.js` (or `mastify.js`, etc).

The last part is done because emscripten's `emcc` expects the input bytecode file to have the `.bc` extension, whereas the makefile generates files with no extension.

Note: most things work, but the console in btcdeb does not. You can work around this by doing `echo -n -e "step\n\n\n"` (with sufficient `\n`s).

## Script debugger

The `btcdeb` command can step through a Bitcoin Script and show stack content and operations on a per op level. See [doc/btcdeb.md](doc/btcdeb.md) for details on usage.

## Script compiler

The `btcc` command can interpret a script in its human readable form and will
return a corresponding Bitcoin Script.

```Bash
$ btcc OP_DUP OP_HASH160 897c81ac37ae36f7bc5b91356cfb0138bfacb3c1 OP_EQUALVERIFY OP_CHECKSIG
76a914897c81ac37ae36f7bc5b91356cfb0138bfacb3c188ac
```

The above is the script pub key for a transaction in Bitcoin in human readable format turned into its hexadecimal representation.
