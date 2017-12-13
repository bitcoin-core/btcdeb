# btcdeb

Bitcoin Script debugging utilities.

## Script compiler

The `btcc` command can interpret a script in its human readable form and will
return a corresponding Bitcoin Script.

```Bash
$ btcc OP_DUP OP_HASH160 897c81ac37ae36f7bc5b91356cfb0138bfacb3c1 OP_EQUALVERIFY OP_CHECKSIG
76a914897c81ac37ae36f7bc5b91356cfb0138bfacb3c188ac
```

The above is the script pub key for a transaction in Bitcoin in human readable format turned into its hexadecimal representation.

```Bash
$ btcc 483045022100c7d8e302908fdc601b125c2734de63ed3bf54353e13a835313c2a2aa5e8f21810220131fad73787989d7fbbdbbd8420674f56bdf61fed5dc2653c826a4789c685011012103b05bdbdf395e495a61add92442071e32703518b8fca3fc34149db4b56c93be42
4c6b483045022100c7d8e302908fdc601b125c2734de63ed3bf54353e13a835313c2a2aa5e8f21810220131fad73787989d7fbbdbbd8420674f56bdf61fed5dc2653c826a4789c685011012103b05bdbdf395e495a61add92442071e32703518b8fca3fc34149db4b56c93be42
```

The above took the script sig for a transaction as the script, and the output was the signature and the public key.

## Script debugger

The `btcdeb` command can step through a Bitcoin Script and show stack content and operations on a per op level.

```Bash
$ btcdeb 76a914897c81ac37ae36f7bc5b91356cfb0138bfacb3c188ac 3045022100c7d8e302908fdc601b125c2734de63ed3bf54353e13a835313c2a2aa5e8f21810220131fad73787989d7fbbdbbd8420674f56bdf61fed5dc2653c826a4789c68501101 03b05bdbdf395e495a61add92442071e32703518b8fca3fc34149db4b56c93be42
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
