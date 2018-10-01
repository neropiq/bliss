[![Build Status](https://travis-ci.org/AidosKuneen/bliss.svg?branch=master)](https://travis-ci.org/AidosKuneen/bliss)
[![GitHub license](https://img.shields.io/badge/license-MIT-blue.svg)](https://raw.githubusercontent.com/AidosKuneen/bliss/LICENSE)
[![GoDoc](https://godoc.org/github.com/AidosKuneen/bliss?status.svg)](https://godoc.org/github.com/AidosKuneen/bliss)
[![Coverage Status](https://coveralls.io/repos/github/AidosKuneen/bliss/badge.svg?branch=master)](https://coveralls.io/github/AidosKuneen/bliss?branch=master)

# bliss 

## Overview

This library is for signing messages by [BLISS](http://bliss.di.ens.fr/).

## Requirements

* git
* go 1.9+

are required to compile this.

## Installation

     $ go get github.com/AidosKuneen/bliss


## Usage

```go
	text:=[]byte("some message")
	var seed [64]byte
	_, err := rand.Read(seed[:])
	pk := NewPrivateKey(bliss.B4, seed)
	pub := pk.PublicKey()
	sig := pk.Sign(text)
	err := pub.Verify(sig, text)
	bpub := pub.Bytes()
	bsig := sig.Bytes()
	pub2, err := NewPublicKey(bpub)
	sig2, err := NewSignature(bsig)

```

## Contribution
Improvements to the codebase and pull requests are encouraged.


## Dependencies and Licenses

This software includes a rewrite (from C++ to go)  of https://github.com/SRI-CSL/Bliss,
which is covered by MIT License.

```
golang.org/x/crypto                                          BSD 3-clause "New" or "Revised" License 
Golang Standard Library                                   BSD 3-clause License
```