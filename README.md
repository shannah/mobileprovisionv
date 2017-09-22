# mobileprovisionv

A CLI tool to validate an iOS provisioning profile against a private key

## Requirements

* OS X (it relies on a few command-line tools found in OS X).
* [NodeJS](https://nodejs.org/en/)

## Installation

~~~~
$ sudo npm install -g mobileprovisionv
~~~~

## Usage

Given a `.p12` file:

~~~~
$ mobileprovisionv /path/to/app_profile.mobileprovision \
    /path/to/keyfile.p12 mypassword
~~~~

or With a `.key` file:

~~~~
$ mobileprovisionv /path/to/app_profile.mobileprovision \
    /path/to/keyfile.key mypassword
~~~~

Output:

If the profile matches the key file, then it will output "1" to STDOUT.  If it does not match it outputs "0".  If any of the files are malformed or there is an IO error (e.g. file not found), it will explode in a big mess (java stack trace).
