# hugh

####

hugh is a minimalistic command line password manager.
It is essentially a port of [hush](https://github.com/lechgu/hush) with only bare features left.
Hugh was developed to satisfy the need to manage passwords and other secrets so they can be stored securely in the text format, compatible with git and other version control systems.
Hugh does not require a master password as other password managers do, instead it uses RSA public/private key pair to encrypt and decrypt passwords. These are exactly same keys used for ssh connections to the github and similar.

Hugh will work on Mac, Windows or Linux

### installation

With Go installed on the machine, clone the repository and do

```
go install
```

### quick start

```

hugh generate | hugh encrypt > password.txt

```

The above will generate a random password, encrypt it, and store as a base64 string in the file `password.txt`. This can be checked in into git and so on.

To decrypt the password and store it on the clipbord, on the Mac use:

```

hugh decrypt password.txt | pbcopy

```

The same thing can be achieved on Windows as:

```

hugh decrypt password.txt | clip

```

### configuration

hugh configuration is stored in the file `~/.hugh`, by default.
The file has the following format:

```
private-key: ~/.ssh/your_private_key
public-key: ~/.ssh/your public_key
password-length: 16
character-classes: aA8#
```

Passing the parameters on the command line overrides the ones in configuration.
