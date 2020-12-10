# FCEF Format specification 

## Ver 1 (v0001) (DEPRECATED)
This document explains the specification of the FCEF file format Ver 1   
**DEPRECATED: due to the vulnerability in the Ver 1 encryption algorithm it's strongly recommended to use Ver 2**

The FCEF format contain(s)
1. nonce & Encrypted Data

**These will be called tags hereafter**     

### Encrypted data
A FCEF file generated with FileCrypt writes the nonce and encrypted data **after 0x0**.
This tag contains the actual data that is used to decrypt.


## Ver 2 (v0002)
This document explains the specification of the FCEF file format Ver 2


[![FCEF visual representation](./res/fcef%20vis.png)]


The FCEF format contain(s)
1. Version number
2. Salt
3. Nonce & Encrypted data

**These will be called tags hereafter**     
**The tag size(excluding Encrypted data) of FCEF Ver2 is 34 bytes**

### Version number
A FCEF file generated with FileCrypt writes the encryption version that it used to encrypt the file **from 0x0 to 0x5**.
It's used to check whether the FCEF file can be decrypted using the current version of the software.
Every version after Ver 1 will contain this tag.   
**Note: the last byte(0x5) of the version tag contains a line brake(`\n`)**    
**Note: the version number ranges from v0001 to v9999**

### Salt
A FCEF file generated with FileCrypt writes the salt generated using `rand.Read(salt)` **from 0x6 to 0x15**
It's used while decrypting to regenerate the argon2 hash from the password.

### Nonce & Encrypted data
A FCEF file generated with FileCrypt writes the nonce **from 0x16-0x21** and encrypted data **after 0x21**.   
This tag contains the actual data that is used to decrypt.

