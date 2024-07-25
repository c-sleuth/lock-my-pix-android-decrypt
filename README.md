# lock-my-pix-android-decrypt

Rough python script that should get the job done in terms of decrypting the files
Also contains a bruteforcing python script that can bruteforce the 4 or 6 digit PINs from a single .6zu file

## Decryption Script

```bash
usage: LockMyPix Decrypt [-h] password input output

positional arguments:
  password    Enter the password for the application
  input       The directory of the exported encrypted files
  output      The directory for the decrypted files

options:
  -h, --help  show this help message and exit
```

## PIN Bruteforce

```bash
usage: LockMyPix Bruteforce [-h] input

positional arguments:
  input       Path to .6zu file

options:
  -h, --help  show this help message and exit
```


