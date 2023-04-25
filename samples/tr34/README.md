# TR-34 Samples
These samples demonstrate the use of the CCA TR-34 verbs, CSNDT34B, CSNDT34C, CSNDT34D and CSNDT34R.  

The samples are designed to be run from the z/OS UNIX shell.  
## Installation
It is recommended that you upload the REXX programs in TEXT mode to an empty zFS directory, then upload the `minica` executable to that directory in BINARY mode and mark all these files as executable (see below).  If you have the z/OS XL C/C++ compiler, you can upload `minica.c` in TEXT mode and compile it, as described in the comments in the source file.
<pre>
$ <b>ls -al</b>
total 304
drwxr-xr-x   2 OMVSKERN SYS1        8192 Apr 25 10:44 .
drwx------   3 OMVSKERN SYS1        8192 Apr 25 10:41 ..
-rw-r-----   1 OMVSKERN SYS1        7800 Apr 25 10:43 asetup.rexx
-rw-r-----   1 OMVSKERN SYS1        4532 Apr 25 10:43 bbind.rexx
-rw-r-----   1 OMVSKERN SYS1        9621 Apr 25 10:43 c2pass.rexx
-rw-r-----   1 OMVSKERN SYS1       94208 Apr 25 10:44 minica
$ <b>chmod +x *</b>
$ <b>ls -al</b>
total 304
drwxr-xr-x   2 OMVSKERN SYS1        8192 Apr 25 10:44 .
drwx------   3 OMVSKERN SYS1        8192 Apr 25 10:41 ..
-rwxr-x--x   1 OMVSKERN SYS1        7800 Apr 25 10:43 asetup.rexx
-rwxr-x--x   1 OMVSKERN SYS1        4532 Apr 25 10:43 bbind.rexx
-rwxr-x--x   1 OMVSKERN SYS1        9621 Apr 25 10:43 c2pass.rexx
-rwxr-x--x   1 OMVSKERN SYS1       94208 Apr 25 10:44 minica
</pre>
## Running the samples
Before running samples, `bbind.rexx` and `c2pass.rexx`, it is necessary to run `asetup.rexx` to create RSA key pairs and certificate signing requests (CSR) for the Key Distribution Host (KDH) and Key Receiving Device (KRD).  Then use `minica` to sign each of the CSR.  This process will also generate an empty certificate revocation list (CRL), required by the CCA TR-34 verbs.

**Note:** The REXX program, `asetup.rexx`, writes RSA keys to your PKDS, for use by the other programs.  Please check the key labels defined in these sample programs to ensure they do not conflict with existing labels in your PKDS.

The typical sequence of events is shown below (including output):
<pre>
$ <b>./asetup.rexx</b>
CSNDPKB  (PKA Key Token Build                   ) rc=0, reason=0
CSNDPKG  (PKA Key Generate                      ) rc=0, reason=0
CSNDKRC  (PKDS Key Record Create                ) rc=0, reason=0
CSNDKRW  (PKDS Key Record Write                 ) rc=0, reason=0
CSNDPIC  (Public Infrastructure Certificate     ) rc=0, reason=0
Certificate signing request written to kdhcsr.pem
CSNDPKB  (PKA Key Token Build                   ) rc=0, reason=0
CSNDPKG  (PKA Key Generate                      ) rc=0, reason=0
CSNDKRC  (PKDS Key Record Create                ) rc=0, reason=0
CSNDKRW  (PKDS Key Record Write                 ) rc=0, reason=0
CSNDPIC  (Public Infrastructure Certificate     ) rc=0, reason=0
Certificate signing request written to krdcsr.pem
$ <b>ls -al *.pem</b>
-rw-r-----   1 OMVSKERN SYS1        1001 Apr 25 10:53 kdhcsr.pem
-rw-r-----   1 OMVSKERN SYS1        1001 Apr 25 10:54 krdcsr.pem
$ <b>./minica kdhcsr.pem kdhcert.pem</b>
gsk_create_database(tr34.kdb) rc=00000000
Creating self-signed CA certificate. This could take a while...
gsk_create_self_signed_certificate rc=00000000
gsk_export_certificate(TR-34 CA) rc=00000000

CA certificate written to file, tr34cacert.pem

gsk_create_signed_crl rc=00000000

CRL written to file, crl.pem

gsk_create_signed_certificate_record rc=00000000

Signed certificate written to file, kdhcert.pem

$ <b>./minica krdcsr.pem krdcert.pem</b>
gsk_create_database(tr34.kdb) rc=03353013
gsk_open_database(tr34.kdb) rc=00000000
Database contains 10 records
gsk_export_certificate(TR-34 CA) rc=00000000

CA certificate written to file, tr34cacert.pem

gsk_create_signed_crl rc=00000000

CRL written to file, crl.pem

gsk_create_signed_certificate_record rc=00000000

Signed certificate written to file, krdcert.pem

$ <b>ls -al *.pem</b>
-rw-r--r--   1 OMVSKERN SYS1         987 Apr 25 10:59 crl.pem
-rw-r--r--   1 OMVSKERN SYS1        1545 Apr 25 10:58 kdhcert.pem
-rw-r-----   1 OMVSKERN SYS1        1001 Apr 25 10:53 kdhcsr.pem
-rw-r--r--   1 OMVSKERN SYS1        1545 Apr 25 10:59 krdcert.pem
-rw-r-----   1 OMVSKERN SYS1        1001 Apr 25 10:54 krdcsr.pem
-rw-r--r--   1 OMVSKERN SYS1        1964 Apr 25 10:59 tr34cacert.pem
$ <b>./bbind.rexx</b>
CSNDT34C (TR-34 Bind-Complete                   ) rc=0, reason=0
CSNDT34B (TR-34 Bind-Begin                      ) rc=0, reason=0
CSNDT34C (TR-34 Bind-Complete                   ) rc=0, reason=0
$ <b>./c2pass.rexx</b>
/*********************************/
/* Setup steps for key transport */
/*********************************/
CSNBKTB2 (Key Token Build2                      ) rc=0, reason=0
CSNBRNGL (Random Number Generate                ) rc=0, reason=0
CSNBKPI2 (Key Part Import2                      ) rc=0, reason=0
CSNBKPI2 (Key Part Import2                      ) rc=0, reason=0
CSNBKTB2 (Key Token Build2                      ) rc=0, reason=0
CSNBKTB2 (Key Token Build2                      ) rc=0, reason=0
CSNBKGN2 (Key Generate2                         ) rc=0, reason=0
/************************************/
/* Protocol steps for key transport */
/************************************/
CSNBRNGL (Random Number Generate                ) rc=0, reason=0
CSNDT34D (TR-34 Key Distribution                ) rc=0, reason=0
CSNDT34R (TR-34 Key Receive                     ) rc=0, reason=0
CSNBKYT2 (Key Test2                             ) rc=0, reason=0
Key Check Value at KRD: 52528ED9DB
CSNBKYT2 (Key Test2                             ) rc=0, reason=0

2-pass Key Transport is complete!

</pre>
