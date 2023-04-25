/* REXX */
/* First phase of setup: generate key pairs and certificate signing requests */
/* see: https://www.ibm.com/docs/en/zos/2.5.0?topic=flows-setup              */

call ZCCREXX(ON)      /* install ZCCREXX host command environment */
address ZCCREXX       /* send commands to ZCCREXX by default      */

call SYSCALLS(ON)     /* install z/OS UNIX REXX command environment */

/* Set these values as you see fit: */
SN_kdh = "CN=Key Distribution Host,O=Agilify,C=AU"
SN_krd = "CN=Key Receiving Device,O=Agilify,C=AU"
PKDS_kdh = "MY.KDH.KEY"
PKDS_krd = "MY.KRD.KEY"
CSRfn_kdh = "kdhcsr.pem"
CSRfn_krd = "krdcsr.pem"

/* On the KDH (Key Distribution Host) */

/* 1. Create the KDH administrative RSA key pair for TR-34 use with target (or set of targets) */

/* Call CSNDPKB to build a skeleton token for RSA 2048-bit SIG-ONLY key pair */
rule_array                 = ZCPACK("RSA-CRT SIG-ONLY");
rule_array_count           = LENGTH(rule_array) / 8
key_value_structure        = '0800'x   ||,   /* Modulus length = 2048 bits    */
                             '0000'x   ||,   /* Modulus field length          */
                             '0003'x   ||,   /* Public exponent field length  */
                             '0000'x   ||,   /* reserved                      */
                             '0000'x   ||,   /* Prime p length                */
                             '0000'x   ||,   /* Prime q length                */
                             '0000'x   ||,   /* d_p length                    */
                             '0000'x   ||,   /* d_q length                    */
                             '0000'x   ||,   /* U length                      */
                             '010001'x       /* Public exponent = 65537       */
key_value_structure_length = LENGTH(key_value_structure)
key_token_length           = 8000
"CSNDPKB"
if return_code >= 8 then do
  signal done
end

/* Call CSNDPKG to generate a random key pair */
rule_array                     = ZCPACK("MASTER")
rule_array_count               = LENGTH(rule_array) / 8
skeleton_key_identifier_length = key_token_length
skeleton_key_identifier        = key_token
generated_key_token_length     = 8000
"CSNDPKG"
if return_code >= 8 then do
  signal done
end

/* Call CSNDKRC to create a PKDS record */
rule_array_count = 0
label            = PKDS_kdh
token_length     = generated_key_token_length
token            = generated_key_token
"CSNDKRC"
if return_code >= 8 then do
  if return_code = 8 & reason_code = 16036 then do    /* PKDS record already exists, so update it with new key */
    /* Call CSNDKRW to overwrite existing record */
    rule_array = ZCPACK("OVERLAY")
    rule_array_count = LENGTH(rule_array) / 8
    "CSNDKRW"
    if return_code >= 8 then do
      signal done
    end
  end
  else do
    signal done
  end
end

/* 2. Create PKCS #10 certificate signing request for the public key of the administrative key pair */

/* Call CSNDPIC to generate a certificate signing request */
rule_array                            = ZCPACK("PK10SNRQ SELFSIGN SDNCLEAR PEM-FMT U-DIGSIG RSA SHA-512")
rule_array_count                      = LENGTH(rule_array) / 8
subject_private_key_identifier_length = 64
subject_private_key_identifier        = PKDS_kdh
subject_name                          = SN_kdh
subject_name_length                   = LENGTH(subject_name)
certificate_length                    = 3500
"CSNDPIC"
if return_code >= 8 then do
  signal done
end

/* write CSR to a file */
address SYSCALL
'open' CSRfn_kdh O_RDWR+O_CREAT+O_TRUNC 660
if retval = -1 then do
  say "Error opening file, '"CSRfn_kdh"', error codes" errno errnojr
  signal done
end
fd          = retval
offset      = 1
certificate = LEFT(certificate, certificate_length)
line_end    = POS('25'x, SUBSTR(certificate, offset, LENGTH(certificate) + 1 - offset))
do while line_end > 0
  rec       = SUBSTR(certificate, offset, line_end - 1) || ESC_N
  'write' fd 'rec' LENGTH(rec) 
  offset    = offset + line_end
  line_end  = POS('25'x, SUBSTR(certificate, offset, LENGTH(certificate) + 1 - offset))
end 
'close' fd
say "Certificate signing request written to" CSRfn_kdh
address ZCCREXX

/* On the KRD (Key Receiving Device) */

/* 1. Create the RSA key pair for TR-34 key management use */

/* Call CSNDPKB to build a skeleton token for RSA 2048-bit KEY-MGMT key pair */
rule_array                 = ZCPACK("RSA-CRT KEY-MGMT");
rule_array_count           = LENGTH(rule_array) / 8
key_value_structure        = '0800'x   ||,   /* Modulus length = 2048 bits    */
                             '0000'x   ||,   /* Modulus field length          */
                             '0003'x   ||,   /* Public exponent field length  */
                             '0000'x   ||,   /* reserved                      */
                             '0000'x   ||,   /* Prime p length                */
                             '0000'x   ||,   /* Prime q length                */
                             '0000'x   ||,   /* d_p length                    */
                             '0000'x   ||,   /* d_q length                    */
                             '0000'x   ||,   /* U length                      */
                             '010001'x       /* Public exponent = 65537       */
key_value_structure_length = LENGTH(key_value_structure)
key_token_length           = 8000
"CSNDPKB"
if return_code >= 8 then do
  signal done
end

/* Call CSNDPKG to generate a random key pair */
rule_array                     = ZCPACK("MASTER")
rule_array_count               = LENGTH(rule_array) / 8
skeleton_key_identifier_length = key_token_length
skeleton_key_identifier        = key_token
generated_key_token_length     = 8000
"CSNDPKG"
if return_code >= 8 then do
  signal done
end

/* Call CSNDKRC to create a PKDS record */
rule_array_count = 0
label            = PKDS_krd
token_length     = generated_key_token_length
token            = generated_key_token
"CSNDKRC"
if return_code >= 8 then do
  if return_code = 8 & reason_code = 16036 then do    /* PKDS record already exists, so update it with new key */
    /* Call CSNDKRW to overwrite existing record */
    rule_array = ZCPACK("OVERLAY")
    rule_array_count = LENGTH(rule_array) / 8
    "CSNDKRW"
    if return_code >= 8 then do
      signal done
    end
  end
  else do
    signal done
  end
end

/* 2. Create PKCS #10 certificate signing request for the public key E-krd */

/* Call CSNDPIC to generate a certificate signing request */
rule_array                            = ZCPACK("PK10SNRQ SELFSIGN SDNCLEAR PEM-FMT U-KEYAGR U-KEYENC RSA SHA-512")
rule_array_count                      = LENGTH(rule_array) / 8
subject_private_key_identifier_length = 64
subject_private_key_identifier        = PKDS_krd
subject_name                          = SN_krd
subject_name_length                   = LENGTH(subject_name)
certificate_length                    = 3500
"CSNDPIC"
if return_code >= 8 then do
  signal done
end

/* write CSR to a file */
address SYSCALL
'open' CSRfn_krd O_RDWR+O_CREAT+O_TRUNC 660
if retval = -1 then do
  say "Error opening file, '"CSRfn_krd"', error codes" errno errnojr
  signal done
end
fd          = retval
offset      = 1
certificate = LEFT(certificate, certificate_length)
line_end    = POS('25'x, SUBSTR(certificate, offset, LENGTH(certificate) + 1 - offset))
do while line_end > 0
  rec       = SUBSTR(certificate, offset, line_end - 1) || ESC_N
  'write' fd 'rec' LENGTH(rec) 
  offset    = offset + line_end
  line_end  = POS('25'x, SUBSTR(certificate, offset, LENGTH(certificate) + 1 - offset))
end
'close' fd
say "Certificate signing request written to" CSRfn_krd
address ZCCREXX

done:
call ZCCREXX(OFF)     /* remove ZCCREXX host command environment */
call SYSCALLS(OFF)    /* remove z/OS UNIX REXX command environment */
