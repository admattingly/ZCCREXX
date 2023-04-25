/* REXX */
/* 2-pass Key Transport - This key transport typically installs a 
                          Terminal Master Key (TMK) at the Key Receiving Device */
/* see: https://www.ibm.com/docs/en/zos/2.5.0?topic=flows-2-pass-key-transport  */

call ZCCREXX(ON)      /* install ZCCREXX host command environment */
address ZCCREXX       /* send commands to ZCCREXX by default      */

call SYSCALLS(ON)     /* install z/OS UNIX REXX command environment */

/* Set these values as you see fit: */
PKDS_kdh     = "MY.KDH.KEY"
PKDS_krd     = "MY.KRD.KEY"
Certfn_kdh   = "kdhcert.pem"
Certfn_krd   = "krdcert.pem"
CRLfn        = "crl.pem"
PKDS_kdh_TMK = "MY.KDH.TMK"
PKDS_krd_TMK = "MY.KRD.TMK"

/*
 * Preparation - read certificates and CRL 
 */

address SYSCALL

/* read the KDH certificate */
drop file.
'readfile (Certfn_kdh) file.'
if retval = -1 then do
  say "Error opening file, '"Certfn_kdh"', error codes" errno errnojr
  signal done
end
kdh_cert = ""
do i = 1 to file.0
  kdh_cert = kdh_cert || file.i
end

/* read the KRD certificate */
drop file.
'readfile (Certfn_krd) file.'
if retval = -1 then do
  say "Error opening file, '"Certfn_krd"', error codes" errno errnojr
  signal done
end
krd_cert = ""
do i = 1 to file.0
  krd_cert = krd_cert || file.i
end

/* read the CRL */
drop file.
'readfile (CRLfn) file.'
if retval = -1 then do
  say "Error opening file, '"CRLfn"', error codes" errno errnojr
  signal done
end
crl = ""
do i = 1 to file.0
  crl = crl || file.i
end

address ZCCREXX

say "/*********************************/"
say "/* Setup steps for key transport */"
say "/*********************************/"

/*
 * On the KDH (Key Distribution Host) 
 */

/* 1. Refresh CRL-CA if needed - we read it from a file */

/* 2. Create TMK/KBPK: The KEK to be shared with the other party. (AES) */

/* (a) KDH-Wrapping-KEK */

  /* Call CSNBKTB2 to build a skeleton token */
rule_array              = ZCPACK("INTERNAL AES NO-KEY EXPORTER WR-TR31 V1PYLD")
rule_array_count        = LENGTH(rule_array) / 8
clear_key_bit_length    = 0
target_key_token_length = 725
"CSNBKTB2"
if return_code >= 8 then do
  signal done
end

  /* Call CSNBRNGL to generate a random value */
rule_array           = ZCPACK("RANDOM")
rule_array_count     = LENGTH(rule_array) / 8
random_number_length = 16          /* 128-bit key */
"CSNBRNGL"
if return_code >= 8 then do
  signal done
end

  /* Call CSNBKPI2 to import the random value into the token */
rule_array            = ZCPACK("AES FIRST MIN1PART")      
rule_array_count      = LENGTH(rule_array) / 8
key_part_bit_length   = 128
key_part              = random_number
key_identifier_length = 725
key_identifier        = LEFT(target_key_token, target_key_token_length)
"CSNBKPI2"
if return_code >= 8 then do
  signal done
end

  /* Call CSNBKPI2 again to complete the token */
rule_array            = ZCPACK("AES COMPLETE")      
rule_array_count      = LENGTH(rule_array) / 8
key_part_bit_length   = 0
key_identifier_length = 725
"CSNBKPI2"
if return_code >= 8 then do
  signal done
end

KDH_Wrapping_KEK = LEFT(key_identifier, key_identifier_length)

/* (b) KDH-Export-KEK and (c) KRD-Import-KEK, created as a matching pair */

  /* Call CSNBKTB2 to build a skeleton token for KDH-Export-KEK */
rule_array              = ZCPACK("INTERNAL AES NO-KEY EXPORTER EXPTT31D VARDRV-D WR-AES V1PYLD")
rule_array_count        = LENGTH(rule_array) / 8
clear_key_bit_length    = 0
target_key_token_length = 725
"CSNBKTB2"
if return_code >= 8 then do
  signal done
end

KDH_Export_KEK_skeleton = LEFT(target_key_token, target_key_token_length)

  /* Call CSNBKTB2 to build a skeleton token for KRD-Import-KEK */
rule_array              = ZCPACK("EXTERNAL AES NO-KEY IMPORTER IMPTT31D VARDRV-D WR-AES V1PYLD")
rule_array_count        = LENGTH(rule_array) / 8
clear_key_bit_length    = 0
target_key_token_length = 725
"CSNBKTB2"
if return_code >= 8 then do
  signal done
end

KRD_Import_KEK_skeleton = LEFT(target_key_token, target_key_token_length)

  /* Call CSNBKGN2 to generate a matching pair of EXPORTER/IMPORTER keys */
rule_array              = ZCPACK("AES OPEX")
rule_array_count        = LENGTH(rule_array) / 8
clear_key_bit_length    = 128
key_type_1              = "TOKEN"
key_type_2              = "TOKEN"
key_encrypting_key_identifier_2_length = LENGTH(KDH_Wrapping_KEK)
key_encrypting_key_identifier_2        = KDH_Wrapping_KEK
generated_key_identifier_1_length      = 900
generated_key_identifier_1             = KDH_Export_KEK_skeleton
generated_key_identifier_2_length      = 900
generated_key_identifier_2             = KRD_Import_KEK_skeleton
"CSNBKGN2"
if return_code >= 8 then do
  signal done
end

KDH_Export_KEK = LEFT(generated_key_identifier_1, generated_key_identifier_1_length)
KRD_Import_KEK = LEFT(generated_key_identifier_2, generated_key_identifier_2_length)

say "/************************************/"
say "/* Protocol steps for key transport */"
say "/************************************/"

/*
 * 1. On the KDH (Key Distribution Host) 
 */

/* The KDH TR-34 application requests a random number from the KRD. */

/*
 * 2. On the KRD (Key Receiving Device) 
 */

/* (a) KRD TR-34 application receives the random number request and processes it. */

  /* Call CCA service CSNBRNGL: "RT-KRD" to create the TR-34 token 
     that contains random number that is needed by the KDH. */
rule_array           = ZCPACK("RT-KRD")
rule_array_count     = LENGTH(rule_array) / 8
random_number_length = 53       /* DER-encoded 32-byte random number */
"CSNBRNGL"
if return_code >= 8 then do
  signal done
end

/* (b) Send RT-KRD to KDH. Also, store RT-KRD locally in application space 
       for a later validation step. */

RT_KRD = random_number

/*
 * 3. On the KDH (Key Distribution Host) 
 */

/* (a) Create the Key Transport token */

  /* Call CCA service CSNDT34D: "2PASSCRE". */
rule_array                    = ZCPACK("2PASSCRE PKI-NONE SKEY-AES VARDRV-D KEK-WRAP DEC-ONLY")
rule_array_count              = LENGTH(rule_array) / 8
source_key_identifier_length  = LENGTH(KRD_Import_KEK)
source_key_identifier         = KRD_Import_KEK
unwrap_kek_identifier_length  = LENGTH(KDH_Wrapping_KEK)
unwrap_kek_identifier         = KDH_Wrapping_KEK
freshness_indicator_length    = LENGTH(RT_KRD)
freshness_indicator           = RT_KRD
crl_length                    = LENGTH(crl)
cred_kdh_length               = LENGTH(kdh_cert)
cred_kdh                      = kdh_cert 
cred_krd_length               = LENGTH(krd_cert)
cred_krd                      = krd_cert
private_key_identifier_length = 64
private_key_identifier        = PKDS_kdh
key_version_number            = "00"
opt_blks_length               = 0
output_token_length           = 9000
"CSNDT34D"
if return_code >= 8 then do
  signal done
end

/* (b) KDH sends the KT-KDH token to the KRD. */

KT_KDH = LEFT(output_token, output_token_length)

/*
 * 4. On the KRD (Key Receiving Device) 
 */

/* (a) The KRD receives the KT-KDH token from the KDH and must process it to complete the Key Transport. */

/* (b) Create key token to hold output TMK (CCA / peer-to-peer step). */

  /* Use CCA service CSNBKTB or CSNBKTB2 to create Kn-TS, a skeleton CCA key token 
     appropriate for a importing the TMK/KBPK. */

  /* see creation of KRD_Import_KEK_skeleton in "setup" step 2(c) above for example,
     but this step is unnecessary to receive the TMK as a CCA token. */
  
/* (c) Process the KT-KDH token received from the KDH. */

  /* Call CCA service CSNDT34R: "2PASSRCV". */
rule_array                       = ZCPACK("2PASSRCV PKI-NONE")
rule_array_count                 = LENGTH(rule_array) / 8
input_token_length               = LENGTH(KT_KDH)
input_token                      = KT_KDH
cred_kdh_length                  = LENGTH(kdh_cert)
cred_kdh                         = kdh_cert
input_freshness_indicator_length = LENGTH(RT_KRD)
input_freshness_indicator        = RT_KRD
private_key_identifier_length    = 64
private_key_identifier           = PKDS_krd
output_key_identifier_length     = 725
"CSNDT34R"
if return_code >= 8 then do
  signal done
end

Kn_T_krd = LEFT(output_key_identifier, output_key_identifier_length)

/*
 * 5. On the KRD (Key Receiving Device) 
 */

/* (a) Key Check Value generated and returned to KDH. */

  /* The KRD generates a Key Check Value (KCV) for Kn-T using CCA service CSNBKYT2 */
rule_array                           = ZCPACK("AES GENERATE CMACZERO")
rule_array_count                     = LENGTH(rule_array) / 8
key_identifier_length                = LENGTH(Kn_T_krd)
key_identifier                       = Kn_T_krd
key_encrypting_key_identifier_length = 0    
verification_pattern_length          = 5
"CSNBKYT2"
if return_code >= 8 then do
  signal done
end

VP_krd = verification_pattern
say "Key Check Value at KRD:" C2X(VP_krd)

/*
 * 6. On the KDH (Key Distribution Host) 
 */

/* (a) Key Check Value verified by KDH. */

  /* KDH verifies the KCV against the original Kn-T that was sent for export using TR-34. */
rule_array                           = ZCPACK("AES VERIFY CMACZERO")
rule_array_count                     = LENGTH(rule_array) / 8
key_identifier_length                = LENGTH(KDH_Export_KEK)
key_identifier                       = KDH_Export_KEK
key_encrypting_key_identifier_length = 0    
verification_pattern_length          = LENGTH(VP_krd)
verification_pattern                 = VP_krd
"CSNBKYT2"
if return_code >= 8 then do
  signal done
end

say " "
say "2-pass Key Transport is complete!"
say " "

done:
call ZCCREXX(OFF)     /* remove ZCCREXX host command environment */
call SYSCALLS(OFF)    /* remove z/OS UNIX REXX command environment */
