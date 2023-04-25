/* REXX */
/* BIND - Bind a Key Receiving Device (KRD) to a Key Distribution Host (KDH) */
/* see: https://www.ibm.com/docs/en/zos/2.5.0?topic=flows-bind               */

call ZCCREXX(ON)      /* install ZCCREXX host command environment */
address ZCCREXX       /* send commands to ZCCREXX by default      */

call SYSCALLS(ON)     /* install z/OS UNIX REXX command environment */

/* Set these values as you see fit: */
PKDS_kdh   = "MY.KDH.KEY"
PKDS_krd   = "MY.KRD.KEY"
Certfn_kdh = "kdhcert.pem"
Certfn_krd = "krdcert.pem"
CRLfn      = "crl.pem"

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

/*
 * 1. On the KDH (Key Distribution Host) 
 */

/* The KDH TR-34 application requests the CredKRD from the KRD - 
     We will read CredKRD from file, Certfn_krd */
     
/*
 * 2. On the KRD (Key Receiving Device) 
 */

/* The CredKRD request is received and processed by the TR-34 application - 
     We will read CredKRD from file, Certfn_krd */

/* Create the token that contains the CredKRD */

  /* Call CCA service CSNDT34C: "BINDKRDC" to create the TR-34 token
     that contains CredKRD for the KDH */
rule_array          = ZCPACK("BINDKRDC")
rule_array_count    = LENGTH(rule_array) / 8
input_token_length  = 0          /* no input token for BINDKRDC */
cred_kdh_length     = 0          /* no Cred_kdh for BINDKRDC */
cred_krd_length     = LENGTH(krd_cert)
cred_krd            = krd_cert
random_number_token = 0         /* no random number token for BINDKRDC */
output_token_length = 3500
"CSNDT34C"
if return_code >= 8 then do
  signal done
end

CT_krd = LEFT(output_token, output_token_length)

/* TR-34 application sends CT-KRD to KDH - we will use variable CT_krd */

/*
 * 3. On the KDH (Key Distribution Host) 
 */

/* Refresh CRL-CA if needed - not needed in our case */

/* Create the 'BIND' token needed for the next protocol step */

  /* Call CCA service CSNDT34B: "BINDCR" */
rule_array                    = ZCPACK("BINDCR PKI-NONE")
rule_array_count              = LENGTH(rule_array) / 8
input_token                   = CT_krd
input_token_length            = LENGTH(input_token)
crl_length                    = LENGTH(crl)
cred_kdh                      = kdh_cert
cred_kdh_length               = LENGTH(cred_kdh)
old_cred_kdh_length           = 0         /* not needed for BINDCR */
cred_krd_length               = 3500
cred_krd                      = ""        /* must be NULL on input for BINDCR */
private_key_identifier_length = 0
output_token_length           = 9000
"CSNDT34B"
if return_code >= 8 then do
  signal done
end

/* Application stores CredKRD so that it is available for future key distribution calls */
CredKRD = LEFT(cred_krd, cred_krd_length)

/* KDH TR-34 application sends the CT-KDH token to the KRD */
CT_kdh = LEFT(output_token, output_token_length)

/*
 * 4. On the KRD (Key Receiving Device) 
 */

/* The KRD receives the CT-KDH token from the KDH and processes it to complete the BIND */

  /* Call CCA service CSNDT34C: "BINDRV" */
rule_array                 = ZCPACK("BINDRV PKI-NONE")
rule_array_count           = LENGTH(rule_array) / 8
input_token                = CT_kdh
input_token_length         = LENGTH(input_token)
cred_kdh_length            = 0      /* not needed for BINDRV */
cred_krd_length            = 0      /* not needed for BINDRV */
random_number_token_length = 0      /* not needed for BINDRV */
output_token_length        = 3500
output_token               = ""
"CSNDT34C"
if return_code >= 8 then do
  signal done
end

/* The application on the KRD stores the CredKDH to complete the 'Bind' phase -
     We already have it in a file, Certfn_kdh */
     
done:
call ZCCREXX(OFF)     /* remove ZCCREXX host command environment */
call SYSCALLS(OFF)    /* remove z/OS UNIX REXX command environment */
