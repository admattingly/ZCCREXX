/* REXX */
/*--------------------------------------------------------------------*/
/* This sample will convert an existing RSA private key so that it    */
/* can be used with the PKCS-PSS digital-signature hash formatting    */
/* method.                                                            */
/*                                                                    */
/* An adaptation of the sample in the IBM CCA APG:                    */
/*   https://www.ibm.com/docs/en/zos/2.5.0?topic=examples-rexx        */
/*--------------------------------------------------------------------*/

/* existing RSA private key label to convert */
existing_RSA_key_label = left('SAMPLE.RSA.CRT.MOD2048',64) ;

/* converted RSA private key label */
converted_RSA_private_key = left('SAMPLE.RSA.CRT.MOD2048.PSS',64) ;

call ZCCREXX(ON)      /* install ZCCREXX host command environment */
address ZCCREXX       /* send commands to ZCCREXX by default      */

/* not included in the IBM sample, we start by creating a suitable
   "existing" RSA-2048 CRT key */

CALL RSAKEY ;

/*-------------------*/
/* PKA Key Translate */
/*-------------------*/
rule_array                   = ZCPACK('INTDWAKW FR-PSS') ;
rule_array_count             = LENGTH(rule_array) / 8 ;
/* Once converted, this key may only be used with the PKCS-PSS
   digital-signature hash formatting method. For no restriction
   on usage, specify FR-NONE.  See the ICSF Application        
   Programmer's Guide for more information.                    
*/                                                            
source_key_identifier_length = 64 ;
source_key_identifier        = existing_RSA_key_label ;
target_key_token_length      = 3500 ;

/* CALL CSNDPKT */
'CSNDPKT' ;

IF return_code /= 0 THEN
  DO ;
   SAY 'PKT failed: rc =' return_code 'rs =' reason_code ;
   EXIT ;
  END ;

/* Write converted RSA private key to PKDS */
label        = converted_RSA_private_key ;
token_length = target_key_token_length ;
token        = target_key_token ;
CALL PKRC ;

/*-----------------------------------------------------------------*/
/* Use the converted RSA private key to generate a signature using */
/* the PKCS-PSS digital signature formatting hash method.          */
/*-----------------------------------------------------------------*/
rule_array                    = ZCPACK('RSA PKCS-PSS HASH SHA-256') ;
rule_array_count              = LENGTH(rule_array) / 8 ;
private_key_identifier_length = 64
private_key_identifier        = converted_RSA_private_key ;
data_length                   = 36 ;
data                          = '00000020'x||,       /* salt length */
  '9EFDE926830891B7F2889646D0105BD8'x||,  /* hash        */
  '09C64F6217EC046F5B384F625C9CCF66'x ;
signature_field_length        = 256 ;        /* 256 decimal */
signature_bit_length          = 2048 ;       /* 2048 decimal */

/* CALL CSNDDSG */
'CSNDDSG'

IF return_code /= 0 THEN
  SAY 'DSG failed: rc =' return_code 'rs =' reason_code ;
ELSE
 DO ;
  signature_field = substr(signature_field,1,signature_field_length) ;
  SAY 'signature field length:' signature_field_length ;
  SAY 'signature bit length:' signature_bit_length ;
  SAY 'signature:' c2x(signature_field) ;
 END ;

call ZCCREXX(OFF)     /* remove ZCCREXX host command environment */
call SYSCALLS(OFF)    /* remove z/OS UNIX REXX command environment */

EXIT ;

/*------------------------*/
/* PKDS Key Record Create */
/*------------------------*/
PKRC:

rule_array_count = 0 ;

/* CALL CSNDKRC */
'CSNDKRC'

IF return_code /= 0 & reason_code /= 16036 THEN
  DO ;
   SAY 'PKRC failed: rc =' return_code 'rs =' reason_code ;
  END ;

RETURN ;

/*---------------------------------------------*/
/* Generate RSA-2048 CRT key and write to PKDS */
/*---------------------------------------------*/
RSAKEY:

/* Call CSNDPKB to build a skeleton token for RSA 2048-bit KEY-MGMT key pair */
rule_array                 = ZCPACK("RSA-CRT KEY-MGMT");
rule_array_count           = LENGTH(rule_array) / 8
key_value_structure        = '0800'x   ||,   /* Modulus length = 2048 bits   */
                             '0000'x   ||,   /* Modulus field length         */
                             '0003'x   ||,   /* Public exponent field length */
                             '0000'x   ||,   /* reserved                     */
                             '0000'x   ||,   /* Prime p length               */
                             '0000'x   ||,   /* Prime q length               */
                             '0000'x   ||,   /* d_p length                   */
                             '0000'x   ||,   /* d_q length                   */
                             '0000'x   ||,   /* U length                     */
                             '010001'x       /* Public exponent = 65537      */
key_value_structure_length = LENGTH(key_value_structure)
key_token_length           = 8000
"CSNDPKB"
if return_code = 0 then do
    
  /* Call CSNDPKG to generate a random key pair */
  rule_array                     = ZCPACK("MASTER")
  rule_array_count               = LENGTH(rule_array) / 8
  skeleton_key_identifier_length = key_token_length
  skeleton_key_identifier        = key_token
  generated_key_token_length     = 8000
  "CSNDPKG"
  if return_code = 0 then do

    /* Call CSNDKRC to create a PKDS record */
    rule_array_count = 0
    label            = existing_RSA_key_label
    token_length     = generated_key_token_length
    token            = generated_key_token
    "CSNDKRC"
    if return_code = 8 & reason_code = 16036 then do    /* PKDS record already exists, so update it with new key */
      /* Call CSNDKRW to overwrite existing record */
      rule_array = ZCPACK("OVERLAY")
      rule_array_count = LENGTH(rule_array) / 8
      "CSNDKRW"
    end
  end
end
return
