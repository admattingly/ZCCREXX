/* REXX */
/* Generate a CRYSTALS-Dilithium key and use it to compute a digital signature */

call ZCCREXX(ON)      /* install ZCCREXX host command environment */
address ZCCREXX       /* send commands to ZCCREXX by default      */

/* Call CSNDPKB to build a skeleton key token */
rule_array                 = ZCPACK("QSA-PAIR U-DIGSIG")
rule_array_count           = LENGTH(rule_array) / 8
key_value_structure        = '03'x   ||,   /* CRYSTALS-Dilithium Round 3 */
                             '00'x   ||,   /* No clear key               */
                             '0807'x ||,   /* CRYSTALS-Dilithium (8,7)   */
                             '0000'x ||,   /* Clear key length           */
                             '0000'x       /* Reserved                   */
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

/* Call CSNDDSG to compute a digital signature using CRYSTALS-Dilithium private key */
rule_array                    = ZCPACK("CRDL-DSA MESSAGE CRDLHASH")
rule_array_count              = LENGTH(rule_array) / 8
private_key_identifier_length = generated_key_token_length
private_key_identifier        = generated_key_token
data                          = "The quick brown fox jumps over the lazy dog."
data_length                   = LENGTH(data)
signature_field_length        = 5000
"CSNDDSG"
if return_code >= 8 then do
  signal done
end
say "Digital signature size:" signature_field_length "bytes"

/* Call CSNDPKX to extract the CRYSTALS-Dilithium public key */
rule_array_count               = 0
source_key_identifier_length   = generated_key_token_length
source_key_identifier          = generated_key_token
target_public_key_token_length = 8000
"CSNDPKX"
if return_code >= 8 then do
  signal done
end

/* Use CSNDDSV with the public key to verify the digital signature */
rule_array = ZCPACK("CRDL-DSA MESSAGE CRDLHASH")
rule_array_count = LENGTH(rule_array) / 8
PKA_public_key_identifier_length = target_public_key_token_length
PKA_public_key_identifier        = target_public_key_token
/* data_length and data are unchanged from call to CSNDDSG */
/* same for signature_field_length and signature_field     */
"CSNDDSV"

done:
call ZCCREXX(OFF)     /* remove ZCCREXX host command environment */
