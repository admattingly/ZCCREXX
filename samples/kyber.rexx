/* REXX */
/* Generate a CRYSTALS-Kyber key and use it exchange a randomly-generated AES-256 key */
/*                                                                                    */
/* Before we can exchange a random "session" key, we need to generate a               */
/* CRYSTALS-Kyber key pair and an AES CIPHER key.  We use CSNDPKE to generate our     */
/* session key, and pass back the key value enciphered under the AES CIPHER key for   */
/* local use, while the session key is returned enciphered under the public           */
/* CRYSTALS-Kyber key for distribution to our communication partner (who uses         */
/* CSNDPKD and the CRYSTALS-Kyber private key to recover the session key.             */

call ZCCREXX(ON)      /* install ZCCREXX host command environment */
address ZCCREXX       /* send commands to ZCCREXX by default      */

/* Call CSNBKTB2 to generate a skeleton for a local AES CIPHER key */
rule_array              = ZCPACK("INTERNAL AES CIPHER")
rule_array_count        = LENGTH(rule_array) / 8
target_key_token_length = 725
"CSNBKTB2"
if return_code >= 8 then do
  signal done
end

/* Call CSNBKGN2 to generate an AES CIPHER key to encrypt/decrypt the random key     */
/* generated (later) by CSNDPKE                                                      */
rule_array                        = ZCPACK("AES OP")
rule_array_count                  = LENGTH(rule_array) / 8
clear_key_bit_length              = 256
key_type_1                        = "TOKEN"
generated_key_identifier_1_length = 900
generated_key_identifier_1        = target_key_token
"CSNBKGN2"
if return_code >= 8 then do
  signal done
end
aes_key_token_length = generated_key_identifier_1_length
aes_key_token        = generated_key_identifier_1

/* Call CSNDPKB to build a skeleton key token */
rule_array                 = ZCPACK("QSA-PAIR U-DATENC")
rule_array_count           = LENGTH(rule_array) / 8
key_value_structure        = '02'x   ||,   /* CRYSTALS-Kyber Round 2 */
                             '00'x   ||,   /* No clear key           */
                             '1024'x ||,   /* CRYSTALS-Kyber (1024)  */
                             '0000'x ||,   /* Clear key length       */
                             '0000'x       /* Reserved               */
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

/* Call CSNDPKX to extract the CRYSTALS-Kyber public key */
rule_array_count               = 0
source_key_identifier_length   = generated_key_token_length
source_key_identifier          = generated_key_token
target_public_key_token_length = 8000
"CSNDPKX"
if return_code >= 8 then do
  signal done
end

/* Call CSNDPKE to generate a random session key enciphering it under our CRYSTALS-Kyber */
/* public key and the local AES CIPHER key                                               */
rule_array                     = ZCPACK("ZERO-PAD RANDOM")
rule_array_count               = LENGTH(rule_array) / 8
keyvalue_length                = 32
sym_key_identifier_length      = aes_key_token_length
sym_key_identifier             = aes_key_token
PKA_key_identifier_length      = target_public_key_token_length
PKA_key_identifier             = target_public_key_token
PKA_enciphered_keyvalue_length = 1568
"CSNDPKE"
if return_code >= 8 then do
  signal done
end
say "PKA-enciphered key:" PKA_enciphered_keyvalue_length "bytes"

/* Use CSNBSAD to decipher the random session key using the local AES key */
rule_array                     = ZCPACK("AES KEYIDENT")
rule_array_count               = LENGTH(rule_array) / 8
key_identifier_length          = aes_key_token_length
key_identifier                 = aes_key_token
block_size                     = 16
initialization_vector_length   = block_size
chain_data_length              = 32
cipher_text_length             = keyvalue_length
cipher_text                    = keyvalue
clear_text_length              = keyvalue_length
"CSNBSAD"
if return_code >= 8 then do
  signal done
end
say "Local session key: " C2X(LEFT(clear_text, clear_text_length))

/* Use CSNDPKD to recover the session key using the CRYSTALS-Kyber private key */
rule_array                     = ZCPACK("ZERO-PAD")
rule_array_count               = LENGTH(rule_array) / 8
/* PKA_enciphered_keyvalue_length and PKA_enciphered_keyvalue are unchanged */
key_identifier_length          = generated_key_token_length
key_identifier                 = generated_key_token
target_keyvalue_length         = 512  /* only 32 bytes are needed */
"CSNDPKD"
if return_code >= 8 then do
  signal done
end
say "Remote session key:" C2X(LEFT(target_keyvalue, target_keyvalue_length))

done:
call ZCCREXX(OFF)     /* remove ZCCREXX host command environment */
