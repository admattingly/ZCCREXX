/* REXX */
/* demonstrate encrypted key encrypt/decrypt using CSNBSAE/SAD */

call ZCCREXX(ON)    /* install ZCCREXX host command environment */
address ZCCREXX     /* route commands to ZCCREXX by default     */

/* build a skeleton key token */
rule_array              = ZCPACK("INTERNAL AES NO-KEY CIPHER ANY-MODE")
rule_array_count        = LENGTH(rule_array) / 8
target_key_token_length = 725
"CSNBKTB2"
if return_code <> 0 then signal done

/* generate a random key */
rule_array                        = ZCPACK("AES OP")
rule_array_count                  = LENGTH(rule_array) / 8
clear_key_bit_length              = 256
key_type_1                        = "TOKEN"
generated_key_identifier_1_length = 900
generated_key_identifier_1        = LEFT(target_key_token, target_key_token_length)
"CSNBKGN2"
if return_code <> 0 then signal done

/* encrypt some text */
rule_array                   = ZCPACK("AES CBC KEYIDENT")
rule_array_count             = LENGTH(rule_array) / 8
key_identifier_length        = generated_key_identifier_1_length
key_identifier               = generated_key_identifier_1
block_size                   = 16
initialization_vector_length = block_size
chain_data_length            = 32
clear_text                   = "The quick brown fox jumps over the lazy dog"
clear_text_length            = 16 * ((LENGTH(clear_text) + 15) % 16)
cipher_text_length           = clear_text_length
"CSNBSAE"
if return_code <> 0 then signal done
say "Clear text:      '"clear_text"'"
say "Cipher text:     "C2X(cipher_text)

/* decrypt this text */
clear_text = "Any old stuff"    /* make sure we don't cheat */
"CSNBSAD"
if return_code <> 0 then signal done
say "Deciphered text: '"clear_text"'"

done:
say "*** processing complete ***"
call ZCCREXX(OFF)   /* remove ZCCREXX host command environment */
