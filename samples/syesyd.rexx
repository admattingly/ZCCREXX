/* REXX */
/* demonstrate protected key encrypt/decrypt unsing CSNBSYE/SYD */

call ZCCREXX(ON)    /* install ZCCREXX host command environment */
address ZCCREXX     /* route commands to ZCCREXX by default     */

/* build a skeleton key token */
rule_array              = ZCPACK("INTERNAL AES NO-KEY CIPHER ANY-MODE XPRTCPAC")
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

/* delete key from CKDS (don't worry if it fails) */
rule_array       = ZCPACK("LABEL-DL")
rule_array_count = LENGTH(rule_array) / 8
key_label = "ZCCREXX.AES.256.SYESYD.KEY"
"CSNBKRD"

/* write the key token to the CKDS */
rule_array_count = 0
key_token_length = generated_key_identifier_1_length
key_token        = LEFT(generated_key_identifier_1, generated_key_identifier_1_length)
"CSNBKRC2"
if return_code <> 0 then signal done

/* encrypt some text */
rule_array                   = ZCPACK("AES CBC KEYIDENT")
rule_array_count             = LENGTH(rule_array) / 8
key_identifier_length        = 64
key_identifier               = key_label
block_size                   = 16
initialization_vector_length = block_size
chain_data_length            = 32
clear_text                   = "The quick brown fox jumps over the lazy dog"
clear_text_length            = 16 * ((LENGTH(clear_text) + 15) % 16)
cipher_text_length           = clear_text_length
"CSNBSYE"
if return_code <> 0 then signal done
say "Clear text:      '"clear_text"'"
say "Cipher text:     "C2X(cipher_text)

/* decrypt this text */
clear_text = "Any old stuff"    /* make sure we don't cheat */
"CSNBSYD"
if return_code <> 0 then signal done
say "Deciphered text: '"clear_text"'"

done:
say "*** processing complete ***"
call ZCCREXX(OFF)   /* remove ZCCREXX host command environment */
