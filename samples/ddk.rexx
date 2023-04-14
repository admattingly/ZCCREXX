/* REXX */
/* Generate a KDKGENKY key and use it to derive a directed key */

signal on failure
call ZCCREXX(ON)      /* install ZCCREXX host command environment */
address ZCCREXX       /* send commands to ZCCREXX by default      */

/* Use CSNBKTB2 to create a suitable skeleton */
rule_array              = ZCPACK("AES INTERNAL KDKGENKY KDKTYPEA")
rule_array_count        = LENGTH(rule_array) / 8
service_data            = ZCPACK("D-MAC GENONLY CMAC D-MAC VERIFY CMAC")
service_data_length     = LENGTH(service_data)
target_key_token_length = 725
"CSNBKTB2"
if return_code >= 8 then do
  signal failure
end

/* Use CSNBKGN2 to generate a random key value */
rule_array                        = ZCPACK("AES OP")
rule_array_count                  = LENGTH(rule_array) / 8
clear_key_bit_length              = 256
key_type_1                        = "TOKEN"
generated_key_identifier_1_length = 725
generated_key_identifier_1        = target_key_token
"CSNBKGN2"
if return_code >= 8 then do
  signal failure
end
say "using KDKGENKY key:" C2X(LEFT(generated_key_identifier_1, generated_key_identifier_1_length))

/* Use CSNBDDK to generate a diversified key */
rule_array                        = ZCPACK("KDFFM GENERATE")
rule_array_count                  = LENGTH(rule_array) / 8
kdk_key_identifier_length         = generated_key_identifier_1_length
kdk_key_identifier                = LEFT(generated_key_identifier_1, generated_key_identifier_1_length)
key_type_vector                   = '00000000000201000001000000000001'x
key_type_vector_length            = LENGTH(key_type_vector)
random_data_length                = 16
output_key_identifier_length      = 725
output_key_identifier             = '0000000800000000'x
"CSNBDDK"
if return_code >= 8 then do
  signal failure
end
say "Diversified key:   " C2X(LEFT(output_key_identifier, output_key_identifier_length))

done:
call ZCCREXX(OFF)     /* remove ZCCREXX host command environment */
return return_code

failure:
say "*** Failure occurred"
signal done
