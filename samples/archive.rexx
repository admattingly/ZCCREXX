/* REXX */
/* Sample: Archive a secure AES key                                  */
/*-------------------------------------------------------------------*/
/* Description:                                                      */
/*                                                                   */
/* This REXX contains samples that show how to archive an existing   */
/* key:                                                              */
/*  - Generate and store a 256-bit AES DATA key in the CKDS          */
/*  - Encrypt data using the AES key                                 */
/*  - Decrypt data using the AES key                                 */
/*  - Archive the key                                                */
/*  - Attempt to encrypt/decrypt data with archived key              */
/*                                                                   */
/* REXX equivalent: https://community.ibm.com/community/user/ibmz-and-linuxone/blogs/eysha-shirrine-powers2/2020/03/25/rexx-sample-archive-a-key-in-the-ckds */

call ZCCREXX(ON)  /* install ZCCREXX host command environment */
address ZCCREXX   /* send commands to ZCCREXX by default      */

/* CLEANUP labels in use for this sample */
rule_array = ZCPACK("LABEL-DL")
rule_array_count = LENGTH(rule_array) / 8
key_label = "ICSF.KEYSAMP.AES256.KEY001"
"CSNBKRD"

/*********************************************************************/
/* Generate a 256-bit AES DATA key                                   */
/*********************************************************************/
key_form   = "OP"
key_length = "KEYLN32"
key_type_1 = "AESDATA"
"CSNBKGN"
if return_code = 0 then do
  say "AES secure key: " C2X(generated_key_identifier_1)
end

/*********************************************************************/
/* Store the key in the CKDS                                         */
/*********************************************************************/
rule_array_count = 0
key_token_length = 64
key_token        = generated_key_identifier_1
"CSNBKRC2"

/*********************************************************************/
/* Encrypt data using the secure key                                 */
/*********************************************************************/
rule_array                   = ZCPACK("AES PKCS-PAD KEYIDENT")
rule_array_count             = LENGTH(rule_array) / 8
key_identifier_length        = 64
key_identifier               = key_label
block_size                   = 16
initialization_vector_length = 16
initialization_vector        = '11111111111111111111111111111111'x
chain_data_length            = 32
clear_text_length            = 11
clear_text                   = "Secret Data"
cipher_text_length           = 16
"CSNBSAE"

encrypted_text = SUBSTR(cipher_text, 1, cipher_text_length)
say 'clear_text:     ' clear_text
say 'encrypted_text: ' C2X(encrypted_text)

/*********************************************************************/
/* Decrypt data using the secure key                                 */
/*********************************************************************/
clear_text_length            = 16
"CSNBSAD"

decrypted_text = SUBSTR(clear_text, 1, clear_text_length)
say 'decrypted_text: ' decrypted_text

/*********************************************************************/
/* Archive the key                                                   */
/*********************************************************************/
rule_array_count     = 1
rule_array           = "CKDS"
label_count          = 1
label_list           = key_label
metadata_list_length = 5
metadata_list        = '0005'x ||,          /* Length of structure  */
                       '0009'x ||,          /* Record archive flag  */
                       '01'x                /* Turn ON the flag     */
"CSFKDMW"

/*********************************************************************/
/* Verify the key is archived                                        */
/*********************************************************************/
record_label         = key_label
metadata_list_length = 4
metadata_list        = '0004'x ||,           /* Length of structure  */
                       '0009'x               /* Record archive flag  */
output_list_length   = 5
"CSFKDMR"

output_block_length = SUBSTR(output_list, 1, 2)
output_block_flag   = SUBSTR(output_list, 3, 1)
output_block_value  = SUBSTR(output_list, 5, 1)

say '';
if output_block_value = '01'x then
  say 'Key archived!';
else
  say 'Key not archived!';

/*********************************************************************/
/* Attempt to use the archived key                                   */
/*********************************************************************/
rule_array                   = ZCPACK("AES PKCS-PAD KEYIDENT")
rule_array_count             = LENGTH(rule_array) / 8
clear_text_length            = 11
clear_text                   = "Secret Data"
cipher_text_length           = 16
say ''
say 'Attempt encryption...'
"CSNBSAE"

say "-----------------------------------------------------------------"
say "End of Sample"
say "-----------------------------------------------------------------"

call ZCCREXX(OFF)   /* remove ZCCREXX host command environment */
