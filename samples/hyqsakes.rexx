/* REXX */
/* Hybrid Quantum Safe Algorithm (QSA) Key Exchange Scheme                                  */
/*                                                                                          */
/* This sample follows the usage notes for CSNDEDH (z/OS 2.5 or later)                      */
/* see: https://www.ibm.com/docs/en/zos/2.5.0?topic=keys-ecc-diffie-hellman-csndedh-csnfedh */
/*                                                                                          */
/* Note: Public keys are not exchanged via certificates in this sample - they should be     */
/*       exchanged via certificates in real life :)                                         */

call ZCCREXX(ON)      /* install ZCCREXX host command environment */
address ZCCREXX       /* send commands to ZCCREXX by default      */

say "/*------------------------------------------------------------*/"
say "/* Step 1. The first person (Alice) creates the keys          */"
say "/*------------------------------------------------------------*/"

/* (a) Create a CRYSTALS-Kyber (1024) key pair */

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

/* Call CSNDPKX to extract the public key */
rule_array_count               = 0
source_key_identifier_length   = generated_key_token_length
source_key_identifier          = generated_key_token
target_public_key_token_length = 8000
"CSNDPKX"
if return_code >= 8 then do
  signal done
end

Kyb_priv_A_length = generated_key_token_length
Kyb_priv_A        = generated_key_token
Kyb_pub_A_length  = target_public_key_token_length
Kyb_pub_A         = target_public_key_token

/* (b) Create a ECC key pair for key agreement */

/* Call CSNDPKB to build a skeleton key token */
rule_array                 = ZCPACK("ECC-PAIR KEY-MGMT")
rule_array_count           = LENGTH(rule_array) / 8
key_value_structure        = '00'x   ||,   /* Prime Curve       */
                             '00'x   ||,   /* Reserved          */
                             '0209'x ||,   /* 521-bit Prime     */
                             '0000'x ||,   /* Zero for skeleton */
                             '0000'x       /* Zero for skeleton */
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

/* Call CSNDPKX to extract the public key */
rule_array_count               = 0
source_key_identifier_length   = generated_key_token_length
source_key_identifier          = generated_key_token
target_public_key_token_length = 8000
"CSNDPKX"
if return_code >= 8 then do
  signal done
end
 
EC_priv_A_length = generated_key_token_length
EC_priv_A        = generated_key_token
EC_pub_A_length  = target_public_key_token_length
EC_pub_A         = target_public_key_token

/* don't bother with certificates to hold the public keys */

say "/*------------------------------------------------------------*/"
say "/* Step 2: The second person (Bob) receives and validates     */"
say "/*         the Kyb-cert-A and EC-cert-A keys from Alice.      */"
say "/*------------------------------------------------------------*/"

/* assume Alice's certificates are valid and use Alice's public keys */

/* 1. After validation, Bob creates these keys: */
/* (a) AES-CIPHER key in a CCA key token        */

/* Call CSNBKTB2 to generate a skeleton for an AES CIPHER key */
rule_array              = ZCPACK("INTERNAL AES CIPHER")
rule_array_count        = LENGTH(rule_array) / 8
target_key_token_length = 725
"CSNBKTB2"
if return_code >= 8 then do
  signal done
end

/* Call CSNBKGN2 to generate an AES CIPHER key */
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

AES_ciph_B_length = generated_key_identifier_1_length
AES_ciph_B        = generated_key_identifier_1

/* (b) Create a ECC key pair for key agreement */

/* Call CSNDPKB to build a skeleton key token */
rule_array                 = ZCPACK("ECC-PAIR KEY-MGMT")
rule_array_count           = LENGTH(rule_array) / 8
key_value_structure        = '00'x   ||,   /* Prime Curve       */
                             '00'x   ||,   /* Reserved          */
                             '0209'x ||,   /* 521-bit Prime     */
                             '0000'x ||,   /* Zero for skeleton */
                             '0000'x       /* Zero for skeleton */
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

/* Call CSNDPKX to extract the public key */
rule_array_count               = 0
source_key_identifier_length   = generated_key_token_length
source_key_identifier          = generated_key_token
target_public_key_token_length = 8000
"CSNDPKX"
if return_code >= 8 then do
  signal done
end
 
EC_priv_B_length = generated_key_token_length
EC_priv_B        = generated_key_token
EC_pub_B_length  = target_public_key_token_length
EC_pub_B         = target_public_key_token

/* 2. Bob creates the shared-key derivation input using the CSNDPKE service. */ 
/*    Bob calls the CSNDPKE service with the RANDOM keyword, AES-ciph-B,     */
/*    Kyb-pub-A, AES encryp-tion IV.                                         */
rule_array                     = ZCPACK("ZERO-PAD RANDOM")
rule_array_count               = LENGTH(rule_array) / 8
keyvalue_length                = 32
sym_key_identifier_length      = AES_ciph_B_length
sym_key_identifier             = AES_ciph_B
PKA_key_identifier_length      = Kyb_pub_A_length
PKA_key_identifier             = Kyb_pub_A
PKA_enciphered_keyvalue_length = 1568
"CSNDPKE"
if return_code >= 8 then do
  signal done
end

/* 3. Bob completes the shared-key derivation, using the CSNDEDH service.  */ 
/*    Bob calls the CSNDEDH service with a derivation keyword, desired key */
/*    length, [AES-ciph-B(rand-32)], AES-ciph-B, AES encryption IV,        */
/*    EC-priv-B, EC-cert-A, output skeleton token.                         */

/* (a) Use CSNBKTB2 to create an AES skeleton token for the shared key */
rule_array              = ZCPACK("INTERNAL AES CIPHER")
rule_array_count        = LENGTH(rule_array) / 8
clear_key_bit_length    = 0
target_key_token_length = 725
"CSNBKTB2"
if return_code >= 8 then do
  signal done
end

/* (b) Use CSNDEDH to derive the shared key */
rule_array                    = ZCPACK("QSA-ECDH DERIV01 IHKEYAES KEY-AES")
rule_array_count              = LENGTH(rule_array) / 8
private_key_identifier_length = EC_priv_B_length
private_key_identifier        = EC_priv_B
public_key_identifier_length  = EC_pub_A_length
public_key_identifier         = EC_pub_A
hybrid_key_identifier_length  = AES_ciph_B_length
hybrid_key_identifier         = AES_ciph_B
party_identifier              = ZCPACK("ALICE BOB")
party_identifier_length       = LENGTH(party_identifier)
key_bit_length                = 256               /* derive AES-256 shared key */
initialization_vector_length  = 16
hybrid_ciphertext_length      = 32
hybrid_ciphertext             = keyvalue          /* output from CSNDPKE */
output_key_identifier_length  = 725               /* 725 would be sufficient */
output_key_identifier         = target_key_token  /* skeleton from CSNBKTB2 */
"CSNDEDH"
if return_code >= 8 then do
  signal done
end

/* 4. Bob stores the shared-key. */

AES_shared_B_length = output_key_identifier_length
AES_shared_B        = output_key_identifier

/* Use CSNBKYT2 to compute a key check value */
rule_array                  = ZCPACK("AES GENERATE SHA-256")
rule_array_count            = LENGTH(rule_array) / 8
key_identifier_length       = AES_shared_B_length
key_identifier              = AES_shared_B
verification_pattern_length = 8
"CSNBKYT2"
if return_code >= 8 then do
  signal done
end
say " "
say "Bob's shared key SHA-256 VP:  " C2X(verification_pattern)
say " "

/* 5. Bob sends EC-cert-B, [Kyb-pub-A(rand-32)] to Alice. */
/* Note: [Kyb-pub-A(rand-32)] is contained in PKA_enciphered_keyvalue from CSNDPKE */

say "/*------------------------------------------------------------*/"
say "/* Step 3: Alice receives and validates EC-cert-B,            */"
say "/*         [Kyb-pub-A(rand-32)].                              */"
say "/*------------------------------------------------------------*/"

/* assume EC-cert-B certificate is valid and use Bob's public key */

/* 1. Alice calls the CSNDEDH service with a derivation keyword, */
/*    desired key length, [Kyb-pub-A (rand-32)], Kyb-priv-A,     */ 
/*    EC-priv-A, EC-cert-B, output skeleton token.               */

/* (a) Use CSNBKTB2 to create an AES skeleton token for the shared key */
rule_array              = ZCPACK("INTERNAL AES CIPHER")
rule_array_count        = LENGTH(rule_array) / 8
clear_key_bit_length    = 0
target_key_token_length = 725
"CSNBKTB2"
if return_code >= 8 then do
  signal done
end

/* (b) Use CSNDEDH to derive the shared key */
rule_array                    = ZCPACK("QSA-ECDH DERIV01 IHKEYKYB KEY-AES")
rule_array_count              = LENGTH(rule_array) / 8
private_key_identifier_length = EC_priv_A_length
private_key_identifier        = EC_priv_A
public_key_identifier_length  = EC_pub_B_length
public_key_identifier         = EC_pub_B
hybrid_key_identifier_length  = Kyb_priv_A_length
hybrid_key_identifier         = Kyb_priv_A
party_identifier              = ZCPACK("ALICE BOB")
party_identifier_length       = LENGTH(party_identifier)
key_bit_length                = 256               /* derive AES-256 shared key */
initialization_vector_length  = 0
hybrid_ciphertext_length      = PKA_enciphered_keyvalue_length
hybrid_ciphertext             = PKA_enciphered_keyvalue        /* output from Bob's CSNDPKE */
output_key_identifier_length  = 725               /* 725 would be sufficient */
output_key_identifier         = target_key_token  /* skeleton from CSNBKTB2 */
"CSNDEDH"
if return_code >= 8 then do
  signal done
end

/* 2. Alice stores the shared-key. */

AES_shared_A_length = output_key_identifier_length
AES_shared_A        = output_key_identifier

/* Use CSNBKYT2 to compute a key check value */
rule_array                  = ZCPACK("AES GENERATE SHA-256")
rule_array_count            = LENGTH(rule_array) / 8
key_identifier_length       = AES_shared_A_length
key_identifier              = AES_shared_A
verification_pattern_length = 8
"CSNBKYT2"
if return_code >= 8 then do
  signal done
end
say " "
say "Alice's shared key SHA-256 VP:" C2X(verification_pattern)
Say " "

done:
call ZCCREXX(OFF)     /* remove ZCCREXX host command environment */
