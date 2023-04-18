/* REXX */
/* Generate a one-way hash */

call ZCCREXX(ON)      /* install ZCCREXX host command environment */
address ZCCREXX       /* send commands to ZCCREXX by default      */

alg  = ""
text = ""
parse arg alg string
if alg = "" then do
  say "Usage: owh algorithm text..."
  say " "
  say "  algorithm is MD5      RPMD-160"
  say "               SHA-1    SHA-224  SHA-256  SHA-384  SHA-512"
  say "               SHA3-224 SHA3-256 SHA3-384 SHA3-512"
  say "               SHAKE128 SHAKE256"
  return 8
end

rule_array_count         = 1
rule_array               = alg
text_length              = LENGTH(string)
text                     = string
chaining_vector_length   = 128
if LEFT(alg, 4) = "SHA3" | LEFT(alg, 5) = "SHAKE" then do
  chaining_vector_length = 256
end
trim_length              = 0
select
  when LEFT(alg, 3) = "MD5" then
    hash_length          = 16
  when LEFT(alg, 4) = "RPMD" then
    hash_length          = 20
  when alg          = "SHA-1" then
    hash_length          = 20
  when alg          = "SHA-224" then do
    hash_length          = 32
    trim_length          = 4
  end
  when alg          = "SHA-256" then
    hash_length          = 32
  when alg          = "SHA_384" then do
    hash_length          = 64
    trim_length          = 16
  end
  when alg          = "SHA3-224" then
    hash_length          = 28
  when alg          = "SHA3-256" then
    hash_length          = 32
  when alg          = "SHA3-384" then
    hash_length          = 48
  otherwise
    hash_length          = 64
end
"CSNBOWH"
if return_code < 8 then do
  output_length = hash_length - trim_length
  say alg"("""string""" in EBCDIC):" C2X(LEFT(hash, output_length))
end

if text_length > 0 then do
  /* convert input string to ASCII */
  source_text = string
  code_table  = '00000000'x
  "CSNBXEA"
  if return_code = 0 then do
    /* compute hash on ASCII text */
    text = target_text
    chaining_vector = '00'x
    "CSNBOWH"
    if return_code < 8 then do
      output_length = hash_length - trim_length
      say alg"("""string""" in ASCII): " C2X(LEFT(hash, output_length))
    end
  end
end

call ZCCREXX(OFF)     /* remove ZCCREXX host command environment */
