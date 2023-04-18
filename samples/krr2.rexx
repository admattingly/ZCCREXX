/* REXX */
/* Read a record from the CKDS */

call ZCCREXX(ON)      /* install ZCCREXX host command environment */
address ZCCREXX       /* send commands to ZCCREXX by default      */

label = ""
arg label .
if label = "" then do
  say "Usage: krr2 key_label"
  return 8
end

key_label        = label
key_token_length = 725
"CSNBKRR2"
if return_code < 8 then do
  say "Key token:" c2x(key_token)
end

call ZCCREXX(OFF)     /* remove ZCCREXX host command environment */
