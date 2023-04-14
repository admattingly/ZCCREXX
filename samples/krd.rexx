/* REXX */
/* Delete a record from the CKDS */
/* REXX equivalent: https://community.ibm.com/community/user/ibmz-and-linuxone/blogs/eysha-shirrine-powers2/2020/03/25/rexx-sample-key-record-delete */

call ZCCREXX(ON)      /* install ZCCREXX host command environment */
address ZCCREXX       /* send commands to ZCCREXX by default      */

label = ""
arg label .
if label = "" then do
  say "Usage: krd key_label"
  return 8
end

rule_array_count = 1
rule_array       = "LABEL-DL"
key_label        = label
"CSNBKRD"

call ZCCREXX(OFF)     /* remove ZCCREXX host command environment */
