/* REXX */
/* This REXX contains a sample that lists all records in the CKDS.   */
/* REXX equivalent: https://community.ibm.com/community/user/ibmz-and-linuxone/blogs/eysha-shirrine-powers2/2020/03/25/rexx-sample-list-records-in-the-ckds */

call ZCCREXX(ON)      /* install ZCCREXX host command environment */
address ZCCREXX       /* send commands to ZCCREXX by default      */

/*********************************************************************/
/* Get the CKDS record count                                         */
/*********************************************************************/
rule_array          = ZCPACK("CKDS COUNT ALL")
rule_array_count    = LENGTH(rule_array) / 8
"CSFKDSL"

say "CKDS record count: " label_count

/*********************************************************************/
/* List the CKDS record labels                                       */
/*********************************************************************/
rule_array          = ZCPACK("CKDS LABELS ALL")
rule_array_count    = LENGTH(rule_array) / 8
label_filter_length = 1
label_filter        = "*"
output_list_length  = label_count * 72
"CSFKDSL"

if return_code = 0 & output_list_length > 0 then do
  offset = 1
  do i = 1 TO label_count
    say 'Key Label: ',
      SUBSTR(output_list, offset, 64) /* Ignore 8 byte key type */
    offset = offset + 72
  end
end

say "-----------------------------------------------------------------"
say "End of Sample"
say "-----------------------------------------------------------------"

call ZCCREXX(OFF)     /* remove ZCCREXX host command environment */
