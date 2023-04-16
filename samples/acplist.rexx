/* REXX */
/* List enabled ACPs for a crypto coprocessor */

call ZCCREXX(ON)    /* install ZCCREXX host command environment */
address ZCCREXX     /* send commands to ZCCREXX by default      */

copro_index = 0     /* set the index of the card to be queried  */

/* call CSFPCI to retrieve Access Control Points */
rule_array_count        = 1
rule_array              = "ACPOINTS"
target_pci_coprocessor  = copro_index
reply_data_block_length = 32768
masks_length            = 32
"CSFPCI"
if return_code <> 0 then do
  signal done
end

/* gather ACPs */
offset = 1
n = 0
do while offset <= reply_data_block_length
  record_type = SUBSTR(reply_data_block, offset, 1)
  if record_type = '01'x then do        /* group header - not interesting */
    description_length = C2D(SUBSTR(reply_data_block, offset + 1, 4))
    offset             = offset + description_length + 5
  end
  else if record_type = '02'x then do   /* ACP description */
    acp_index          = SUBSTR(reply_data_block, offset + 1, 2)    /* leave in binary form for correct sorting */
    description_length = C2D(SUBSTR(reply_data_block, offset + 3, 4))
    description        = toEBCDIC(SUBSTR(reply_data_block, offset + 7, description_length))
    bit_mask           = SUBSTR(reply_data_block, offset + 7 + description_length, 4)
    enable_list_count  = C2D(SUBSTR(reply_data_block, offset + 11 + description_length, 4))
    offset             = offset + 15 + description_length + 2 * enable_list_count
    n                  = n + 1
    acp.n              = acp_index||description
  end
  else do
    say "*** OOPS - unrecognized record type "
    signal done
  end
end

/* sort by acp index */
acp.0 = n
call sort(acp)

/* print out ACPs */
say "Enabled Access Control Points for target_pci_coprocessor:" target_pci_coprocessor
do i = 1 to acp.0
  say C2X(LEFT(acp.i, 2)) SUBSTR(acp.i, 3)
end

done:
call ZCCREXX(OFF)   /* remove ZCCREXX host command environment */
return

sort:
arg stem .
interpret 'sort_n = 'stem'.0'
if sort_n <= 0 then return
sort_list.0 = 1
interpret 'sort_list.1 = 'stem'.1'
if sort_n > 1 then do
  /* find a spot for the next element in the input, starting at the end */
  do sort_i = 2 to sort_n
    interpret 'sort_new = 'stem'.sort_i'
    sort_j = sort_list.0
    do while sort_j > 0 & sort_new < sort_list.sort_j
      sort_k = sort_j + 1
      sort_list.sort_k = sort_list.sort_j
      sort_j = sort_j - 1
    end
    sort_k = sort_j + 1
    sort_list.sort_k = sort_new
    sort_list.0 = sort_list.0 + 1
  end
end
do sort_i = 1 to sort_n
  interpret stem'.sort_i = sort_list.sort_i'
end
return

toEBCDIC: procedure
arg ascii_text
/* call CSNBXAE to convert ASCII text to EBCDIC */
ZCERRSAY    = 0     /* suppress CCA API result banner */
text_length = LENGTH(ascii_text)
source_text = ascii_text
code_table  = '00000000'x
"CSNBXAE"
return target_text
