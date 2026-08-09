rule EICAR_Test_File {
  meta:
    description = "Development-only EICAR test signature"
  strings:
    $eicar = "EICAR-STANDARD-ANTIVIRUS-TEST-FILE" ascii
  condition:
    $eicar
}

