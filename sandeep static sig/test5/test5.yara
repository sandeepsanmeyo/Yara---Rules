import "hash"

rule Backdoortest4
 {
 
    meta:
	
	    desription = " to detect malware "
     
	 
	     condition:
		 hash.md5(0, filesize) == "bcc7caa6a013aad40f40c4ef7711c725"
 
 }