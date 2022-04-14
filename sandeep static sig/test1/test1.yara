import "hash"

rule Backdoortest
 {
 
    meta:
	
	    desription = " to detect malware "
     
	 
	     condition:
		 hash.md5(0, filesize) == "2c098a1b29f77e7c23aab17f10487fe4"
 
 }