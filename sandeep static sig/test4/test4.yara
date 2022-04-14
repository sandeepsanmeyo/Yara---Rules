import "hash"

rule Backdoortest4
 {
 
    meta:
	
	    desription = " to detect malware "
     
	 
	     condition:
		 hash.md5(0, filesize) == "a6ba7be5d2435b6a5e0ae81e56833598"
 
 }