import "hash"

rule Backdoortest3
 {
 
    meta:
	
	    desription = " to detect malware "
     
	 
	     condition:
		 hash.md5(0, filesize) == "fa441d64d6ff82b1720ad98b1140f955"
 
 }