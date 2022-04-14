import "hash"

rule Backdoortest2
 {
 
    meta:
	
	    desription = " to detect malware "
     
	 
	     condition:
		 hash.md5(0, filesize) == "1ec44740e3d5d1fda054ad171c4cafff"
 
 }