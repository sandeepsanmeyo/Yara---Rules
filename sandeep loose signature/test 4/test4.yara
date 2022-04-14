rule Backdoorloosedemo5strings
{
         meta: 
		   owner="vamshi"
		   malware="backdoor sample"
		   
		   strings:
		    $a=  "wtypesbase.h"
			
             $b=   ".refptr.WSAID_CONNECTEX__YmR9c9crObjjK9ckt1ygsPQKg"           
			 $c=  "http://serv1.ec2-102-95-13-2-ubuntu.local "
			 
		
			 
			 condition:
			  ($a and $b or $c )
			 
}