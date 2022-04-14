rule Backdoorloosetest4strings
{
         meta: 
		 
		   malware="backdoor sample"
		   
		   strings:
		 
			
             $b=   ".refptr.WSAID_CONNECTEX__YmR9c9crObjjK9ckt1ygsPQKg"           
			 $c=  "http://serv1.ec2-102-95-13-2-ubuntu.local "
			 
		
			 
			 condition:
			  ( $b or $c )
			 
}
