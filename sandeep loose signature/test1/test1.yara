rule Backdoortest1strings
{
         meta: 
		    
		     malware="backdoor sample"
		   
      strings:
		    
		    $a="https://secure.comodo.net/CPS0C"
		     
                    $b= "http://ocsp.comodoca.com0"
		   
		     $c= "DeleteFile"
			 
		 		 
    condition:
		
		($a and $b and $c)
						 
}