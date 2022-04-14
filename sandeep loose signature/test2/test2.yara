 rule Backdoortest2strings
{
         meta: 
		    
		     malware="backdoor sample"
		   
      strings:
		    
		    $a= "Client.exe"
			
           $b= "Remote cloud logging"
		   
		     $c= "4System.Web.Services.Protocols.SoapHttpClientProtocol"
		 		 
    condition:
		
		($a and $b or $c)
						 
}