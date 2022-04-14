rule Backdoortest3strings
{
         meta: 
		    
		     malware="backdoor sample"
		   
      strings:
		    
		    $a="http://exasperated-comprom.006ugbhostapp.com/ranger/sass/boofwrrap/mixins/mixins1/gate.php"
		     
             $b = "XDFBGJGF.exe"
			 	 
    condition:
		
		($a or $b)
}