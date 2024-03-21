##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post
  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => '[Platform] [Module Category] [Software] [Function]',
        'Description' => %q{
          Say something that the user might want to know.
        },
        'License' => MSF_LICENSE,
        'Author' => [ 'Name' ],
        'Platform' => [ 'win', 'linux', 'osx', 'unix', 'bsd', 'solaris' ],
        'SessionTypes' => [ 'meterpreter', 'shell' ]
      )
    )
  end

  def run
    # Main method
  end
end
