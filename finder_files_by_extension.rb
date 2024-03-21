##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post
  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => '[Windows] [Post] [Listener] [Get all files with txt extension and enumerate]',
        'Description' => %q{
          Say something that the user might want to know.
        },
        'License' => MSF_LICENSE,
        'Author' => [ 'Adil et Lazare' ],
        'Platform' => [ 'win', 'linux',],
        'SessionTypes' => [ 'meterpreter']
      )
    )
  end

  def run
    puts "module run"
  end
end
