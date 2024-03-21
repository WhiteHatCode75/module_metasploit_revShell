##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post
  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => '[Platform] [Post] [Listener] [Get all files with txt extension and enumerate]',
        'Description' => %q{
          Say something that the user might want to know.
        },
        'License' => MSF_LICENSE,
        'Author' => [ 'Adil et Lazare' ],
        'Platform' => [ 'win', 'linux',],
        'SessionTypes' => [ 'meterpreter'],
        'Compat' => {
          'Meterpreter' => {
            'Commands' => %w[
              core_migrate
              stdapi_railgun_api
              stdapi_sys_process_get_processes
              stdapi_sys_process_getpid
              stdapi_ui_get_idle_time
              stdapi_ui_get_keys_utf8
              stdapi_ui_start_keyscan
              stdapi_ui_stop_keyscan
            ]
          }
        }
      )
    )

    register_options(
      [
        OptString.new('EXTENSION', [true, 'File Extension to harvest', 'txt']),
        OptPath.new('DIRECTORY', [true, 'Starting point', '/']),
        OptBool.new('VERBOSE', [false, 'verbose mode', false]),
        OptString.new('FILE NAME', [false, 'search a specific file', nil]),
      ]
    )
  end

  def run
    puts "module run"
  end
end
