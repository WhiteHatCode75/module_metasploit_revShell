require 'socket'

class MetasploitModule < Msf::Exploit::Remote
    Rank = NormalRanking
  
    def initialize(info = {})
      super(
        update_info(
          info,
          'Name' => '[Upec] [Software] [Root Cause] [Vulnerability type]',
          'Description' => %q{
            reverse_shell manager by lazare and adil
          },
          'License' => MSF_LICENSE,
          'Author' => [ 'Name' ],
          'References' => [
            [ 'URL', '' ]
          ],
          'Platform' => 'win',
          'Targets' => [
            [
              'Windows x64',
              {
                'Ret' => 0x41414141 # This will be available in `target.ret`
              }
            ]
          ],
          'Payload' => {
            'BadChars' => "\x00"
          },
          'Privileged' => false,
          'DisclosureDate' => '',
          'DefaultTarget' => 0,
          'Notes' => {
            'Stability' => [CRASH_SAFE],
            'Reliability' => [REPEATABLE_SESSION],
            'SideEffects' => [ARTIFACTS_ON_DISK, IOC_IN_LOGS]
          },
        )
      )
    end
  
    def check

    end
  
    def exploit
      
    end

    def initServer      
      # Création d'un serveur TCP sur le port 8888
      server = TCPServer.new(8888)

      # Tableau pour stocker les clients connectés
      clients = []

      # Fonction pour envoyer un message à tous les clients
      def broadcast(message, clients)
        clients.each do |client|
          client.puts message
        end
      end

      # Accepter et gérer les connexions des clients
      Thread.new do
        loop do
          client = server.accept
          clients << client

          # Lecture des messages du client et diffusion à tous les clients
          Thread.new(client) do |cl|
            loop do
              message = cl.gets.chomp
              broadcast(message, clients)
            end
          end
        end
      end

      # Lire les saisies de l'utilisateur et les envoyer à tous les clients
      loop do
        print "Saisir un message : "
        message = gets.chomp
        broadcast(message, clients)
      end
    end  
  
  end