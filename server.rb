require 'socket'

class Server
  def initialize(port)
    @server = TCPServer.new('localhost', port)
    @clients = []
  end

  def start
    puts "Serveur démarré. En attente de connexions..."
    
    # Thread pour accepter de nouveaux clients
    accept_thread = Thread.new do
      loop do
        client = @server.accept
        @clients << client
        puts "Nouveau client connecté: #{client}"
      end
    end

    # Thread pour interagir avec les clients
    interact_thread = Thread.new do
      loop do
        sleep(0.1) # Attente pour éviter une utilisation excessive du CPU
        next if @clients.empty?

        client = @clients.first
        interact_with(client)
      end
    end

    [accept_thread, interact_thread].each(&:join)
  end

  def interact_with(client)
    print "commande :  "
    command = gets&.chomp
    while command != "exit" 
        print "commande : "
        command = gets&.chomp
        client.puts command

        res = client.gets.chomp
        puts res
    end
  end

  def broadcast(message, sender)
    @clients.each do |client|
      next if client == sender
      client.puts message
    end
  end
end

server = Server.new(3000)
server.start
