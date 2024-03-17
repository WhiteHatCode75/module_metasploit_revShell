require 'socket'

hostname = 'localhost'
port = 3000

# Connexion au serveur
client = TCPSocket.open(hostname, port)


response = client.gets.chomp
while response != "exit"
    puts response
    client.puts "reponse"
    response = client.gets.chomp
end

client.close
