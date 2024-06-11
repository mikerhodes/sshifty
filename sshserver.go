package main

import (
	"encoding/binary"
	"log"
	"net"
	"os"
	"sync"

	"golang.org/x/crypto/ssh"
)

func main() {
	// An SSH server is represented by a ServerConfig, which holds
	// certificate details and handles authentication of ServerConns.
	config := &ssh.ServerConfig{
		NoClientAuth: true,
	}

	// We need to set a host key, or the SSH server won't
	// start.
	privateBytes, err := os.ReadFile("id_rsa")
	if err != nil {
		log.Fatal("Failed to load private key: ", err)
	}
	private, err := ssh.ParsePrivateKey(privateBytes)
	if err != nil {
		log.Fatal("Failed to parse private key: ", err)
	}
	config.AddHostKey(private)

	// Once a ServerConfig has been configured, connections can be
	// accepted.
	listener, err := net.Listen("tcp", "0.0.0.0:2022")
	if err != nil {
		log.Fatal("failed to listen for connection: ", err)
	}

	log.Println("Waiting for connections")
	nConn, err := listener.Accept()
	if err != nil {
		log.Fatal("failed to accept incoming connection: ", err)
	}
	defer nConn.Close()

	// We wrap the socket in a server, which performs the
	// protocols handshake and accepts our ssh connection.
	conn, chans, reqs, err := ssh.NewServerConn(nConn, config)
	if err != nil {
		log.Fatal("failed to handshake: ", err)
	}
	defer conn.Close()

	// Allow us to wait on a lot of goroutines we will kick
	// off --- remember we said that SSH was multiplexed?
	var wg sync.WaitGroup
	defer wg.Wait()

	// The incoming Request channel must be serviced.
	// This contains just heartbeats for shell sessions,
	// but I think contains more for things like port forwarding.
	wg.Add(1)
	go func() {
		ssh.DiscardRequests(reqs)
		wg.Done()
	}()

	// In the Go server implementation, we receive new
	// SSH multiplexed channels via the chans ... go channel.
	for newChannel := range chans {
		// "session" is the type used for shells, let's
		// only accept that and reject other channels the
		// client might request.
		if newChannel.ChannelType() != "session" {
			newChannel.Reject(ssh.UnknownChannelType, "unknown channel type")
			continue
		}
		channel, requests, err := newChannel.Accept()
		if err != nil {
			log.Fatalf("Could not accept channel: %v", err)
		}
		log.Println("Accepted a new channel!")

		// channel is the stream object --- it has Read and
		// Write methods. Those can be used to receive data
		// from the ssh client, and send things back to the
		// client.
		// requests are the instructions for how we are using
		// this channel --- eg, to start a shell or run a
		// one-off command.
		// Broadly speaking, we listen for requests until we
		// figure out what the client wants to use this
		// channel's data streaming for, then get on with doing
		// that.

		// Finally, we can spy on what the SSH clients sends:
		wg.Add(1)
		go func(in <-chan *ssh.Request) {
			for req := range in {
				log.Printf("received req %s", req.Type)

				// We respond to pty-req ("allocate me a
				// pseudo-terminal") and shell ("start me
				// a shell, and connect the channel to it")
				// so that the ssh client will send a few
				// requests.
				switch req.Type {
				case "pty-req":
					req.Reply(true, nil)
				case "shell":
					req.Reply(true, nil)
					channel.Write([]byte("Hello SSH\r\n"))

					channel.Write([]byte("bye now\r\n"))
					buf := make([]byte, 4)
					binary.BigEndian.PutUint32(buf, 4)
					channel.SendRequest("exit-status", false, buf[0:4])

					channel.Close()
				case "exec":
					log.Printf("req exec with payload (cmd): %s", string(req.Payload))
					req.Reply(true, nil)
					channel.Write([]byte("Hello SSH\r\n"))
					channel.Write([]byte("You sent: "))
					channel.Write(req.Payload)
					channel.Write([]byte("\r\n\n"))

					channel.Write([]byte("bye now\r\n"))
					buf := make([]byte, 4)
					binary.BigEndian.PutUint32(buf, 4)
					channel.SendRequest("exit-status", false, buf[0:4])

					channel.Close()
				default:
					req.Reply(false, nil)
				}
			}
			wg.Done()
		}(requests)

	}
}
