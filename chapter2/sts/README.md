[ sts: simple time server ]

this is a simple time server. the server encrypts the time messages with
the secret key, and when clients connect, it sends the encrypted time
message to the client. when the client connects to the server and receives
the message, it attempts to decrypt it and prints it to the screen.

to run, first ensure the server and client have a copy of the key available.
the key may be specified in both applications using the `-k` flag. for
example,

    <ono-sendai: chapter2/sts> $ gensymkey server.key
    [+] generating 1 keys: .
    [+] generated 1 keys
    <ono-sendai: chapter2/sts> $ go run server/server.go &
    [1] 19012
    2013/02/14 21:39:55 listening on  :4141
    <ono-sendai: chapter2/sts> $ go run client/client.go -k server.key 
    [+] dialing server:  :4141
    2013/02/14 21:40:38 plaintext: 1360903238
    [+] decrypted message is 10 bytes
    [+] retrieved time:
         2013-02-14 21:40:38 -0700 MST
    <ono-sendai: chapter2/sts> $

the server searches the current directory for the key `server.key`; the
client program searches for `client.key`. if the key isn't found, the
program aborts.
