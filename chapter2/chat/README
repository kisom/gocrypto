[ marchat ]

Chat server demonstration for the March Denver Gopher's meetup (marchat == Mar CH at).

Usage:
        marchat [-k file] [-p port] [-u username]
        
        -k file         file containing the AES key for the conversation; if
                        no key file is provided, encryption is turned off.
        -p port         port for web interface, defaults to 4000.
        -u user         username to send messages as, defaults to "anonymous".


Installing:
        go get github.com/gokyle/marchat


Example Keys:

Two AES keys have already been generated for demonstration purposes.


Demo scenario:

2 users using 'demo.key'. (marchat -u my_name -k demo.key)
1 user with 'wrong.key'. (marchat -u my_name -k wrong.key)
1 user with no encryption. (marchat -u my_name)


Usage:

Open your web browser to http://localhost:port, where port is the port you
specified in the options (or 4000 if you didn't). For example,

          http://localhost:4000 -u Joe


Notes:

marchat uses UDP multicast for chatting; messages may be lost on the wire.


Credits:

The HTML UI uses Twitter's Bootstrap for styling. Twitter's Bootstrap is
licensed under the Apache 2.0 license. See
https://github.com/twitter/bootstrap/blob/master/LICENSE

This project was inspired by, and borrows elements from, Andrew Gerrand's
"Go: code that grows with grace" (http://talks.golang.org/2012/chat.slide#1).

Aaron Bieber (https://github.com/qbit) contributed some improvements.
