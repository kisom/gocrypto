package main

import (
	"fmt"
	"html/template"
	"log"
	"net/http"
)

func rootHandler(w http.ResponseWriter, r *http.Request) {
	err := rootTemplate.Execute(w, config)
	if err != nil {
		log.Fatal("[!] serving root: ", err.Error())
	}
}

var rootTemplate = template.Must(template.New("root").Parse(`
<!doctype html>
<html>
  <head>
    <meta charset="utf8" />
    <title>MarCHat</title>
    <link href="//netdna.bootstrapcdn.com/twitter-bootstrap/2.3.1/css/bootstrap-combined.no-icons.min.css"
          rel="stylesheet">
    <script>
        var transmitter, receiver, input, output;
        
        var mlist;
        function printMessages(ml) {
                mlst = JSON.parse(ml.data)
                if (mlst.length === 0)
                        return;
                mlist = mlst;

                for (var i = 0; i < mlst.length; i++) {
			var p = document.createElement('p');
			p.innerHTML = atob(mlst[i]);
			output.appendChild(p);
		}
		output.scrollTop = 1000000
        };
        
        function onKey(e) {
        	if (e.keyCode == 13) {
        		sendMessage();
        	}
        };
        
        function sendMessage() {
                var m = input.value;
                input.value = "";
                transmitter.send(m + '\n');
        };
        
        function checkMessages() {
                // server handles connection shutdown
                var receiver = new WebSocket('ws://127.0.0.1:{{.Port}}/incoming')
                receiver.onmessage = printMessages;
        }
        
        function init() {
                output = document.getElementById('messages');
                transmitter = new WebSocket('ws://127.0.0.1:{{.Port}}/socket');
        
        	input = document.getElementById("input");
        	input.addEventListener("keyup", onKey, false);
                check = setInterval(checkMessages, 1000);
        
        };
        window.addEventListener("load", init, false);
   
    </script>

    <style type="text/css">
        html,
        body {
            height: 100%; 
        }
        #wrap {
            min-height: 100%;
            height: auto !important;
            height: 100%; 
            margin: 0 auto -60px;
        }
        #push, #footer {
            height: 60px;
        }
        #footer {
            background-color: #f5f5f5;
        }
        @media (max-width: 767px) {
            #footer {
                margin-left: -20px;
                margin-right: -20px;
                padding-left: 20px;
                padding-right: 20px;
            }
        }
        .container {
            width: auto;
            max-width: 680px;
        }
        .container .credit {
            margin: 20px 0;
        }
	#messages { height: 300px; overflow: auto; width: 800px; border: 1px solid #eee; font: 13px Helvetica, Arial; }
	#messages p { padding: 8px; margin: 0; }
	#messages p:nth-child(odd) { background: #F6F6F6; }
    </style>
  </head>

  <body>
    <div id="wrap">
      <div class="container"> 
        <div class="row">
          <div class="span4"></div>
          <div class="span4">
            <h3 style="text-align:center">chatting as '{{.User}}'</h3>
            <p style="text-align:center"><input id='input' type = "text"></p>
            <small style="text-align:center">Hit enter to send a message.</small>
            <h3 style="text-align:center">Messages</h3>
            <div id="messages"></div>
          </div>
          <div class="span4"></div>
        </div>
      </div>
    </div>
  </body>
</html>
`))

func ShowError(msg string) string {
	return fmt.Sprintf(`<span style="color:red">%s</span>`, msg)
}

func ShowSuccess(msg string) string {
	return fmt.Sprintf(`<span style="color:green">%s</span>`, msg)
}

func ShowControl(msg string) string {
	return fmt.Sprintf(`<em>%s</em>`, msg)
}
