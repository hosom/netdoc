##! Enable alerting on new certificate seen. Do not enable this before 
##! performing some intial tuning.

module Netdoc;

@load policy/protocols/ssl/known-certs
@load base/frameworks/notice

export {
	## Notice message for never before seen certificate
	redef enum Notice::Type += { Undocumented_Certificate };
	
	## Long term tracking for certificates
	global certs: set[addr, string] &synchronized &redef;	
}

event ssl_established(c: connection)
	{

	if ( ! c$ssl?$cert_chain || |c$ssl$cert_chain| < 1 ||
		! c$ssl$cert_chain[0]?$x509 )
		return;

	if ( ! Site::is_local_addr(c$id$resp_h) )
		return;
	
	if ( ! c$ssl$cert_chain[0]?$sha1 )
		return;
		
	local hash = c$ssl$cert_chain[0]$sha1;
	local host = c$id$resp_h;
	if ( [host, hash] !in Netdoc::certs )
		NOTICE([$note=Undocumented_Certificate, 
				$msg="An undocumented x509 certificate is in use.",
				$fuid=c$ssl$cert_chain[0]$fuid,
				$sub=c$ssl$subject,
				$conn=c]);
	
	add Netdoc::certs[host, hash]; 
	}
