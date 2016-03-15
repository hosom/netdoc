module Netdoc;

export {
	redef enum Notice::Type += {
		## Notice generated when an undocumented SSH server is found.
		Undocumented_SSH_Server
	};
	
	## Tracking SSH servers
	global ssh_servers: set[addr, port] &redef &synchronized;
}

event connection_state_remove(c: connection)
	{
	if ( c?$ssh && [c$id$resp_h, c$id$resp_p] !in ssh_servers )
		NOTICE([$note=Undocumented_SSH_Server,
				$msg="An undocumented SSH server has been found.",
				$conn=c]);
				
	add ssh_servers[c$id$resp_h, c$id$resp_p];
	}