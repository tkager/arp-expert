-- ARP Expert 1.0b
-- Writen by Thomas Kager
-- tkager@linux.com

-- Created 3/12/2016
-- Last modified 3/13/16

--[[

- Purpose
The purpose of this script is to pull ARP transaction security and performance data from a packet trace.

Potential uses may include:
- ARP spoofing attempts
- ARP storms
- IP conflicts
- Incorrectly configured subnet masks/IPs, etc.

- Usage
tshark -r "(filename)" -2 -X lua_script:arp_expert.lua

	filename = capture file

- Requirements
Requires Wireshark/Tshark 1.10 or later with LUA compiled. This can be determined through the "About Wireshark" menu option.
--]]

tap=Listener.new(nil, "arp") -- Create Listener, with a Filter for ARP traffic (only).

arp = {} -- Create usrdata array http.

-- Field Extractors are used to map tshark fields to variables and typically behave as function calls

-- ARP extractors
arp_opcode=Field.new("arp.opcode")
arp_src_hw_mac=Field.new("arp.src.hw_mac")
arp_src_proto_ipv4=Field.new("arp.src.proto_ipv4")
arp_dst_proto_ipv4=Field.new("arp.dst.proto_ipv4")

-- Calculated fields. It appears that when you are using more than one of these of fields, you need to map it to a real extractor field
arp_requests=Field.new("frame.number")
arp_replies=Field.new("frame.number")
arp_mac=0 -- we seem to be able to use one bogus non-field extractor in tap_packet(). Need to understand this better.

function tap.draw() -- Wireshark/Tshark explicitly looks for tap.draw() after running through all packets.

-- Header Output. Needs to occur once before we iterate through the array(s) in the main loop.
print("-- ARP Expert 1.0")
print("-- Writen by Thomas Kager")
print("-- tkager@linux.com")
print()

io.write("Who","\t\t\t","Requests","\t", "Replies", "\t\t", "Is At")
io.write("\n") --- linespace after header.  This can occur within previous write operation.

-- Main Loop
for k,v in pairs (arp) do
	io.write(tostring(k),"\t\t",tostring(arp[k][arp_requests]),"\t\t",tostring(arp[k][arp_replies]),"\t\t")

	if (arp[k][arp_mac]) == nil then -- if there are no mac entries we have requests without responses.

	else
		for x,y in pairs (arp[k][arp_mac]) do
			io.write(tostring(y)," ")
		end
	end

io.write("\n") --- linespace after row. This can also occur as part of one large write operation.
end

end -- end tap.draw()


function tap.packet() -- Wireshark/Tshark explicitly looks for tap.packet(). It runs for each frame that matches listener filter.

if tostring(arp_opcode()) == "1" then -- If frame is an ARP request and there are specific fields that we can polulate/tally.

	binding=tostring(arp_dst_proto_ipv4())

	if arp[binding] == nil then
	arp[binding]={}
	arp[binding][arp_requests]=1
	arp[binding][arp_replies]=0

	else
	arp[binding][arp_requests]=arp[binding][arp_requests]+1

	end


else if tostring(arp_opcode()) == "2" then -- If frame is an ARP response, there are specific fields which we need to collect.

	binding=tostring(arp_src_proto_ipv4())

	if arp[binding] == nil then
		arp[binding]={}
		arp[binding][arp_requests]=0
		arp[binding][arp_replies]=1

	-- Create entry for source mac, if it doesn't exist.
		src_mac=tostring(arp_src_hw_mac())

		if arp[binding][arp_mac] == nil then
			arp[binding][arp_mac]={}
		end

		if arp[binding][arp_mac][arp_src_hw_mac] == nil then
			arp[binding][arp_mac][arp_src_hw_mac] = src_mac

		end

	else
		arp[binding][arp_replies]=arp[binding][arp_replies]+1
		src_mac=tostring(arp_src_hw_mac())

		if arp[binding][arp_mac] == nil then -- If there is no mac entry, create one.
			arp[binding][arp_mac]={}
			arp[binding][arp_mac][arp_src_hw_mac] = src_mac
		else
			x = arp[binding][arp_mac][arp_src_hw_mac]
			_, count = string.gsub(x, src_mac, " ")
			if count == 0 then -- Check to determine whether the mac (is at) was found in the existing entry. If not, add it to the list.
				arp[binding][arp_mac][arp_src_hw_mac] = x .. " " .. src_mac
			end
		end

	end

else -- for the unknown case which should never exist.
	end

end -- End IF (the one which checks to determine whether it is request or response)

end -- end of tap_packet()
