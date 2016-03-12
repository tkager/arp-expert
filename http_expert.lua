
-- HTTP Expert 1.1
-- Writen by Thomas Kager
-- tkager@linux.com

-- Created 3/11/2016
-- Last modified 3/12/16

--[[

- Purpose
The purpose of this script is to pull HTTP transaction security and performance data from a packet trace.

- Usage
tshark -r "(filename)" -2 -X lua_script:http_expert.lua -q > (filename.csv)

	filename = capture file
	filename.csv = destination csv. The output of this script is CSV for easy import into spreadsheet program such as Excel. While it is possible to output to terminal,
	file redirection (>) is encouraged due to variable field length and readability concerns.

- Requirements
Requires Wireshark/Tshark 1.10 or later with LUA compiled. This can be determined through the "About Wireshark" menu option.
--]]

tap=Listener.new(nil, "http") -- Create Listener, with a Filter for HTTP traffic (only).

http = {} -- Create usrdata array http.

-- Field Extractors are used to map tshark fields to variables and typically behave as function calls

-- Information collected/derived from HTTP request
http_request_time=Field.new("frame.time")
http_request_frame=Field.new("frame.number")
client=Field.new("ip.src")
server=Field.new("ip.dst")
http_request_method=Field.new("http.request.method")
http_request_version=Field.new("http.request.version")
http_user_agent=Field.new("http.user_agent")
http_host=Field.new("http.host")
http_request_uri=Field.new("http.request.uri")
http_data=Field.new("http") -- Esentially a Hex dump of the entire header field. Used to calculate the number of optional header fields.
http_request_header_fields=0 -- As this is a caculated field, there is no direct mapping to tshark field extractor. We need to create it but we will just initialize it to 0.

-- Information collected from HTTP response
http_reply_frame=Field.new("frame.number")
http_request_in=Field.new("http.request_in")
http_response_code=Field.new("http.response.code")
http_cache_control=Field.new("http.cache_control")
http_time=Field.new("http.time")


function tap.draw() -- Wireshark/Tshark explicitly looks for tap.draw() after running through all packets.
-- Header Output. Needs to occur once before we iterate through the array(s) in the main loop.
io.write("request frame",",","request time",",","client",",","server",",","request method",",","request version",",","http host",",","request uri",",","user agent",",","request header fields",",","response frame",",","response code",",","response time",",","cache control")
io.write("\n") --- linespace after header.  This can occur within previous write operation.

-- Main Loop
for k,v in pairs (http) do
-- Optimal to combine these into a single IO write. Such a write can be extended across multiple lines, however this convention breaks prior to LUA 5.2.
io.write(tostring(k),",",tostring(http[k][http_request_time]),",",tostring(http[k][client]),",",tostring(http[k][server]),",",tostring(http[k][http_request_method]),",",tostring(http[k][http_request_version]),",",tostring(http[k][http_host]),",",tostring(http[k][http_request_uri]),",",tostring(http[k][http_user_agent]),",",tostring(http[k][http_request_header_fields]),",")
io.write(tostring(http[k][http_reply_frame]),",",tostring(http[k][http_response_code]),",",tostring(http[k][http_time]),",",tostring(http[k][http_cache_control]))
io.write("\n") --- linespace after row. This can also occur as part of one large write operation.
end

end -- end tap.draw()


function tap.packet() -- Wireshark/Tshark explicitly looks for tap.packet(). It runs for each frame that matches listener filter.

if http_request_method() then -- If frame is an HTTP request, there are specific fields that we need to collect.

	request_frame=tostring(http_request_frame())
	http[request_frame]={}
	http[request_frame][http_request_time]=tostring(http_request_time()):gsub(',','')
	http[request_frame][client]=tostring(client())
	http[request_frame][server]=tostring(server())
	http[request_frame][http_request_method]=tostring(http_request_method())
	http[request_frame][http_request_version]=tostring(http_request_version())
	http[request_frame][http_host]=tostring(http_host())
	http[request_frame][http_request_uri]=tostring(http_request_uri())

	-- Determine Number of Request Header Fields.
	x=tostring(http_data())
	_, count = string.gsub(x, "0d:0a", " ") -- Count number of CR/LF, as these delineate header fields.
	_, double_white = string.gsub(x, "0d:0a:0d:0a", " ") -- Count occurrenes in which 2 CR/LF occur one after these other, as these will be counted as 2 header fields.
	http[request_frame][http_request_header_fields]=count - double_white - 1 -- Subtract multiple CR/LF occurrences from the CR/LF count. Also subtract 1, because there is an occurence between (method, URI, version) and the first header.

	-- Add user_agent if present within headers store the value, else populate with none. This is necessary as we will get an error if the header field doesn't exist.
	if http_user_agent() == nil then
		http[request_frame][http_user_agent]="none"
	else
		http[request_frame][http_user_agent]=tostring(http_user_agent())
	end

else if http_response_code() then -- If frame is an HTTP response, there are specific fields which we need to collect.
	request_in=tostring(http_request_in())
	http[request_in][http_reply_frame]=tostring(http_reply_frame())
	http[request_in][http_response_code]=tostring(http_response_code())
	http[request_in][http_time]=tostring(http_time())
	-- Check for cache control. If it doesn't exist, store none. Else store the value.
	if http_cache_control() == nil then
		http[request_in][http_cache_control]="none"
	else
		http[request_in][http_cache_control]=tostring(http_cache_control()):gsub(',','') --- We need to strip out any commas that may exist in cache control header, as this is a CSV.
	end

else -- Other frames (such as continutation frames) do not contain usable field values. We will break the script if we try and process them.
	end


end

end -- end of tap_packet()
