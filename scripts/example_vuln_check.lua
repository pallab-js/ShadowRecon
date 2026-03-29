-- ShadowRecon Example Lua Script
-- Matches the new Lua 5.4 High-Performance Engine

-- The script environment provides:
-- host: { ip = "...", hostname = "..." }
-- port: { number = 80, protocol = "tcp" } (if applicable)
-- shadow: { tcp_connect(ip, port), http_get(url) }

local function check_vulnerability()
    local ip = host.ip
    local port_num = port.number
    
    -- Example: Simple HTTP banner check
    if port_num == 80 or port_num == 443 then
        local protocol = (port_num == 443) and "https" or "http"
        local url = string.format("%s://%s:%d/", protocol, ip, port_num)
        
        local status, body = shadow.http_get(url)
        
        if status == 200 then
            if string.find(body, "admin") then
                return {
                    output = "Found potential admin panel in body",
                    vulnerability = "POTENTIAL-ADMIN-PANEL"
                }
            end
        end
    end
    
    -- Example: TCP raw probe
    local sock = shadow.tcp_connect(ip, port_num)
    if sock then
        sock:send("HEAD / HTTP/1.0\r\n\r\n")
        local response = sock:receive(1024)
        sock:close()
        
        if string.find(response, "Server:") then
            return {
                output = "Server header found via raw socket",
                banner = response
            }
        end
    end

    return "No specific vulnerability found"
end

-- Return the result
return check_vulnerability()
