-- Example Lua script for custom vulnerability scanning
-- This script demonstrates how to create custom checks for RustScan

script_metadata = {
    id = "example-vuln-check",
    name = "Example Vulnerability Check",
    description = "An example script that demonstrates custom vulnerability detection",
    type = "service", -- "port", "host", or "service"
    target_ports = {80, 443, 8080, 8443}, -- ports this script applies to
    target_services = {"http", "https"}, -- services this script applies to
}

-- Helper function to make HTTP requests
function make_http_request(ip, port, path)
    -- In a real implementation, this would make actual HTTP requests
    -- For this example, we'll simulate a response
    return {
        status = 200,
        headers = {
            ["server"] = "Example-Server/1.0",
            ["x-powered-by"] = "Example-Framework"
        },
        body = "<html><body>Example website</body></html>"
    }
end

-- The execute function is called for each applicable target
function execute()
    local results = {}

    if target.type == "service" then
        print("Running custom vulnerability check on " .. target.ip .. ":" .. target.port)

        -- Simulate an HTTP request to check for vulnerabilities
        local response = make_http_request(target.ip, target.port, "/")

        -- Example vulnerability checks
        local vulnerabilities = {}

        -- Check for outdated server software
        if response.headers["server"] and string.find(response.headers["server"], "Example%-Server/1%.0") then
            table.insert(vulnerabilities, {
                id = "EXAMPLE-OUTDATED-SERVER",
                title = "Outdated Server Software",
                description = "The server is running outdated software that may have known vulnerabilities",
                severity = "medium",
                cve = nil,
                cvss_score = 6.5,
                references = {"https://example.com/security-advisory"}
            })
        end

        -- Check for information disclosure
        if response.headers["x-powered-by"] then
            table.insert(vulnerabilities, {
                id = "EXAMPLE-INFO-DISCLOSURE",
                title = "Information Disclosure",
                description = "Server is leaking technology information via X-Powered-By header",
                severity = "low",
                cve = nil,
                cvss_score = 2.5,
                references = {"https://owasp.org/www-project-top-ten/"}
            })
        end

        -- Prepare the result
        local output
        if #vulnerabilities > 0 then
            output = string.format("Found %d vulnerabilities on %s:%d", #vulnerabilities, target.ip, target.port)
        else
            output = string.format("No vulnerabilities found on %s:%d", target.ip, target.port)
        end

        results[1] = {
            script_id = "example-vuln-check",
            output = output,
            elements = {
                checked_url = string.format("http://%s:%d/", target.ip, target.port),
                response_status = response.status,
                server_header = response.headers["server"] or "unknown"
            },
            vulnerabilities = #vulnerabilities > 0 and vulnerabilities or nil
        }
    end

    return results
end