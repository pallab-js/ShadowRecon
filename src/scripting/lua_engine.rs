use mlua::{Lua, Value};
use std::path::Path;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;
use crate::types::{HostInfo, PortInfo, ScriptResult};

pub struct LuaScriptEngine {
    // Lua is !Send, so we create a new state per script execution or use a pool.
    // For simplicity and safety in a multi-threaded scanner, we'll create a new state per run.
}

impl LuaScriptEngine {
    pub fn new() -> anyhow::Result<Self> {
        Ok(Self {})
    }

    fn setup_lua_env(&self, lua: &Lua, host: &HostInfo, port: Option<&PortInfo>) -> anyhow::Result<()> {
        let globals = lua.globals();

        // Host table
        let host_table = lua.create_table()?;
        host_table.set("ip", host.ip.to_string())?;
        host_table.set("hostname", host.hostname.clone().unwrap_or_default())?;
        globals.set("host", host_table)?;

        // Port table
        if let Some(p) = port {
            let port_table = lua.create_table()?;
            port_table.set("number", p.port)?;
            port_table.set("protocol", p.protocol.clone())?;
            globals.set("port", port_table)?;
        }

        // Network API
        let net = lua.create_table()?;
        
        // TCP Connect
        let tcp_connect = lua.create_function(|_, (addr, port): (String, u16)| {
            let socket_addr = format!("{}:{}", addr, port);
            match TcpStream::connect_timeout(&socket_addr.parse().unwrap(), Duration::from_secs(5)) {
                Ok(stream) => {
                    stream.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
                    stream.set_write_timeout(Some(Duration::from_secs(5))).unwrap();
                    Ok(LuaSocket { stream: Some(stream) })
                }
                Err(e) => Err(mlua::Error::external(e)),
            }
        })?;
        net.set("tcp_connect", tcp_connect)?;

        // HTTP GET
        let http_get = lua.create_function(|_, url: String| {
            let client = reqwest::blocking::Client::builder()
                .danger_accept_invalid_certs(true)
                .timeout(Duration::from_secs(10))
                .build()
                .map_err(mlua::Error::external)?;
            
            let resp = client.get(url).send().map_err(mlua::Error::external)?;
            let status = resp.status().as_u16();
            let body = resp.text().map_err(mlua::Error::external)?;
            
            Ok((status, body))
        })?;
        net.set("http_get", http_get)?;

        globals.set("shadow", net)?;

        Ok(())
    }

    pub async fn run_script<P: AsRef<Path>>(
        &self,
        script_id: &str,
        path: P,
        host: &HostInfo,
        port: Option<&PortInfo>,
    ) -> anyhow::Result<Vec<ScriptResult>> {
        let script_content = std::fs::read_to_string(path)?;
        let lua = Lua::new();
        
        self.setup_lua_env(&lua, host, port)?;

        // The script should return a table of results or a single string
        let result: Value = lua.load(&script_content).eval()?;
        
        let mut script_results = Vec::new();
        
        match result {
            Value::String(s) => {
                script_results.push(ScriptResult {
                    script_id: script_id.to_string(),
                    output: s.to_str()?.to_string(),
                    elements: std::collections::HashMap::new(),
                    vulnerabilities: None,
                });
            }
            Value::Table(t) => {
                let output: String = t.get("output").unwrap_or_else(|_| "No output".to_string());
                script_results.push(ScriptResult {
                    script_id: script_id.to_string(),
                    output,
                    elements: std::collections::HashMap::new(),
                    vulnerabilities: None,
                });
            }
            _ => {}
        }

        Ok(script_results)
    }
}

struct LuaSocket {
    stream: Option<TcpStream>,
}

impl mlua::UserData for LuaSocket {
    fn add_methods<'lua, M: mlua::UserDataMethods<'lua, Self>>(methods: &mut M) {
        methods.add_method_mut("send", |_, this, data: String| {
            if let Some(ref mut s) = this.stream {
                s.write_all(data.as_bytes()).map_err(mlua::Error::external)?;
                Ok(())
            } else {
                Err(mlua::Error::external("Socket closed"))
            }
        });

        methods.add_method_mut("receive", |_, this, len: usize| {
            if let Some(ref mut s) = this.stream {
                let mut buf = vec![0u8; len];
                let n = s.read(&mut buf).map_err(mlua::Error::external)?;
                Ok(String::from_utf8_lossy(&buf[..n]).to_string())
            } else {
                Err(mlua::Error::external("Socket closed"))
            }
        });

        methods.add_method_mut("close", |_, this, ()| {
            this.stream = None;
            Ok(())
        });
    }
}
