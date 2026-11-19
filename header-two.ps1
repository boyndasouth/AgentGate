$u = "https://agentgate-broker.onrender.com/mcp"
$hd = @{ Authorization = "Bearer $token"; Accept = "application/json, text/event-stream" }
function Rpc($body, $extra) {
  Invoke-WebRequest -UseBasicParsing -Method Post -Uri $u -Headers ($hd + $extra) -ContentType "application/json" -Body $body
}
$init = Rpc '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"t","version":"1"}}}' @{}
$sid = $init.Headers["mcp-session-id"]
$h2 = @{ "mcp-session-id" = $sid; "MCP-Protocol-Version" = "2025-06-18" }
$null = Rpc '{"jsonrpc":"2.0","method":"notifications/initialized"}' $h2
$tl = Rpc '{"jsonrpc":"2.0","id":2,"method":"tools/list"}' $h2
$tl.Content