try {
  $r = Invoke-WebRequest -UseBasicParsing -Method Post -Uri "https://agentgate-broker.onrender.com/mcp" `
    -Headers @{ Authorization = "Bearer $token"; Accept = "application/json, text/event-stream" } `
    -ContentType "application/json" -Body $body
  "STATUS: $($r.StatusCode)"
  $r.Content
} catch {
  "STATUS: $([int]$_.Exception.Response.StatusCode)"
  $sr = New-Object System.IO.StreamReader($_.Exception.Response.GetResponseStream())
  $sr.ReadToEnd()
}

