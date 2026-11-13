# Deploys the spiritexe.pages.dev front (pages/dist) with Wrangler, reusing the cf CLI's
# sign-in so no separate Wrangler login is needed. Run after `cf deploy` when public/ changed:
#   powershell -ExecutionPolicy Bypass -File scripts\deploy-pages.ps1
$ErrorActionPreference = 'Stop'
Set-Location (Join-Path $PSScriptRoot '..')

node scripts/build-pages.mjs

$cfg = Get-Content (Join-Path $env:APPDATA 'xdg.config\cloudflare\config\default.json') -Raw | ConvertFrom-Json
$token = $null
foreach ($name in 'oauth_token', 'access_token', 'token', 'api_token') {
    if ($cfg.$name) { $token = $cfg.$name; break }
}
if (-not $token) {
    foreach ($p in $cfg.PSObject.Properties) {
        if ($p.Value -is [pscustomobject] -and $p.Value.access_token) { $token = $p.Value.access_token; break }
    }
}
if (-not $token) {
    Write-Host 'Could not find the cf sign-in. Fields in the file:' ($cfg.PSObject.Properties.Name -join ', ')
    exit 1
}

$headers = @{ Authorization = "Bearer $token" }
$accounts = Invoke-RestMethod -Uri 'https://api.cloudflare.com/client/v4/accounts' -Headers $headers
$env:CLOUDFLARE_ACCOUNT_ID = $accounts.result[0].id
$env:CLOUDFLARE_API_TOKEN = $token

npx --yes wrangler@4 pages deploy pages/dist --project-name spiritexe --branch main --commit-dirty=true
