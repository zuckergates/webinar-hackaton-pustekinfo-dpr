param([ValidateSet('Start','Test','Attacks','Stop','Status')][string]$Action='Start')
$ErrorActionPreference='Stop'
Push-Location -LiteralPath $PSScriptRoot
try {
# Avoid taking over a lab that belongs to a different folder.
$projectsJson = & docker compose ls --all --format json
if ($LASTEXITCODE -ne 0) { throw 'Docker tidak tersedia. Buka Docker Desktop terlebih dahulu.' }
$localConfig = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot 'compose.yaml'))
foreach ($project in ($projectsJson | ConvertFrom-Json)) {
 if ($project.Name -eq 'webinar-invoice-lab') {
  $configs = @($project.ConfigFiles -split ',')
  if ($configs.Count -ne 1 -or [IO.Path]::GetFullPath($configs[0]) -ne $localConfig) {
   throw 'Lab dengan nama yang sama berasal dari folder lain. Kelola salinan lama dari folder asalnya sebelum menggunakan salinan ini. Tidak ada container yang diubah.'
  }
 }
}
function Run-Compose { $composeArguments=$args; & docker compose --project-name webinar-invoice-lab --file $localConfig @composeArguments; if($LASTEXITCODE -ne 0){throw "Docker Compose failed: $($composeArguments -join ' ')"} }
switch($Action){
 'Attacks' {
   $attackRunId=[guid]::NewGuid().ToString()
   Run-Compose @('--profile','tools','run','--rm','tester','python','tests/attacks.py','--run-id',$attackRunId)
   Run-Compose @('--profile','tools','run','--rm','-e',"ATTACK_RUN_ID=$attackRunId",'untrusted')
   Run-Compose @('--profile','tools','run','--rm','tester','python','tests/attacks.py','--report','--run-id',$attackRunId)
 }
 'Start' {
   New-Item -ItemType Directory -Path runtime,evidence -Force | Out-Null
   Run-Compose @('--profile','tools','build','setup','db')
   Run-Compose @('--profile','tools','run','--rm','--no-deps','setup')
   Run-Compose @('up','-d','--wait','db','vulnerable','query-fixed','hardened')
   Write-Host 'Vulnerable http://localhost:8081 | Query-fixed http://localhost:8082 | Hardened http://localhost:8083'
 }
 'Test' {
   Run-Compose @('--profile','tools','run','--rm','tester')
   Run-Compose @('--profile','tools','run','--rm','untrusted')
   Run-Compose @('exec','-T','db','bash','/lab-scripts/backup_restore.sh')
   Run-Compose @('--profile','tools','run','--rm','tester','python','tests/restore_app.py')
 }
 'Stop' {Run-Compose @('stop')}
 'Status' {Run-Compose @('ps')}
}
} finally {
 Pop-Location
}
