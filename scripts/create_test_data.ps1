Param(
    [string]$BaseDir = (Join-Path (Get-Location) "test_data")
)

New-Item -ItemType Directory -Path $BaseDir -Force | Out-Null

# EICAR test (safe test string)
$eicar = 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'
Set-Content -Path (Join-Path $BaseDir 'eicar.com') -Value $eicar -NoNewline -Encoding ASCII

# small wordlist
"password" | Out-File -FilePath (Join-Path $BaseDir 'wordlist.txt') -Encoding ASCII
Add-Content -Path (Join-Path $BaseDir 'wordlist.txt') -Value "123456"

# random.bin (10 KiB)
$bytes = New-Object byte[] 10240
[System.Random]::new().NextBytes($bytes)
[System.IO.File]::WriteAllBytes((Join-Path $BaseDir 'random.bin'), $bytes)

# copy of notepad (if exists) into test_data as sample (non-destructive)
$notepad = "$env:windir\System32\notepad.exe"
if (Test-Path $notepad) {
    Copy-Item -Path $notepad -Destination (Join-Path $BaseDir 'notepad_sample.exe') -Force
} else {
    # create tiny fake binary placeholder
    Set-Content -Path (Join-Path $BaseDir 'notepad_sample.exe') -Value "MZ" -Encoding ASCII
}

Write-Host "Test data created in: $BaseDir"
Get-ChildItem $BaseDir | Format-Table Name,Length,LastWriteTime
