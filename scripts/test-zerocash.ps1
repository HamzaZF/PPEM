# test-zerocash.ps1

# 1. Start Bob's server as a background job
$bobPort = 8081
$bobOut = "bob-out.log"
$bobErr = "bob-err.log"
$bobJob = Start-Job -ScriptBlock {
    & ./main.exe -name=Bob -port=8081 *> $using:bobOut 2> $using:bobErr
}

Write-Host "Started Bob as background job (ID $($bobJob.Id)) on port $bobPort..."

# 2. Wait for Bob's server to be ready
$maxTries = 20
$ready = $false
for ($i = 0; $i -lt $maxTries; $i++) {
    try {
        $resp = Invoke-WebRequest -Uri "http://localhost:$bobPort/pubkey" -TimeoutSec 1
        if ($resp.StatusCode -eq 200) {
            $ready = $true
            break
        }
    } catch {}
    Start-Sleep -Seconds 1
}
if (-not $ready) {
    Write-Host "Bob's server did not start in time. Exiting."
    Stop-Job -Id $bobJob.Id
    Remove-Job -Id $bobJob.Id
    exit 1
}

Write-Host "Bob is ready!"

# 3. Start Alice's server as a background job (she will send a transaction to Bob)
$alicePort = 8080
$aliceOut = "alice-out.log"
$aliceErr = "alice-err.log"
$aliceJob = Start-Job -ScriptBlock {
    & ./main.exe -name=Alice -port=8080 -peer=localhost:8081 -coins=100 -energy=50 *> $using:aliceOut 2> $using:aliceErr
}

Write-Host "Started Alice as background job (ID $($aliceJob.Id)) on port $alicePort..."

# 4. Wait for Alice to send the transaction (give her a few seconds)
Start-Sleep -Seconds 5

# 5. Optionally, stop both jobs
Stop-Job -Id $aliceJob.Id
Stop-Job -Id $bobJob.Id
Remove-Job -Id $aliceJob.Id
Remove-Job -Id $bobJob.Id

Write-Host "Test complete. See alice-out.log, alice-err.log, bob-out.log, and bob-err.log for output."
Write-Host "Bob's wallet: Bob_wallet.json"