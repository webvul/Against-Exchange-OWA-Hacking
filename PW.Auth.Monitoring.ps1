
# Change along with task scheduler trigger
$MinutesToBack = 1

$Date = Get-Date
$strDate = $Date.ToString('yyyy-MM-dd')

$End_time = $Date
$Start_time = $Date.AddMinutes(-$MinutesToBack)
$LogFolder = '.\Logs'
$strLogFile = "$LogFolder\${strDate}.txt"
$strLogFile_e = "$LogFolder\${strDate}_e.txt"

Set-Content -Path $strLogFile_e -Value $null

$WhiteList = @(Get-Content -Path 'FW_WhiteList.txt' -Encoding UTF8 -ErrorAction:SilentlyContinue | ?{$_ -and $_ -imatch '^[^#]'})
$BlackList = @(Get-Content -Path 'FW_BlackList.txt' -Encoding UTF8 -ErrorAction:SilentlyContinue | ?{$_ -and $_ -imatch '^[^#]'})

# threshold for ip not matching whitelist,
# 30 means total number of auth failure in past {MinutesToBack} minutes,
# 1 means number of different accounts auth failed,
# IPs matched both rules are identified as attacking
$t_4625_fw = @(30, 1)
# threshold for whitelist ip
$t_4625_fw_Intranet = @(50, 1)
# default block time, in seconds, which is 2 years
$t_4625_fw_TimeoutDefault = 525600

$Mail_From = "$($env:COMPUTERNAME)<ITInfraAlerts@didichuxing.com>"
$Mail_To = 'someoneA@larry.song', 'someoneB@larry.song'
$Mail_Subject = 'IP attacking warning'

# smtp server to sent warning email
$Mail_SMTPServer = 'smtpserver.larry.song'

function Add-Log
{
    PARAM(
        [String]$Path,
        [String]$Value,
        [String]$Type = 'Info'
    )
    $Type = $Type.ToUpper()
    $Date = Get-Date
    Write-Host "$($Date.ToString('[HH:mm:ss] '))[$Type] $Value" -ForegroundColor $(
        switch($Type)
        {
            'WARNING' {'Yellow'}
            'Error' {'Red'}
            default {'White'}
        }
    )
    if($Path){
        Add-Content -LiteralPath $Path -Value "$($Date.ToString('[HH:mm:ss] '))[$Type] $Value" -Encoding UTF8 -ErrorAction:SilentlyContinue
    }
}

    Add-Log -Path $strLogFile_e -Value "Catch logs after : $($Start_time.ToString('HH:mm:ss'))"
    Add-Log -Path $strLogFile_e -Value "Catch logs before: $($End_time.ToString('HH:mm:ss'))"

    $4625 = @(Get-WinEvent -FilterHashtable @{LogName = 'Security'; Id = 4625; StartTime = $Start_time; EndTime = $End_time;} -ErrorAction:SilentlyContinue)
    Add-Log -Path $strLogFile_e -Value "Total 4625 logs count : [$($4625.Count)]"

    # http://schemas.microsoft.com/win/2004/08/events/event
    # index 5 = TargetUserName
    # index 6 = TargetDomainName
    # index 19 = IpAddress
    $s_4625 = @{}
    foreach($e in $4625)
    {
        $xmlData = $IP = $Account = $Domain = $null
        $xmlData = [xml]$e.ToXml()
        $IP = $(
            if($xmlData.Event.EventData.Data[19].'#text' -imatch '^\s*$')
            {
                '(NULL)'
            }
            else
            {
                $xmlData.Event.EventData.Data[19].'#text'.Trim()
            }
        )
        $Account = $(
            if($xmlData.Event.EventData.Data[5].'#text' -imatch '^\s*$')
            {
                '(NULL)'
            }
            else
            {
                $xmlData.Event.EventData.Data[5].'#text'.Trim()
            }
        )
        $Domain = $(
            if($xmlData.Event.EventData.Data[6].'#text' -imatch '^\s*$')
            {
                '(NULL)'
            }
            else
            {
                $xmlData.Event.EventData.Data[6].'#text'.Trim()
            }
        )
        if($Account -notmatch '@|\\')
        {
            $Account = "$Domain\$Account"
        }
        $s_4625.$($IP) += @($Account)
    }

    $GoBlock = @{}
    foreach($IP in $s_4625.Keys)
    {
        $t_4625_fw_Timeout = $t_4625_fw_TimeoutDefault
        $tmp = @($s_4625.$IP | Group-Object | Sort-Object Count -Descending)
        Add-Log -Path $strLogFile_e -Value "In past [${MinutesToBack}] minute [IP address][errors][account][top 5]:[$IP][$($s_4625.$IP.Count)][$($tmp.Count)][$($tmp[0..4] | %{$_.Name, $_.Count -join ':'})]"
        $tmpx = @($WhiteList | ?{$IP -imatch $_})
        if($tmpx)
        {
            Add-Log -Path $strLogFile_e -Value "[$IP] in white list, matched: [$($tmpx -join '][')]"
            if($tmpx -imatch 'supper')
            {
                Add-Log -Path $strLogFile_e -Value "[$IP] Matched as supper white list"
                continue
            }
            $tempx = $null
            $tempx = @([regex]::Matches($tmpx, 'Timeout:(\d+)') | %{[int]($_.Groups[1].Value)} | Sort-Object -Descending)[0]
            $t_4625_fw_Timeout = $tempx
            if($s_4625.$IP.Count -ge $t_4625_fw_Intranet[0] -and $tmp.Count -ge $t_4625_fw_Intranet[1])
            {
                Add-Log -Path $strLogFile_e -Value "[${IP}:$t_4625_fw_Timeout] in whitelist,but excceed threshold for whitelist, adding into firewall" -Type Warning
                $GoBlock.$IP = $t_4625_fw_Timeout
            }
        }
        else
        {
            Add-Log -Path $strLogFile_e -Value "[$IP] not in white list"
            if($s_4625.$IP.Count -ge $t_4625_fw[0] -and $tmp.Count -ge $t_4625_fw[1])
            {
                $tmp.Name | Add-Content -Path "$LogFolder\$IP.log" -Encoding UTF8
                Add-Log -Path $strLogFile_e -Value "[${IP}:$t_4625_fw_Timeout] excceed threshold" -Type Warning
                $GoBlock.$IP = $t_4625_fw_Timeout
            }
        }
    }

    $Mail = $false
    if($GoBlock)
    {
        foreach($IP in $GoBlock.Keys)
        {
            if(!(Get-NetFirewallRule -DisplayName "ScriptAuto_Block_$IP" -ErrorAction:SilentlyContinue))
            {
                $Mail = $true
                New-NetFirewallRule -DisplayName "ScriptAuto_Block_$IP" -Profile Any -Action Block -RemoteAddress $IP -Protocol Tcp -LocalPort 443 -Direction Inbound -Description $Date.AddMinutes($GoBlock.$IP).ToString('yyyy-MM-dd HH:mm:ss') -ErrorAction:SilentlyContinue
                if(!$?)
                {
                    Add-Log -Path $strLogFile_e -Value "[$IP] failed to add to firewall, cause:" -Type Error
                    Add-Log -Path $strLogFile_e -Value $Error[0] -Type Error
                }
                else
                {
                    Add-Log -Path $strLogFile_e -Value "[$IP] succeed add into firewall" -Type Warning
                }
            }
        }
    }

    Get-NetFirewallRule -DisplayName "ScriptAuto_*" | %{
        if($_.Description)
        {
            if(([datetime]($_.Description) - $Date).TotalMinutes -lt 0)
            {
                $_ | Remove-NetFirewallRule
            }
        }
        else
        {
            $_ | Remove-NetFirewallRule
        }

        $x = $_
        $WhiteList | ?{$_ -imatch 'supper'} | %{
            if($x.DisplayName -imatch $_)
            {
                $x | Remove-NetFirewallRule
            }
        }
    }

    $BlackList | %{
        if(!(Get-NetFirewallRule -DisplayName "ScriptAuto_BlackList_$_" -ErrorAction:SilentlyContinue))
        {
            New-NetFirewallRule -DisplayName "ScriptAuto_BlackList_$_" -Profile Any -Action Block -RemoteAddress $_ -Direction Inbound -Description ($Date.AddYears(100).ToString('yyyy-MM-dd HH:mm:ss')) -ErrorAction:SilentlyContinue
        }
    }

    If($Mail)
    {
        try
        {
            Send-MailMessage -From $Mail_From -To $Mail_To -Subject $Mail_Subject -SmtpServer $Mail_SMTPServer -Body ((Get-Content $strLogFile_e -Encoding Default) -join "`t`n") -Encoding utf8
        }
        catch
        {
            Add-Log -Path $strLogFile_e -Value "Failed to send mail, cause: $($Error[0])" -Type Error
        }
    }

    Get-Content -Path $strLogFile_e -Encoding UTF8 | Add-Content -Path $strLogFile -Encoding UTF8
    Add-Log -Path $strLogFile_e -Value 'Completed'
