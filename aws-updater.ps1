#requires -version 4.0 -runasadministrator

<#
    .Synopsis
    This script is used to udpate AWS software components on an EC2 instance
    .DESCRIPTION
    This script is used to udpate AWS software components on an EC2 instance
    .EXAMPLE
    .\aws-updater.ps1
    .NOTES    
    File Name  :aws-updater.ps1
    Author     : Jostein Elvaker Haande
    Email      : jostein.haande@virtualworks.com
    Requires   : PowerShell Version 4.0 and RunAsAdministrator
#>

<# REVISION HISTORY
    Version: 0.1
    Date: 2021-11-30
#>

#region functions
function Start-FileTransfer {
    [CmdletBinding()]

    param (
        # Parameter help description
        [Parameter(Mandatory = $true)]
        [string]
        $url,

        # Parameter help description
        [Parameter(Mandatory = $true)]
        [string]
        $destination
    )

    if ($PSVersionTable.PSVersion.Major -ge 5) {
        try {
            Write-Debug "PS 5 available, using BitsTransfer"
            Start-BitsTransfer -source $url -Destination $destination
        }
        catch {
            Write-Debug "Not running on recent PS, falling back to Invoke-WebRequest"
            Write-Host "An error occurred connecting to SharePoint Online"
            Write-Host $_.ScriptStackTrace
            exit 1
        }
    }
    else {
        try {
            Invoke-WebRequest -Uri $url -OutFile $destination -UseBasicParsing
        }
        catch {
            Write-Host "An error occurred connecting to SharePoint Online"
            Write-Host $_.ScriptStackTrace
            exit 1
        }
    }
}
#endregion


#region script
$awsTempPath = "$env:USERPROFILE\Desktop\awsTemp"

$installedApps = Get-WmiObject -Class Win32_Product | Select-Object Name, Version
$installedDrivers = Get-WmiObject Win32_PnPSignedDriver | Select-Object DeviceName, Manufacturer, DriverVersion

[System.Version]$cfnVersion = $installedApps | Where-Object { $_.Name -like 'aws-cfn-bootstrap' } | Select-Object -ExpandProperty Version
[System.Version]$cfnVersionLatest = $(Invoke-WebRequest -Uri https://raw.githubusercontent.com/tolecnal/aws-updater/main/cfn.txt -UseBasicParsing).Content
[string]$cfnURL = "https://s3.amazonaws.com/cloudformation-examples/aws-cfn-bootstrap-py3-win64-latest.exe"

[System.Version]$ec2launchVersion = $installedApps | Where-Object { $_.Name -like 'Amazon EC2Launch' } | Select-Object -ExpandProperty Version
[System.Version]$ec2launchVersionLatest = $(Invoke-WebRequest -Uri https://raw.githubusercontent.com/tolecnal/aws-updater/main/ec2launch.txt -UseBasicParsing).Content
[string]$ec2launchUrl = "https://s3.amazonaws.com/amazon-ec2launch-v2/windows/amd64/latest/AmazonEC2Launch.msi"

[System.Version]$enaVersion = $installedDrivers | Where-Object { $_.DeviceName -like 'Amazon Elastic Network Adapter' } | Select-Object -ExpandProperty DriverVersion -First 1
[System.Version]$enaVersionLatest = $(Invoke-WebRequest -Uri https://raw.githubusercontent.com/tolecnal/aws-updater/main/ena.txt -UseBasicParsing).Content
[string]$enaUrl = "https://s3.amazonaws.com/ec2-windows-drivers-downloads/ENA/Latest/AwsEnaNetworkDriver.zip"

[System.Version]$nvmeVersion = $installedDrivers | Where-Object { $_.DeviceName -like 'AWS NVMe Elastic Block Storage Adapter' } | Select-Object -ExpandProperty DriverVersion -First 1
[System.Version]$nvmeVersionLatest = $(Invoke-WebRequest -Uri https://raw.githubusercontent.com/tolecnal/aws-updater/main/nvme.txt -UseBasicParsing).Content
[string]$nvmwUrl = "https://s3.amazonaws.com/ec2-windows-drivers-downloads/NVMe/Latest/AWSNVMe.zip"

[System.Version]$stanvmeVersion = $installedDrivers | Where-Object { $_.DeviceName -like 'Standard NVM Express Controller' } | Select-Object -ExpandProperty DriverVersion -First 1
if ($nvmeVersion -eq $null -and $stanvmeVersion) {
    $nvmeVersion = "0.0.0.0"
}

[System.Version]$pvVersion = $installedApps | Where-Object { $_.Name -like 'AWS PV Drivers' } | Select-Object -ExpandProperty Version
[System.Version]$pvVersionLatest = $(Invoke-WebRequest -Uri https://raw.githubusercontent.com/tolecnal/aws-updater/main/pv.txt -UseBasicParsing).Content
[string]$pvUrl = "https://s3.amazonaws.com/ec2-windows-drivers-downloads/AWSPV/Latest/AWSPVDriver.zip"

[System.Version]$ssmVersion = $installedApps | Where-Object { $_.Name -like 'Amazon SSM Agent' } | Select-Object -ExpandProperty Version
[System.Version]$ssmVersionLatest = $(Invoke-WebRequest -Uri https://raw.githubusercontent.com/tolecnal/aws-updater/main/ssm.txt -UseBasicParsing).Content
[string]$ssmUrl = "https://s3.amazonaws.com/ec2-downloads-windows/SSMAgent/latest/windows_amd64/AmazonSSMAgentSetup.exe"

$tabName = "Amazon AWS installed components"
$table = New-Object system.Data.DataTable $tabName

$col1 = New-Object system.Data.DataColumn Name, ([string])
$col2 = New-Object system.Data.DataColumn instVersion, ([string])
$col3 = New-Object system.Data.DataColumn offVersion, ([string])
$table.columns.add($col1)
$table.columns.add($col2)
$table.columns.add($col3)

$row = $table.NewRow()
$row.Name = "aws-cfn-bootstrap"
$row.instVersion = $cfnVersion
$row.offVersion = $cfnVersionLatest
$table.Rows.Add($row)

$row = $table.NewRow()
$row.Name = "Amazon EC2Launch"
$row.instVersion = $ec2launchVersion
$row.offVersion = $ec2launchVersionLatest
$table.Rows.Add($row)

$row = $table.NewRow()
$row.Name = "Amazon Elastic Network Adapter"
$row.instVersion = $enaVersion
$row.offVersion = $enaVersionLatest
$table.Rows.Add($row)

$row = $table.NewRow()
$row.Name = "AWS NVMe Elastic Block Storage Adapter"
$row.instVersion = $nvmeVersion
$row.offVersion = $nvmeVersionLatest
$table.Rows.Add($row)

$row = $table.NewRow()
$row.Name = "AWS PV Drivers"
$row.instVersion = $pvVersion
$row.offVersion = $pvVersionLatest
$table.Rows.Add($row)

$row = $table.NewRow()
$row.Name = "Amazon SSM Agent"
$row.instVersion = $ssmVersion
$row.offVersion = $ssmVersionLatest
$table.Rows.Add($row)

$table | Format-Table

mkdir $awsTempPath -Force

Write-Host -ForegroundColor Green  "Checking aws-cfn-bootstrap"
if ($cfnVersion -lt $cfnVersionLatest) {
    $sb = Start-Job -ScriptBlock {
        Write-Host "Installation outdated, upgrading..."

        $cfnTempPath = "$awsTempPath\aws-cfn-bootstrap-py3-win64-latest.exe"
        Start-FileTransfer -url $cfnURL -destination $cfnTempPath

        Invoke-Item $cfnTempPath
    }
    Wait-Job $sb.Name
    Write-Output "Job aws-cfn-bootstrap complete"
}
else {
    Write-Host "Installation up to date, doing nothing"
}
Write-Host " "

Write-Host -ForegroundColor Green "Checking Amazon EC2Launch"
if ($ec2launchVersion -lt $ec2launchVersionLatest) {
    $sb = Start-Job -ScriptBlock {
        Write-Host "Installation outdated, upgrading..."

        $ec2launchTempPath = "$awsTempPath\AmazonEC2Launch.msi"
        Start-FileTransfer -url $ec2launchUrl -destination $ec2launchTempPath

        try {
            msiexec /i "$ec2launchTempPath"
        }
        catch {
            Write-Host "An error running msiexec for ec2Launch"
            Write-Host $_.ScriptStackTrace
        }
    }
    Wait-Job $sb.Name
    Write-Output "Job EC2Launch complete"
}
else {
    Write-Host "Installation up to date, doing nothing"
}
Write-Host " "

Write-Host -ForegroundColor Green "Amazon Elastic Network Adapter"
if ($enaVersion -lt $enaVersionLatest) {
    $sb = Start-Job -ScriptBlock {
        Write-Host "Installation outdated, upgrading..."

        $enaTempPath = "$awsTempPath\AwsEnaNetworkDriver.zip"
        Start-FileTransfer -url $enaUrl -destination $enaTempPath

        Expand-Archive -Path $enaTempPath -DestinationPath "$awsTempPath\ena"
        & "$awsTempPath\ena\install.ps1"
    }
    Wait-Job $sb.Name
    Write-Host "Job ENA driver complete"
}
else {
    Write-Host "Installation up to date, doing nothing"
}
Write-Host " "

Write-Host -ForegroundColor Green "AWS NVMe Elastic Block Storage Adapter"
if ($nvmeVersion -lt $nvmeVersionLatest) {
    $sb = Start-Job -ScriptBlock {
        Write-Host "Installation outdated, upgrading..."

        $nvmeTempPath = "$awsTempPath\AWSNVMe.zip"
        Start-FileTransfer -url $nvmwUrl -destination $nvmeTempPath

        Expand-Archive -Path $nvmeTempPath -DestinationPath "$awsTempPath\nvme"
        & "$awsTempPath\nvme\install.ps1"
    }
    Wait-Job $sb.Name
    Write-Host "Job NVMe Driver complete"
}
else {
    Write-Host "Installation up to date, doing nothing"
}
Write-Host " "

Write-Host -ForegroundColor Green "AWS PV Drivers"
if ($pvVersion -lt $pvVersionLatest) {
    $sb = Start-Job -ScriptBlock {
        Write-Host "Installation outdated, upgrading..."

        $pvTempPath = "$awsTempPath\AWSPVDriver.zip"
        Start-FileTransfer -url $pvUrl -destination $pvTempPath

        Expand-Archive -Path $pvTempPath -DestinationPath "$awsTempPath\AWSPVDriver"
        msiexec /i "$awsTempPath\AWSPVDriver\install.ps1"
    }
    Wait-Job $sb.Name
    Write-Host "Job PV Driver complete"
}
else {
    Write-Host "Installation up to date, doing nothing"
}
Write-Host " "

Write-Host -ForegroundColor Green "Amazon SSM Agent"
if ($ssmVersion -lt $ssmVersionLatest) {
    $sb = Start-Job -ScriptBlock {
        Write-Host "Installation outdated, upgrading..."

        $ssmTempPath = "$awsTempPath\AmazonSSMAgentSetup.exe"
        Start-FileTransfer -url $ssmUrl -destination $ssmTempPath

        Start-Process -FilePath $ssmTempPath -ArgumentList "/S"
    }
    Wait-Job $sb.Name
    Write-Host "Job SSM Agent complete"
}
else {
    Write-Host "Installation up to date, doing nothing"
}
Write-Host " "

Write-Host "Cleaning up temporary files"
Remove-Item $awsTempPath -Recurse

Write-Host -ForegroundColor Green "AWS update complete"
#endregion
