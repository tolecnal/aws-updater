#requires -version 4.0 -runasadministrator

# fix for TLS issue
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072

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
    Email      : jostein.haande@ayfie.com
    Requires   : PowerShell Version 4.0 and RunAsAdministrator
#>

<# REVISION HISTORY
    Version: 0.1
    Date: 2021-11-30

    Version: 0.2
    Date: 2021-11-30
    Fixes: minor bug fixes and added capbability to write to the EventLog
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
            # ps 5.0 is available
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
            # seems like we are using PS 4.0
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

# First we set some internal variables
$awsUpdateName = "AWS component updater"
$awsTempPath = "$env:USERPROFILE\Desktop\awsTemp"

# Then we get all installed applications and drivers
$installedApps = Get-WmiObject -Class Win32_Product | Select-Object Name, Version
$installedDrivers = Get-WmiObject Win32_PnPSignedDriver | Select-Object DeviceName, Manufacturer, DriverVersion

# Then we download the most recent version number from GitHub
# And compoare these with the versions installed
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

# In some cases the latest NVMe driver is not installed
# And instead the default NVMe driver is used, if this is the case
# then we set the version number to 0.0.0.0 to install the driver
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

# Then we create the table object used to display the
# installed versions with their most recent ones
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

# Display the tables
$table | Format-Table

# Ensure logging source for Event Log exists
New-EventLog -LogName Setup -Source "AWS component updater" -ErrorAction SilentlyContinue

# Check if we are running on a Domain Controller
$osInfo = Get-CimInstance -ClassName Win32_OperatingSystem
if ($osInfo.ProductType -eq 2) {
    Write-Warning "This machine is running as a Domain Controller!"
    Write-Warning "Running this script is done solely at your own risk."
    Write-Warning "To be able to update the PV drivers you will need this registry key"
    Write-Warning "reg add HKLM\SOFTWARE\Wow6432Node\Amazon\AWSPVDriverSetup /v DisableDCCheck /t REG_SZ /d true"
}

# Write a general warning to users of the script
Write-Warning "This is your last chance to discontinue the script!"
Write-Warning "The script MIGHT break your server instance - beware!"
Write-Warning "Use the script at your own risk!"

# Ask for confirmation before actually running the script
$caption = "Please Confirm"    
$message = "Are you Sure You Want To Proceed:"
[int]$defaultChoice = 0
$yes = New-Object System.Management.Automation.Host.ChoiceDescription "&Yes", "Do the job."
$no = New-Object System.Management.Automation.Host.ChoiceDescription "&No", "Do not do the job."
$options = [System.Management.Automation.Host.ChoiceDescription[]]($yes, $no)
$choiceRTN = $host.ui.PromptForChoice($caption, $message, $options, $defaultChoice)

if ( $choiceRTN -ne 1 ) {

    # Make temp folder for downloads
    mkdir $awsTempPath -Force -ErrorAction SilentlyContinue | Out-Null

    # aws-cfn-bootstrap code
    Write-Host -ForegroundColor Green  "Checking aws-cfn-bootstrap"
    if ($cfnVersion -lt $cfnVersionLatest) {
        Write-Host "Installation outdated, upgrading..."
        Write-Host "... first uninstalling current version"

        $app = Get-WmiObject -Class Win32_Product -Filter "Name = 'aws-cfn-bootstrap'"
        Start-Sleep 10
        if ($app) {
            try {
                $app.Uninstall() | Out-Null
                Start-Sleep 45
            }
            catch {
                Write-Host "An error occured during uninstall of aws-cfn-bootstrap"
                Write-Host $_.ScriptStackTrace
            }
        }

        $cfnTempPath = "$awsTempPath\aws-cfn-bootstrap-py3-win64-latest.exe"
        Start-FileTransfer -url $cfnURL -destination $cfnTempPath | Out-Null
        Unblock-File -Path $cfnTempPath

        Invoke-Item $cfnTempPath | Out-Null
    
        Write-EventLog -LogName "Setup" -Source $awsUpdateName -EventId 2 -Category 1 -EntryType Information -Message "aws-cfn-bootstrap upgraded from $cfnVersion to $cfnVersionLatest"
        Write-Output "Job aws-cfn-bootstrap complete"
    }
    else {
        Write-Host "Installation up to date, doing nothing"
    }
    Write-Host " "

    # ec2launch code
    Write-Host -ForegroundColor Green "Checking Amazon EC2Launch"
    if ($ec2launchVersion -lt $ec2launchVersionLatest) {
        Write-Host "Installation outdated, upgrading..."

        $app = Get-WmiObject -Class Win32_Product -Filter "Name = 'EC2ConfigService'"
        Start-Sleep 10
        if ($app) {
            try {
                Write-Host "... uninstalling deprecated EC2ConfigService"
                $app.Uninstall() | Out-Null
                Start-Sleep 20
            }
            catch {
                Write-Host "An error occured during uninstall of EC2ConfigService"
                Write-Host $_.ScriptStackTrace
            }
        }

        $ec2launchTempPath = "$awsTempPath\AmazonEC2Launch.msi"
        Start-FileTransfer -url $ec2launchUrl -destination $ec2launchTempPath | Out-Null
        Unblock-File -Path $ec2launchTempPath

        try {
            msiexec /i "$ec2launchTempPath" | Out-Null
        }
        catch {
            Write-Host "An error running msiexec for ec2Launch"
            Write-Host $_.ScriptStackTrace
        }
        Write-EventLog -LogName "Setup" -Source $awsUpdateName -EventId 2 -Category 1 -EntryType Information -Message "EC2Launch upgraded from $ec2launchVersion to $ec2launchVersionLatest"
        Write-Output "Job EC2Launch complete"
    }
    else {
        Write-Host "Installation up to date, doing nothing"
    }
    Write-Host " "

    # ENA driver code
    Write-Host -ForegroundColor Green "Amazon Elastic Network Adapter"
    if ($enaVersion -lt $enaVersionLatest) {

        Write-Host "Installation outdated, upgrading..."

        $enaTempPath = "$awsTempPath\AwsEnaNetworkDriver.zip"
        Start-FileTransfer -url $enaUrl -destination $enaTempPath | Out-Null
        Unblock-File $enaTempPath
 
        if ($PSVersionTable.PSVersion.Major -eq 4) {
            try {
                Add-Type -assembly "system.io.compression.filesystem"
                [io.compression.zipfile]::ExtractToDirectory($enaTempPath, "$awsTempPath\ena")
            }
            catch {
                Write-Host "An error occured during extraction of the ENA drivers"
                Write-Host $_.ScriptStackTrace
            }
        }
        else {
            Expand-Archive -Path $enaTempPath -DestinationPath "$awsTempPath\ena" | Out-Null
        }
        
        & "$awsTempPath\ena\install.ps1" | Out-Null

        Write-EventLog -LogName "Setup" -Source $awsUpdateName -EventId 2 -Category 1 -EntryType Information -Message "ENA driver upgraded from $enaVersion to $enaVersionLatest"
        Write-Host "Job ENA driver complete"
    }
    else {
        Write-Host "Installation up to date, doing nothing"
    }
    Write-Host " "

    # NVMe driver code
    Write-Host -ForegroundColor Green "AWS NVMe Elastic Block Storage Adapter"
    if ($nvmeVersion -lt $nvmeVersionLatest) {
        Write-Host "Installation outdated, upgrading..."

        $nvmeTempPath = "$awsTempPath\AWSNVMe.zip"
        Start-FileTransfer -url $nvmwUrl -destination $nvmeTempPath | Out-Null
        Unblock-File -Path $nvmeTempPath

        if ($PSVersionTable.PSVersion.Major -eq 4) {
            try {
                Add-Type -assembly "system.io.compression.filesystem"
                [io.compression.zipfile]::ExtractToDirectory($nvmeTempPath, "$awsTempPath\nvme")
            }
            catch {
                Write-Host "An error occured during extraction of the NVMe drivers"
                Write-Host $_.ScriptStackTrace
            }
        }
        else {
            Expand-Archive -Path $nvmeTempPath -DestinationPath "$awsTempPath\nvme" | Out-Null
        }

        & "$awsTempPath\nvme\install.ps1" | Out-Null

        Write-EventLog -LogName "Setup" -Source $awsUpdateName -EventId 2 -Category 1 -EntryType Information -Message "NVMe driver upgraded from $nvmeVersion to $enaVersionLatest"
        Write-Host "Job NVMe Driver complete"
    }
    else {
        Write-Host "Installation up to date, doing nothing"
    }
    Write-Host " "

    # PV Driver code
    Write-Host -ForegroundColor Green "AWS PV Drivers"
    if ($pvVersion -lt $pvVersionLatest) {
        Write-Host "Installation outdated, upgrading..."

        $pvTempPath = "$awsTempPath\AWSPVDriver.zip"
        Start-FileTransfer -url $pvUrl -destination $pvTempPath | Out-Null
        Unblock-File $pvTempPath

        Expand-Archive -Path $pvTempPath -DestinationPath "$awsTempPath\AWSPVDriver" | Out-Null
        msiexec /i "$awsTempPath\AWSPVDriver\install.ps1" | Out-Null
 
        Write-EventLog -LogName "Setup" -Source $awsUpdateName -EventId 2 -Category 1 -EntryType Information -Message "PV driver upgraded from $pvVersion to $pvVersionLatest"
        Write-Host "Job PV Driver complete"
    }
    else {
        Write-Host "Installation up to date, doing nothing"
    }
    Write-Host " "

    # SSM agent code
    Write-Host -ForegroundColor Green "Amazon SSM Agent"
    if ($ssmVersion -lt $ssmVersionLatest) {
        Write-Host "Installation outdated, upgrading..."

        $ssmTempPath = "$awsTempPath\AmazonSSMAgentSetup.exe"
        Start-FileTransfer -url $ssmUrl -destination $ssmTempPath | Out-Null
        Unblock-File -Path $ssmTempPath

        Start-Process -FilePath $ssmTempPath -ArgumentList "/S" | Out-Null

        Write-EventLog -LogName "Setup" -Source $awsUpdateName -EventId 2 -Category 1 -EntryType Information -Message "SSM agent upgraded from $ssmVersion to $ssmVersionLatest"
        Write-Host "Job SSM Agent complete"
    }
    else {
        Write-Host "Installation up to date, doing nothing"
    }
    Write-Host " "

    # clean up temp folder
    Write-Host "Cleaning up temporary files"
    Remove-Item $awsTempPath -Recurse -Force -ErrorAction SilentlyContinue | Out-Null

    Write-Host -ForegroundColor Green "AWS update complete"
}
else {
    Write-Warning "Script aborted due to user input"
}
#endregion
