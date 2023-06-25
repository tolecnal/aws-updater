# aws-updater.ps1

This script is used to update all installed AWS components install on an EC2 instance.

# Files

Just download the file *aws-updater.ps1*  to your desktop and run it.

## Run script

Start a PowerShell session with Administrative privileges

```
cd $ENV:USERPROFILE\Desktop
Start-BitsTransfer https://raw.githubusercontent.com/tolecnal/aws-updater/main/aws-updater.ps1
.\aws-updater.ps1
```

## Components checked

- aws-cfn-bootstrap
- EC2Launch
- Amazon Elastic Network Adapter Driver
- AWS NVMe Elastic Block Storage Adapter Driver
- AWS PV Driver
- Amazon SSM Agent
- Amazon CloudWatch Agent

## Issues running the script?

Please report the issue on the GitHub issue tracker: https://github.com/tolecnal/aws-updater/issues
