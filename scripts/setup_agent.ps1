#Requires -Version 3.0

<#
.SYNOPSIS
    Installs Elastic Agent together with Sysmon.

.DESCRIPTION
    This installs Elastic Agent and Sysmon with the provided configuration. It handles the
    complete deployment process including file verification, extraction, hosts file updates, 
    and service installation.

.PARAMETER tun0_ip
    The IP address of the server hosting the files.

.PARAMETER files
    Comma-separated list of filenames that should be present in the upload directory

.PARAMETER enrollment_token
    The enrollment token for Elastic Agent registration with Fleet server.

.PARAMETER DestinationPath
    Optional. The destination directory where files are located. Defaults to C:\Windows\Temp.

.EXAMPLE    
    # Execute the main function
    Install-ElasticAgentAndSysmon -tun0_ip "192.168.1.100"  -files "sysmonconfig-with-filedelete.xml,elastic-agent-9.0.1-windows-x86_64.zip,Sysmon.zip" -enrollment_token "ABC123..."

.EXAMPLE
    # Alternative with custom destination
    Install-ElasticAgentAndSysmon -tun0_ip "10.0.0.1" -files "config.xml,agent.zip" -enrollment_token "XYZ789..." -DestinationPath "C:\Downloads"

.NOTES
    Author:  PowerShell Script
    Version: 3.2 (File Verification)
    Purpose: Install Elastic Agent together with Sysmon
    Requires: PowerShell 3.0 or higher, Administrator privileges
    
    Usage Pattern:
    1. Ensure files are uploaded to the destination directory
    2. Execute main function: Install-ElasticAgentAndSysmon -tun0_ip "IP" -files "file1,file2" -enrollment_token "TOKEN"
    
    This script performs the following actions:
    1. Verifies required files exist in the upload directory
    2. Extracts ZIP archives (Elastic Agent and Sysmon)
    3. Updates the Windows hosts file with fleet01 entry
    4. Installs Elastic Agent with Fleet enrollment
    5. Installs or updates Sysmon with provided configuration
#>

# Global script variables
$script:InstallationStats = @{
    FilesExtracted = 0
    ServicesInstalled = 0
    Errors = @()
}

function Write-ColorOutput {
    <#
    .SYNOPSIS
        Writes colored output to the console.
    #>
    param(
        [string]$Message,
        [ValidateSet('Green', 'Red', 'Yellow', 'Cyan', 'White', 'Magenta', 'Blue')]
        [string]$Color = 'White'
    )
    
    Write-Host $Message -ForegroundColor $Color
}

function Test-AdminPrivileges {
    <#
    .SYNOPSIS
        Checks if the script is running with administrator privileges.
    #>
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Initialize-Directory {
    <#
    .SYNOPSIS
        Ensures a directory exists and is writable.
    #>
    param([string]$Path)
    
    try {
        if (-not (Test-Path -Path $Path)) {
            New-Item -ItemType Directory -Path $Path -Force | Out-Null
            Write-ColorOutput "Created directory: $Path" -Color Green
        }
        
        # Test write access
        $testFile = Join-Path $Path "write_test_$(Get-Random).tmp"
        New-Item -Path $testFile -ItemType File -Force | Out-Null
        Remove-Item -Path $testFile -Force
        
        return $true
    }
    catch {
        Write-ColorOutput "Failed to create or access directory '$Path': $($_.Exception.Message)" -Color Red
        $script:InstallationStats.Errors += "Directory access failed: $Path"
        return $false
    }
}

function Test-RequiredFiles {
    <#
    .SYNOPSIS
        Verifies that all required files exist in the upload directory.
    #>
    param(
        [string]$UploadPath,
        [string[]]$RequiredFiles
    )
    
    Write-ColorOutput "`nVerifying required files..." -Color Blue
    
    $missingFiles = @()
    $foundFiles = @()
    
    foreach ($file in $RequiredFiles) {
        $filePath = Join-Path $UploadPath $file
        if (Test-Path $filePath) {
            $fileInfo = Get-Item $filePath
            $fileSize = Get-FileSizeString -Bytes $fileInfo.Length
            Write-ColorOutput "? Found: $file ($fileSize)" -Color Green
            $foundFiles += $file
        }
        else {
            Write-ColorOutput "? Missing: $file" -Color Red
            $missingFiles += $file
        }
    }
    
    if ($missingFiles.Count -gt 0) {
        Write-ColorOutput "`nMissing files:" -Color Red
        foreach ($file in $missingFiles) {
            Write-ColorOutput "  � $file" -Color Red
        }
        
        Write-ColorOutput "`nFiles currently in upload directory:" -Color Yellow
        $existingFiles = Get-ChildItem -Path $UploadPath -File | Select-Object Name, Length
        if ($existingFiles) {
            foreach ($file in $existingFiles) {
                $size = Get-FileSizeString -Bytes $file.Length
                Write-ColorOutput "  � $($file.Name) ($size)" -Color Yellow
            }
        }
        else {
            Write-ColorOutput "  No files found in directory" -Color Yellow
        }
        
        return $false
    }
    
    Write-ColorOutput "? All required files verified successfully" -Color Green
    return $true
}

function Get-FileSizeString {
    <#
    .SYNOPSIS
        Converts bytes to human-readable string.
    #>
    param([long]$Bytes)
    
    $sizes = @('B', 'KB', 'MB', 'GB', 'TB')
    $index = 0
    $size = [double]$Bytes
    
    while ($size -ge 1024 -and $index -lt ($sizes.Count - 1)) {
        $size /= 1024
        $index++
    }
    
    return "{0:N2} {1}" -f $size, $sizes[$index]
}

function Expand-UploadedArchives {
    <#
    .SYNOPSIS
        Extracts ZIP files to their designated locations.
    #>
    param([string]$UploadPath)
    
    Write-ColorOutput "`nExtracting uploaded archives..." -Color Blue
    
    # Extract Elastic Agent
    $elasticAgentZip = Get-ChildItem -Path $UploadPath -Filter "elastic-agent-*-windows-x86_64.zip" | Select-Object -First 1
    if ($elasticAgentZip) {
        try {
            Write-ColorOutput "Extracting: $($elasticAgentZip.Name)" -Color Yellow
            Expand-Archive -Path $elasticAgentZip.FullName -DestinationPath $UploadPath -Force
            Write-ColorOutput "? Elastic Agent extracted successfully" -Color Green
            $script:InstallationStats.FilesExtracted++
        }
        catch {
            Write-ColorOutput "? Failed to extract Elastic Agent: $($_.Exception.Message)" -Color Red
            $script:InstallationStats.Errors += "Elastic Agent extraction failed: $($_.Exception.Message)"
        }
    }
    else {
        Write-ColorOutput "? Elastic Agent ZIP file not found" -Color Yellow
    }
    
    # Extract Sysmon
    $sysmonZip = Get-ChildItem -Path $UploadPath -Filter "Sysmon.zip" | Select-Object -First 1
    if ($sysmonZip) {
        try {
            Write-ColorOutput "Extracting: $($sysmonZip.Name)" -Color Yellow
            Initialize-Directory -Path "C:\Sysmon"
            Expand-Archive -Path $sysmonZip.FullName -DestinationPath "C:\Sysmon" -Force
            Write-ColorOutput "? Sysmon extracted successfully" -Color Green
            $script:InstallationStats.FilesExtracted++
        }
        catch {
            Write-ColorOutput "? Failed to extract Sysmon: $($_.Exception.Message)" -Color Red
            $script:InstallationStats.Errors += "Sysmon extraction failed: $($_.Exception.Message)"
        }
    }
    else {
        Write-ColorOutput "? Sysmon ZIP file not found" -Color Yellow
    }
}

function Update-HostsFile {
    <#
    .SYNOPSIS
        Updates the Windows hosts file with fleet01 entry.
    #>
    param([string]$IPAddress)
    
    try {
        Write-ColorOutput "`nUpdating hosts file..." -Color Blue
        $hostsPath = "C:\Windows\System32\Drivers\etc\hosts"
        $hostsEntry = "$IPAddress fleet01"
        
        # Check if entry already exists
        $existingContent = Get-Content -Path $hostsPath -ErrorAction SilentlyContinue
        if ($existingContent -notcontains $hostsEntry) {
            Add-Content -Path $hostsPath -Value $hostsEntry
            Write-ColorOutput "? Added hosts entry: $hostsEntry" -Color Green
        }
        else {
            Write-ColorOutput "? Hosts entry already exists: $hostsEntry" -Color Green
        }
    }
    catch {
        Write-ColorOutput "? Failed to update hosts file: $($_.Exception.Message)" -Color Red
        $script:InstallationStats.Errors += "Hosts file update failed: $($_.Exception.Message)"
    }
}

function Install-ElasticAgentService {
    <#
    .SYNOPSIS
        Installs and enrolls Elastic Agent with Fleet server.
    #>
    param(
        [string]$UploadPath,
        [string]$EnrollmentToken
    )
    
    try {
        Write-ColorOutput "`nInstalling Elastic Agent..." -Color Blue
        
        # Find the extracted Elastic Agent directory
        $elasticAgentDir = Get-ChildItem -Path $UploadPath -Directory -Filter "elastic-agent-*-windows-x86_64" | Select-Object -First 1
        
        if (-not $elasticAgentDir) {
            throw "Elastic Agent directory not found after extraction"
        }
        
        $elasticAgentExe = Join-Path $elasticAgentDir.FullName "elastic-agent.exe"
        
        if (-not (Test-Path $elasticAgentExe)) {
            throw "elastic-agent.exe not found in $($elasticAgentDir.FullName)"
        }
        
        Write-ColorOutput "Found Elastic Agent at: $elasticAgentExe" -Color Cyan
        
        # Build installation command
        $installArgs = @(
            "install"
            "--url=https://fleet01:8220"
            "--enrollment-token=$EnrollmentToken"
            "-inf"
        )
        
        Write-ColorOutput "Executing Elastic Agent installation..." -Color Yellow
        Write-ColorOutput "Command: $elasticAgentExe $($installArgs -join ' ')" -Color Cyan
        
        $process = Start-Process -FilePath $elasticAgentExe -ArgumentList $installArgs -Wait -PassThru -NoNewWindow
        
        if ($process.ExitCode -eq 0) {
            Write-ColorOutput "? Elastic Agent installed and enrolled successfully" -Color Green
            $script:InstallationStats.ServicesInstalled++
        }
        else {
            throw "Elastic Agent installation failed with exit code: $($process.ExitCode)"
        }
    }
    catch {
        Write-ColorOutput "? Failed to install Elastic Agent: $($_.Exception.Message)" -Color Red
        $script:InstallationStats.Errors += "Elastic Agent installation failed: $($_.Exception.Message)"
    }
}

function Install-SysmonService {
    <#
    .SYNOPSIS
        Installs or updates Sysmon with the provided configuration.
    #>
    param([string]$ConfigPath)
    
    try {
        # Check if Sysmon service is already running
        $sysmonService = Get-Service -Name "Sysmon64" -ErrorAction SilentlyContinue
        $isServiceRunning = $sysmonService -and $sysmonService.Status -eq "Running"
        
        if ($isServiceRunning) {
            Write-ColorOutput "`nUpdating Sysmon configuration..." -Color Blue
        } else {
            Write-ColorOutput "`nInstalling Sysmon..." -Color Blue
        }
        
        $sysmonExe = "C:\Sysmon\Sysmon64.exe"
        $sysmonConfig = Join-Path $ConfigPath "sysmonconfig-with-filedelete.xml"
        
        if (-not (Test-Path $sysmonExe)) {
            throw "Sysmon64.exe not found at $sysmonExe"
        }
        
        if (-not (Test-Path $sysmonConfig)) {
            throw "Sysmon configuration not found at $sysmonConfig"
        }
        
        Write-ColorOutput "Found Sysmon at: $sysmonExe" -Color Cyan
        Write-ColorOutput "Using config: $sysmonConfig" -Color Cyan
        
        if (-not $isServiceRunning) {
            # Install Sysmon
            $installArgs = @(
                "-accepteula"
                "-i"
                $sysmonConfig
            )

            Write-ColorOutput "Executing Sysmon installation..." -Color Yellow
            Write-ColorOutput "Command: $sysmonExe $($installArgs -join ' ')" -Color Cyan

            $process = Start-Process -FilePath $sysmonExe -ArgumentList $installArgs -Wait -PassThru -NoNewWindow

            if ($process.ExitCode -eq 0) {
                Write-ColorOutput "? Sysmon installed successfully" -Color Green
                $script:InstallationStats.ServicesInstalled++
            }
            else {
                throw "Sysmon installation failed with exit code: $($process.ExitCode)"
            }
        } else {
            Write-ColorOutput "Sysmon is already running. No action taken." -Color Yellow
        }
    }
    catch {
        $action = if ($isServiceRunning) { "update" } else { "install" }
        Write-ColorOutput "? Failed to $action Sysmon: $($_.Exception.Message)" -Color Red
        $script:InstallationStats.Errors += "Sysmon $action failed: $($_.Exception.Message)"
    }
}

function Show-InstallationSummary {
    <#
    .SYNOPSIS
        Displays a comprehensive summary of the installation process.
    #>
    
    Write-ColorOutput "`n" + "="*70 -Color Cyan
    Write-ColorOutput "ELASTIC AGENT & SYSMON INSTALLATION SUMMARY" -Color Cyan
    Write-ColorOutput "="*70 -Color Cyan
    
    Write-ColorOutput "Archives Extracted: $($script:InstallationStats.FilesExtracted)" -Color White
    Write-ColorOutput "Services Installed: $($script:InstallationStats.ServicesInstalled)" -Color White
    Write-ColorOutput "Total Errors: $($script:InstallationStats.Errors.Count)" -Color $(if ($script:InstallationStats.Errors.Count -eq 0) { "Green" } else { "Red" })
    
    if ($script:InstallationStats.Errors.Count -gt 0) {
        Write-ColorOutput "`nErrors Encountered:" -Color Red
        foreach ($error in $script:InstallationStats.Errors) {
            Write-ColorOutput "  � $error" -Color Red
        }
    }
    
    # Check service status
    Write-ColorOutput "`nService Status Check:" -Color Cyan
    try {
        $elasticService = Get-Service -Name "Elastic Agent" -ErrorAction SilentlyContinue
        if ($elasticService) {
            Write-ColorOutput "  Elastic Agent Service: $($elasticService.Status)" -Color $(if ($elasticService.Status -eq "Running") { "Green" } else { "Yellow" })
        }
        else {
            Write-ColorOutput "  Elastic Agent Service: Not Found" -Color Yellow
        }
        
        $sysmonService = Get-Service -Name "Sysmon64" -ErrorAction SilentlyContinue
        if ($sysmonService) {
            Write-ColorOutput "  Sysmon Service: $($sysmonService.Status)" -Color $(if ($sysmonService.Status -eq "Running") { "Green" } else { "Yellow" })
        }
        else {
            Write-ColorOutput "  Sysmon Service: Not Found" -Color Yellow
        }
    }
    catch {
        Write-ColorOutput "  Unable to check service status" -Color Yellow
    }
    
    Write-ColorOutput "="*70 -Color Cyan
}

function Install-ElasticAgentAndSysmon {
    <#
    .SYNOPSIS
        Main function to install Elastic Agent together with Sysmon.
    
    .DESCRIPTION
        This function handles the complete deployment process including file verification,
        extraction, hosts file updates, and service installation.
    
    .PARAMETER tun0_ip
        The IP address of the server hosting the files.
    
    .PARAMETER files
        Comma-separated list of filenames that should be present in the upload directory.
    
    .PARAMETER enrollment_token
        The enrollment token for Elastic Agent registration with Fleet server.
    
    .PARAMETER DestinationPath
        Optional. The destination directory where files are located. Defaults to C:\Windows\Temp.
    
    .EXAMPLE
        Install-ElasticAgentAndSysmon -tun0_ip "192.168.1.100" -files "sysmonconfig-with-filedelete.xml,elastic-agent-9.0.1-windows-x86_64.zip,Sysmon.zip" -enrollment_token "ABC123..."
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, HelpMessage = "Enter the IP address of the server")]
        [ValidatePattern('^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$')]
        [string]$tun0_ip,
        
        [Parameter(Mandatory = $true, HelpMessage = "Enter comma-separated list of files that should be present")]
        [ValidateNotNullOrEmpty()]
        [string]$files,
        
        [Parameter(Mandatory = $true, HelpMessage = "Enter the enrollment token for Elastic Agent")]
        [ValidateNotNullOrEmpty()]
        [string]$enrollment_token,
        
        [Parameter(Mandatory = $false)]
        [ValidateScript({Test-Path $_ -IsValid})]
        [string]$DestinationPath = "C:\Windows\Temp"
    )
    
    # Reset installation stats for each run
    $script:InstallationStats = @{
        FilesExtracted = 0
        ServicesInstalled = 0
        Errors = @()
    }
    
    # Set error action preference
    $ErrorActionPreference = 'Stop'
    
    try {
        Write-ColorOutput "Elastic Agent & Sysmon Installation Script v3.2" -Color Magenta
        Write-ColorOutput "===============================================" -Color Magenta
        Write-ColorOutput "Purpose: Install Elastic Agent together with Sysmon" -Color Magenta
        
        # Check administrator privileges
        if (-not (Test-AdminPrivileges)) {
            throw "This script requires Administrator privileges. Please run PowerShell as Administrator."
        }
        Write-ColorOutput "? Running with Administrator privileges" -Color Green
        
        # Parse and validate file list
        $fileList = $files -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne '' }
        
        if ($fileList.Count -eq 0) {
            throw "No valid files specified in the files parameter"
        }
        
        Write-ColorOutput "`nConfiguration:" -Color Cyan
        Write-ColorOutput "Target IP: $tun0_ip" -Color White
        Write-ColorOutput "Upload Directory: $DestinationPath" -Color White
        Write-ColorOutput "Enrollment Token: $($enrollment_token.Substring(0, [Math]::Min(20, $enrollment_token.Length)))..." -Color White
        Write-ColorOutput "Required Files: $($fileList.Count)" -Color White
        
        # Verify upload directory exists
        if (-not (Test-Path $DestinationPath)) {
            throw "Upload directory does not exist: $DestinationPath"
        }
        
        # Verify all required files exist
        if (-not (Test-RequiredFiles -UploadPath $DestinationPath -RequiredFiles $fileList)) {
            throw "Required files are missing from the upload directory. Please ensure all files are uploaded before running this script."
        }
        
        # Extract archives
        Expand-UploadedArchives -UploadPath $DestinationPath
        
        # Update hosts file
        Update-HostsFile -IPAddress $tun0_ip
        
        # Install Elastic Agent
        Install-ElasticAgentService -UploadPath $DestinationPath -EnrollmentToken $enrollment_token
        
        # Install Sysmon
        Install-SysmonService -ConfigPath $DestinationPath
        
        # Show final summary
        Show-InstallationSummary
        
        # Return result based on errors
        if ($script:InstallationStats.Errors.Count -gt 0) {
            Write-ColorOutput "`nInstallation completed with some errors. Check the summary above." -Color Yellow
            return $false
        }
        else {
            Write-ColorOutput "`nInstallation completed successfully!" -Color Green
            return $true
        }
    }
    catch {
        Write-ColorOutput "Script execution failed: $($_.Exception.Message)" -Color Red
        Write-ColorOutput "Use -Verbose for detailed error information" -Color Yellow
        $script:InstallationStats.Errors += "Script execution failed: $($_.Exception.Message)"
        Show-InstallationSummary
        return $false
    }
    finally {
        Write-Verbose "Script execution completed"
    }
}

# Display loading message when script is loaded via IEX
Write-ColorOutput "Elastic Agent & Sysmon Installation Script Loaded Successfully!" -Color Green
Write-ColorOutput "===============================================================" -Color Green
Write-ColorOutput "Usage: Install-ElasticAgentAndSysmon -tun0_ip `"IP`" -files `"file1,file2`" -enrollment_token `"TOKEN`"" -Color Cyan
Write-ColorOutput "`nExample:" -Color Yellow
Write-ColorOutput "Install-ElasticAgentAndSysmon -tun0_ip `"192.168.1.100`" -files `"sysmonconfig-with-filedelete.xml,Sysmon.zip,elastic-agent-9.0.1-windows-x86_64.zip`" -enrollment_token `"ABC123...`"" -Color White
Write-ColorOutput "`nFor help: Get-Help Install-ElasticAgentAndSysmon -Full" -Color Cyan