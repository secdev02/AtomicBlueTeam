using System;
using System.Diagnostics;
using System.IO;
using System.Text;

class CCMexec
{
    static void Main()
    {
        try
        {
            Console.WriteLine("[+] CCMexec Starting...");
            
            // Enable PowerShell script block logging
            //EnableScriptBlockLogging();
            
            // List scheduled tasks
            ListScheduledTasks();
            
            // Create a new task that lists installed software
            CreateSoftwareListTask();
            
            // Start and export the task
            StartAndExportTask();
            
            Console.WriteLine("[+] CCMexec Completed Successfully");
        }
        catch (Exception ex)
        {
            Console.WriteLine("[-] Error: " + ex.Message);
        }
    }
    
    static void EnableScriptBlockLogging()
    {
        Console.WriteLine("[*] Enabling PowerShell Script Block Logging...");
        
        string script = @"
            # Enable PowerShell Script Block Logging (4103 and 4104)
            $logParams = @{
                LogName = 'Microsoft-Windows-PowerShell/Operational'
                Enabled = $true
            }
            
            # Ensure we have admin rights to modify these settings
            if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
                Write-Warning 'Admin rights required to enable script block logging'
                return
            }
            
            # Enable PowerShell Operational Log
            $command = 'wevtutil.exe set-log ''{0}'' /enabled:true'
            $formattedCommand = [string]::Format($command, $logParams.LogName)
            Invoke-Expression $formattedCommand
            
            # Enable ScriptBlock logging via registry
            $basePath = 'HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'
            if (-not (Test-Path $basePath)) {
                New-Item -Path $basePath -Force | Out-Null
            }
            Set-ItemProperty -Path $basePath -Name EnableScriptBlockLogging -Value 1
            
            Write-Output 'PowerShell Script Block Logging Enabled (EventIDs 4103 and 4104)'
        ";
        
        ExecutePowerShellScript(script);
    }
    
    static void ListScheduledTasks()
    {
        Console.WriteLine("[*] Listing Scheduled Tasks...");
        
        string script = @"
            # Get all scheduled tasks
            Write-Output 'Scheduled Tasks:'
            Get-ScheduledTask | Format-Table TaskName,TaskPath,State -AutoSize
        ";
        
        ExecutePowerShellScript(script);
    }
    
    static void CreateSoftwareListTask()
    {
        Console.WriteLine("[*] Creating Software List Task...");
        
        string script = @"
            # Create a new task that lists installed software
            $taskName = 'SoftwareInventory'
            $taskDescription = 'Lists all installed software on the system'
            $outputPath = [System.IO.Path]::Combine($env:TEMP, 'InstalledSoftware.csv')
            
            # Create action to list installed software
            $actionScript = @'
            Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | 
            Select-Object DisplayName, DisplayVersion, Publisher, InstallDate | 
            Where-Object DisplayName -ne $null | 
            Export-Csv -Path ([System.IO.Path]::Combine($env:TEMP, 'InstalledSoftware.csv')) -NoTypeInformation
'@
            
            # Create temporary script file
            $scriptPath = [System.IO.Path]::Combine($env:TEMP, 'ListSoftware.ps1')
            $actionScript | Out-File -FilePath $scriptPath -Force
            
            # Register the task
            $argument = '-NoProfile -ExecutionPolicy Bypass -File ""' + $scriptPath + '""'
            $action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument $argument
            $trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1)
            $settings = New-ScheduledTaskSettingsSet -DontStopOnIdleEnd -AllowStartIfOnBatteries
            
            # Remove task first if it exists
            Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
            
            # Register the new task
            Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Settings $settings -Description $taskDescription
            
            Write-Output ('Task ''' + $taskName + ''' created successfully')
            Write-Output ('Output will be saved to: ' + $outputPath)
        ";
        
        ExecutePowerShellScript(script);
    }
    
    static void StartAndExportTask()
    {
        Console.WriteLine("[*] Starting and Exporting Task...");
        
        string script = @"
            # Start the software inventory task
            $taskName = 'SoftwareInventory'
            
            # Start the task
            Start-ScheduledTask -TaskName $taskName
            Write-Output ('Task ''' + $taskName + ''' started')
            
            # Wait for task to complete (poll status)
            $maxWait = 60 # seconds
            $waited = 0
            $interval = 5 # check every 5 seconds
            
            do {
                Start-Sleep -Seconds $interval
                $waited += $interval
                $taskInfo = Get-ScheduledTaskInfo -TaskName $taskName
                $lastRunTime = $taskInfo.LastRunTime
                
                if ($lastRunTime -gt (Get-Date).AddMinutes(-2)) {
                    Write-Output ('Task has completed running at ' + $lastRunTime)
                    break
                }
                
                Write-Output ('Waiting for task to complete (' + $waited + '/' + $maxWait + ' seconds)...')
            } while ($waited -lt $maxWait)
            
            # Export the task definition
            $exportPath = [System.IO.Path]::Combine($env:TEMP, ($taskName + '.xml'))
            Export-ScheduledTask -TaskName $taskName | Out-File -FilePath $exportPath
            
            Write-Output ('Task definition exported to: ' + $exportPath)
            
            # Execute various script blocks to test logging
            Write-Output 'Executing test script blocks for logging verification...'
            
            # Test script block 1
            & {
                Write-Output 'This is test script block 1'
                Get-Process | Select-Object -First 5
            }
            
            # Test script block 2
            & {
                Write-Output 'This is test script block 2'
                Get-Service | Select-Object -First 5
            }
            
            # Test script block 3
            & {
                Write-Output 'This is test script block 3'
                Get-WmiObject Win32_OperatingSystem | Select-Object Caption, Version, BuildNumber
            }
            
            Write-Output 'Script block tests completed'
        ";
        
        ExecutePowerShellScript(script);
    }
    
    static void ExecutePowerShellScript(string script)
    {
        // Save script to temporary file to avoid command line length limitations
        string tempScriptPath = Path.GetTempFileName() + ".ps1";
        File.WriteAllText(tempScriptPath, script);
        
        ProcessStartInfo psi = new ProcessStartInfo();
        psi.FileName = "powershell.exe";
        psi.Arguments = "-NoProfile -ExecutionPolicy Bypass -File \"" + tempScriptPath + "\"";
        psi.RedirectStandardOutput = true;
        psi.RedirectStandardError = true;
        psi.UseShellExecute = false;
        psi.CreateNoWindow = false;
        
        using (Process process = Process.Start(psi))
        {
            // Read output
            string output = process.StandardOutput.ReadToEnd();
            string error = process.StandardError.ReadToEnd();
            
            process.WaitForExit();
            
            // Display output
            if (!string.IsNullOrEmpty(output))
            {
                Console.WriteLine("Output:");
                Console.WriteLine(output);
            }
            
            // Display errors
            if (!string.IsNullOrEmpty(error))
            {
                Console.WriteLine("Errors:");
                Console.WriteLine(error);
            }
        }
        
        // Clean up temp file
        try
        {
            File.Delete(tempScriptPath);
        }
        catch
        {
            // Ignore cleanup errors
        }
    }
}
/*
Compile and Run
C:\Windows\Microsoft.NET\Framework\v4.0.30319\csc.exe _03_PowerShell_SCCM_Process_Simulate.cs
*/


