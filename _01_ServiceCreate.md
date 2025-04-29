### Create a test for Event ID

```
# Create a directory to store our files


$workingDir = "C:\ServiceTest"
if (!(Test-Path $workingDir)) {
    New-Item -ItemType Directory -Path $workingDir
}

# Create the C# service code
$serviceCode = @'
using System;
using System.ServiceProcess;
using System.Diagnostics;
using System.Threading;

namespace MinimalService
{
    public class MinimalService : ServiceBase
    {
        private EventLog eventLog;
        private Thread serviceThread;
        private bool running = false;

        public MinimalService()
        {
            this.ServiceName = "MinimalService";
            this.CanStop = true;
            this.CanPauseAndContinue = false;
            this.AutoLog = true;

            // Set up event logging
            if (!EventLog.SourceExists(this.ServiceName))
            {
                EventLog.CreateEventSource(this.ServiceName, "Application");
            }
            eventLog = new EventLog();
            eventLog.Source = this.ServiceName;
            eventLog.Log = "Application";
        }

        protected override void OnStart(string[] args)
        {
            eventLog.WriteEntry("Minimal Service Starting...");
            running = true;
            serviceThread = new Thread(new ThreadStart(ServiceWorker));
            serviceThread.Start();
        }

        protected override void OnStop()
        {
            eventLog.WriteEntry("Minimal Service Stopping...");
            running = false;
            if (serviceThread != null)
            {
                serviceThread.Join(3000); // Wait for the thread to finish
            }
        }

        private void ServiceWorker()
        {
            while (running)
            {
                eventLog.WriteEntry("Minimal Service is running", EventLogEntryType.Information);
                Thread.Sleep(10000); // Sleep for 10 seconds
            }
        }

        public static void Main()
        {
            ServiceBase.Run(new MinimalService());
        }
    }
}
'@

# Save the service code to a file
$serviceCodePath = Join-Path -Path $workingDir -ChildPath "MinimalService.cs"
Set-Content -Path $serviceCodePath -Value $serviceCode

# Compile the service using .NET Framework
$references = "System.dll", "System.ServiceProcess.dll"
$outputPath = Join-Path -Path $workingDir -ChildPath "MinimalService.exe"

Add-Type -Path $serviceCodePath -OutputAssembly $outputPath -OutputType WindowsApplication -ReferencedAssemblies $references -Debug:$false

# Create the service
$serviceName = "MinimalService"
$exePath = $outputPath

Write-Host "Creating service..." -ForegroundColor Yellow
sc.exe create $serviceName binPath= $exePath DisplayName= "Minimal Test Service" start= auto

# Start the service
Write-Host "Starting service..." -ForegroundColor Green
Start-Service -Name $serviceName
Start-Sleep -Seconds 5

# Check the service status
Get-Service -Name $serviceName

# Stop the service
Write-Host "Stopping service..." -ForegroundColor Red
Stop-Service -Name $serviceName -Force
Start-Sleep -Seconds 3

# Delete the service
Write-Host "Deleting service..." -ForegroundColor Magenta
sc.exe delete $serviceName

Write-Host "Process completed!" -ForegroundColor Cyan
```
