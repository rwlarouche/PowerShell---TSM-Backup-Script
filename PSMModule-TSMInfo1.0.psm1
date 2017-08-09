<#
    .SYNOPSIS
     A brief summary of the commands in the file.

    .DESCRIPTION
    A detailed description of the commands in the file.

    .NOTES
    ========================================================================
         Windows PowerShell Source File 
         Created with SAPIEN Technologies PrimalScript 2016
         
         NAME: 
         
         AUTHOR: Ryan LaRouche 
         DATE  : 6/29/2017
         
         COMMENT: 
    ==========================================================================
#>

function Get-TSMInfo{
	[CmdletBinding()] 
	param(
		[Parameter(Mandatory = $True,
		 ValueFromPipeline = $True,
		 ValueFromPipelineByPropertyName = $True)]
        [String[]]$ComputerName
	)
	BEGIN {
		MakeLogFile
		
		#Make cvs path (timestamped)
	   	$now = (Get-Date -Format u) -replace "Z", ""
	    $TimeForCSVFileName = $now -replace ":", "-"
	    $TimeForCSVFileName = $TimeForCSVFileName -replace " ", "_"
	    $TempDirectory = Get-Item env:'temp'
		$global:CSVFile = $TempDirectory.value + "\" + $TimeForCSVFileName + "_TSMInfo.csv"
	}
	PROCESS {
		try {
			foreach ($Computer in $ComputerName){
				if ($Computer.substring($Computer.get_Length()-5) -like ("*_TLOG*")){
					LogEvent $global:LogFile "SKIPPED $Computer : Hostname $Computer is a _TLOG host, please enter valid server name."
				}
				else {
					Get-TSMService -Server $Computer.Trim()
				}
			}
		}
		catch{
			LogEvent $global:LogFile "ERROR: Script encountered a runtime error and had to terminate.
			Please try again."
		}
	}
	END {}
}

function MakeLogFile{
	$now = (Get-Date -Format u) -replace "Z", ""
	$TimeForLogFileName = $now -replace ":", "-"
	$TimeForLogFileName = $TimeForLogFileName -replace " ", "_"
		
	$TempDirectory = Get-Item env:'temp'
	$TempDirectory.value
	$global:LogFile = $TempDirectory.value + "\" + $TimeForLogFileName + "_TSMInfo.log"
	
	#Write opening line to log file
	try
		{
		if (Test-Path $global:LogFile)
			# file exists
			{
			"`t`t $now`.Test-Script.run.log" | Out-File $global:LogFile -append
			}
		else
			# file does NOT exist
			{
			"`t`t $now`.Get-TSMInfo.run.log" | Out-File $global:LogFile
			}
		}
	catch
		{
		LogEvent $global:LogFile "Script ERROR: Could not write to log file - '$global:LogFile'."
		}
}

function MakeCSVFile{
	try
		{
		if (!(Test-Path $global:CSVFile)) #If file does not exist, create new file with headers
			{
            
			$CSVFile = New-Object PSObject
				#Add Row/Empty Content
				$CSVFile | Add-Member NoteProperty ServerName '' #Server Name
				$CSVFile | Add-Member NoteProperty IPAddress '' #IPAddress
				$CSVFile | Add-Member NoteProperty Uptime '' #Uptime
				$CSVFile | Add-Member NoteProperty ServiceName '' #Service
				$CSVFile | Add-Member NoteProperty ServiceState '' #Service State
				$CSVFile | Add-Member NoteProperty StartMode '' #Start-Mode
				$CSVFile | Add-Member NoteProperty NodeName '' #Node-Name
				$CSVFile | Add-Member NoteProperty OptPath '' #Opt Path
				$CSVFile | Add-Member NoteProperty SchedPath '' #Sched Path
				$CSVFile | Add-Member NoteProperty ErrorPath '' #Error Path
				$CSVFile | Add-Member NoteProperty ErrorList '' #Error Master List
				$CSVFile | Add-Member NoteProperty RemedyList '' #Remedy Master List
				
				$CSVFile | Export-Csv $global:CSVFile -Force
			}
			# Else do nothing, no need to make file
		}
	catch
		{
		 LogEvent $global:LogFile "Script ERROR: Could not write to CSV file - '$global:CSVFile'"
		}
}

function Get-TSMService{
	param([string]$Server)
	
	BEGIN {}
	PROCESS {
		#Array that will track the errors to display troubleshooting at the end of each server's log output
		[System.Collections.ArrayList]$ErrorLog = @()

		#Search through each server for specified files/contents
		try{
	        # If remote connection successful, print log events before running TSM service collection
			LogEvent $global:LogFile ""
			LogEvent $global:LogFile "Running script for server : '$Server'"

             #Get and display IP Address           
            $WMIJob= Get-WmiObject -ComputerName $Server Win32_NetworkAdapterConfiguration -AsJob
	        $jobWait = $WMIJob | Wait-Job -Timeout 10 
    	   	$WMIService = Receive-Job -Job $WMIJob
  	       	if ($WMIJob.State -ne "Completed"){ #Add Error to Error table if job fails
                LogEvent $global:LogFile "ERROR: Unable to get IP Address"
 	        	$ErrorLog.Add("ERROR: Unable to get IP Address") | Out-Null
 	        	$IPAddress = "not found"
 		    }
            Else{
                $IPAddress = $WMIService | Where-Object { $_.IPAddress -ne $null } | Select-Object -ExpandProperty "IPAddress"
                LogEvent $global:LogFile "`tIP Address : $IPAddress"
            }
	        Stop-Job -Job $WMIJob
	  	    Remove-Job -Job $WMIJob

            #Get server uptime
    		$WMIJob= Get-WmiObject -ComputerName $Server -Class Win32_OperatingSystem -AsJob
	    	$jobWait = $WMIJob | Wait-Job -Timeout 10
		    	$WMIService = Receive-Job -Job $WMIJob
  	    	if ($WMIJob.State -ne "Completed"){ #Add Error to Error table if job fails
                LogEvent $global:LogFile "ERROR: Unable to get Server Uptime"
 		    	$ErrorLog.Add("ERROR: Unable to get Server Uptime") | Out-Null
 		    	$uptime = "not found"
	 		}
            Else{
                $lastBootTime = $WMIService.ConvertToDateTime($WMIService.LastBootUpTime)
                $sysUpTime = ((Get-Date) - $lastboottime)
                $uptime = "$($sysuptime.days) Days, $($sysuptime.hours) Hours, $($sysuptime.minutes) Minutes"
                LogEvent $global:LogFile "`tServer Uptime : $uptime"
            }
	     	Stop-Job -Job $WMIJob
	  	    Remove-Job -Job $WMIJob
	  	    
			#Get local drives on server
			[System.Collections.ArrayList]$DriveNames = @()
			$WMIJob = Get-WmiObject -ComputerName $Server -Class win32_volume -AsJob
	    	$jobWait = $WMIJob | Wait-Job -Timeout 10
		    	$WMIService = Receive-Job -Job $WMIJob
  	    	if ($WMIJob.State -ne "Completed"){ #Add Error to Error table if job fails
                LogEvent $global:LogFile "ERROR: Unable to get list of local drives on server"
 		    	$ErrorLog.Add("ERROR: Unable to get list of local drives on server") | Out-Null
 		    	$DriveNames.Add("None") | Out-Null
	 		}
            Else{
            	#$WMIService | Where-Object {($_.DriveType -eq 3)} # | Select-Object -ExpandProperty "DriveLetter"
            	$drives = $WMIService | Where-Object {($_.DriveType -eq 3)}
            	foreach($drive in $drives){
            		$DriveNames.Add($drive.DriveLetter) | Out-Null
            	}
            	$DrivesString = ($DriveNames -join " ")
                LogEvent $global:LogFile "`tLocal Drives : $DrivesString"
            }
	     	Stop-Job -Job $WMIJob
	  	    Remove-Job -Job $WMIJob
	  	    
			LogEvent $global:LogFile "About to collect TSM Info.."
			LogEvent $global:LogFile "Checking for all TSM Services.."
		
			#Get list of running services on server
			$services = Get-Service	-ComputerName $Server
 			$serviceFound = $false 	# Bool tracks if a TSM service is found (false if not)
 		
 			#Get all server services
 			foreach ($service in $services){
 				$serviceName = $service | Select-Object -ExpandProperty "Name"
 				
 				#Find TSM services
 				if ($serviceName -like "TSM*"){
 					$serviceFound = $true
 					LogEvent $global:LogFile "TSM Service found : '$serviceName'"
 					
 					#Ignore irrelevant TSM Services
 					if (($serviceName -like "TSM Client Acceptor") -or ($serviceName -like "TSM Remote Client Agent")){
 						LogEvent $global:LogFile "`Skipping this TSM Service : '$serviceName'"
 					}
	 				else{
	 					#Get service info/parameters for relevant services
	 					try{
	 					get-ServiceInfo -Server $Server -ServiceName $serviceName -ErrorLog $ErrorLog -IPAddress $IPAddress -Uptime $uptime
	 					}
	 					catch{
							LogEvent $global:LogFile "ERROR: Could not get service properties for '$service'"
						}
	 				}
 				}
 			}
 			
 			#If no TSM service found, return in log
 				if ($serviceFound -eq $false){
 					LogEvent $global:LogFile "No TSM Service found"     
 				}
 		}
		# WMI Remote Connection Error
		catch{
			LogEvent $global:LogFile "ERROR: Unable to remotely connect to server '$Server'"
            LogEvent $global:LogFile "Pinging server.. '$Server' at IP: '$IPAddress'"
            if (test-Connection -ComputerName $Server -Count 2 -Quiet ) {  
                 LogEvent $global:LogFile "Successfully pinged '$Server'"
                 LogEvent $global:LogFile "This script requires that 'Remote Connection Access' Service State is Running on the remote server"
            } 
            else{
                LogEvent $global:LogFile "ERROR: Unable to ping '$Server' : Please check server status."
                $ErrorLog.Add("ERROR: Unable to ping '$Server' : Please check server status.")  | Out-Null
            }     

		}
	}
	END {}
}

function Get-ServiceInfo{
	param(
	[string]$Server,
	[string]$ServiceName,
    [string]$IPAddress,
    [string]$Uptime,
	[System.Collections.ArrayList]$ErrorLog
	)
	BEGIN {}
	PROCESS {
		try{
			#Run Get=WmiObject as a job with a timeout to prevent infinite request if unable to reach WMI job
			$WMIJob= Get-WmiObject -ComputerName $Server -Class Win32_Service -Filter "Name='$ServiceName'" -AsJob
			$jobWait = $WMIJob | Wait-Job -Timeout 10
			$WMIService = Receive-Job -Job $WMIJob
	  		if ($WMIJob.State -ne "Completed"){ #Add Error to Error table if job fails
	  			$ErrorLog.Add("ERROR: Unable to get WMI Service for service '$ServiceName'") | Out-Null
	  		}
            Else{
           	    $ServiceState = $WMIService | Select-Object -ExpandProperty "State"
	  		    $ServiceStartMode = $WMIService | Select-Object -ExpandProperty "StartMode"	
	  		    LogEvent $global:LogFile "`tService-State : $ServiceState"
	  		    if ($ServiceState -eq "Stopped"){
	 				LogEvent $global:LogFile "`t`tERROR: Service should not be stopped unless '$Server' is part of a cluster"
					$ErrorLog.Add("ERROR: Service should not be stopped unless '$Server' is part of a cluster") | Out-Null
	  		    }
	  		    LogEvent $global:LogFile "`tStart-Mode : $ServiceStartMode"
            }
	  		Stop-Job -Job $WMIJob
	  		Remove-Job -Job $WMIJob
		
			$path = "HKLM:\SYSTEM\CurrentControlSet\services\$ServiceName\Parameters"
			$parameters = Invoke-Command -ComputerName $Server -Command {Get-ItemProperty -Path $args[0]} -ArgumentList $path
	
			#Get values from Server parameters keys
			$TSMNodeName = $parameters | Select-Object -ExpandProperty "ClientNodeName" #Node Name
			$RawPath = $parameters | Select-Object -ExpandProperty "OptionsFile"		#Opt File
			$driveletter = $RawPath[0]
			$drivepath = [string]$RawPath[0..2] -replace(" ","")
			$TSMOptFile = $RawPath.replace($drivepath, "\\$Server\$driveletter`$\")
			
			if(Get-Member -inputobject $parameters -name "ScheduleLog"){ #Schedule Log
				$RawPath = $parameters | Select-Object -ExpandProperty "ScheduleLog"
				$driveletter = $RawPath[0]
				$drivepath = [string]$RawPath[0..2] -replace(" ","")
				$TSMSchedLog = $RawPath.replace($drivepath, "\\$Server\$driveletter`$\")
			}
			Else{
				$FileContents = Invoke-Command -ComputerName $Server -Command {Get-Content -Path $args[0]} -ArgumentList $TSMOptFile
				foreach ($line in $FileContents){
					if($line -like ("*schedlogname*")){
						$RawPath = $line.split('"')[1]
						$driveletter = $RawPath[0]
						$drivepath = [string]$RawPath[0..2] -replace(" ","")
						$TSMSchedLog = $RawPath.replace($drivepath, "\\$Server\$driveletter`$\")
					}
				}
			}
			if(Get-Member -inputobject $parameters -name "ErrorLog"){ #Error Log
				$RawPath = $parameters | Select-Object -ExpandProperty "ErrorLog"
				$driveletter = $RawPath[0]
				$drivepath = [string]$RawPath[0..2] -replace(" ","")
				$TSMErrorLog = $RawPath.replace($drivepath, "\\$Server\$driveletter`$\")
			}
			Else{
				$FileContents = Invoke-Command -ComputerName $Server -Command {Get-Content -Path $args[0]} -ArgumentList $TSMOptFile
				foreach ($line in $FileContents){
					if($line -like "*errorlogname*"){
						$RawPath = $line.split('"')[1]
						$driveletter = $RawPath[0]
						$drivepath = [string]$RawPath[0..2] -replace(" ","")
						$TSMErrorLog = $RawPath.replace($drivepath, "\\$Server\$driveletter`$\")
					}
				}
			}
			
			#If any value is null, assign a 'not found' value
			if ($TSMNodeName -eq $NULL){$TSMNodeName = 'not found'}
			if ($TSMOptFile -eq $NULL){$TSMOptFile = 'not found'}
			if ($TSMSchedLog -eq $NULL){$TSMSchedLog = 'not found'}
			if ($TSMErrorLog -eq $NULL){$TSMErrorLog = 'not found'}
			
			LogEvent $global:LogFile "`tTSM Client-NodeName in REGISTRY is : '$TSMNodeName'"
			if ($TSMNodeName -like $Server){
				LogEvent $global:LogFile "`t`tTSM Client-NodeName MATCHES server name '$Server'"
			}
			else{
				LogEvent $global:LogFile "`tERROR: TSM Client-NodeName '$TSMNodeName' in REGISTRY DOES NOT MATCH server name '$Server'"
				$ErrorLog.Add("ERROR: TSM Client-NodeName '$TSMNodeName' in REGISTRY DOES NOT MATCH server name '$Server'") | Out-Null
			}
			LogEvent $global:LogFile "`tTSM Options File in REGISTRY is : '$TSMOptFile'"
			LogEvent $global:LogFile "`tTSM Sched Log File in REGISTRY is : '$TSMSchedLog'"
			LogEvent $global:LogFile "`tTSM Error Log File in REGISTRY is : '$TSMErrorLog'"
			
			#Check opt/error/sched files
			Get-OptFile -Server $Server -TSMOptFile $TSMOptFile -ErrorLog $ErrorLog
			Get-SchedLog -Server $Server -TSMSchedLog $TSMSchedLog -ErrorLog $ErrorLog
			Get-ErrorLog -Server $Server -TSMErrorLog $TSMErrorLog -ErrorLog $ErrorLog
			
			# Output a list of all of the errors that occured (for readability and efficiency)
			$linecount = 0 # Line counter
			LogEvent $global:LogFile "--- ERROR LOG MASTER-LIST ---"
			if ($ErrorLog.Count -eq 0){
				$linecount++  | Out-Null
				LogEvent $global:LogFile "$linecount : No critical errors occurred during backup"
			}
			foreach ($error in $ErrorLog){
				$linecount ++ | Out-Null
				LogEvent $global:LogFile "$linecount : $error"
			}
			LogEvent $global:LogFile "-----------------------------"
			
			# Output list of remediation steps based on error log messages
			$linecount = 0
            [System.Collections.ArrayList]$RemedyLog = @()
			LogEvent $global:LogFile "---- REMEDY MASTER-LIST ----"
			if ($ErrorLog.Count -eq 0){ # If no errors, there are no remedies
				$linecount++ | Out-Null
				LogEvent $global:LogFile "$linecount : No remediation necessary"
                $ErrorLog.Add("$linecount : No critical errors occurred during backup") | Out-Null
                $RemedyLog.Add("$linecount : No remediation necessary") | Out-Null
			}
			foreach ($error in $ErrorLog){ # For each error, provide a remedy
				if ($error -contains ("ERROR: Unable to ping '$Server' : Please check server status.")){	#Unable to connect/ping server
					$linecount++ | Out-Null
					$remedy = "'Server' was not pingable : Please check the status of '$Server' (IP: $IPAddress)"
					LogEvent $global:LogFile "$linecount : $remedy"
                    $RemedyLog.Add("$linecount : $remedy") | Out-Null
				}
				if ($error -Match("ERROR: Unable to get WMI Service for service '$ServiceName'")){	#WMI Error
					$linecount++ | Out-Null
					$remedy = "WMI Connection Failure : Please check the status of 'ServiceName'"
					LogEvent $global:LogFile "$linecount : $remedy"  | Out-Null
                    $RemedyLog.Add("$linecount : $remedy") | Out-Null
				}
				if ($error -contains ("ERROR: TSM Client-NodeName '$TSMNodeName' in REGISTRY DOES NOT MATCH server name '$Server'")){	#Client-NodeName
					$linecount++ | Out-Null
					$remedy = "Client Node-Name in REGISTRY does not match server name '$Server' "
					LogEvent $global:LogFile "$linecount : $remedy"
                    $RemedyLog.Add("$linecount : $remedy") | Out-Null
				}
				if ($error -contains ("ERROR: TSM Options File not found at : $TSMOptFile")){	#Opt File Path
					$linecount++ | Out-Null
					$remedy = "Failed to find TSM Opt File : Please verify that '$TSMOptFile' points to the Opt File. If it does not, either: `
					A. move the Opt File to the specified Path location`
						or`
					B. Change the Path within the Registry to match the correct Path"
					LogEvent $global:LogFile "$linecount : $remedy"
                    $RemedyLog.Add("$linecount : $remedy") | Out-Null
				}
				if ($error -contains ("ERROR: dsmerror.log not found at : $TSMErrorLog")){	#Error Log Path
					$linecount++ | Out-Null
					$remedy = "Failed to find TSM Error Log File : Please verify that '$TSMErrorLog' points to the Error Log File. If it does not, either: `
					A. move the Error Log File to the specified Path location `
						or `
					B. Change the Path within the Registry to match the correct Path"
					LogEvent $global:LogFile "$linecount : $remedy"
                    $RemedyLog.Add("$linecount : $remedy") | Out-Null
				}
				if ($error -contains ("ERROR: dsmsched.log not found at : $TSMSchedLog")){	#Sched Log Path
					$linecount++ | Out-Null
					$remedy = "Failed to find TSM Sched Log File : Please verify that '$TSMSchedLog' points to the Sched Log File. If it does not, either: `
					A. move the Sched Log File to the specified Path location`
						or`
					B. Change the Path within the Registry to match the correct Path"
					LogEvent $global:LogFile "$linecount : $remedy"
                    $RemedyLog.Add("$linecount : $remedy") | Out-Null
				}
				if ($error -contains ("ERROR: Elapsed processing time exceeded 24 hours")){	#Timeout Exception
					$linecount++ | Out-Null
					$remedy = "$linecount : Processing Time Exception: The previous backup was still running when '$Server' tried to run TSM. This typically occurs on a new server that`
					is running TSM Backup for the first time. Note the incident and monitor."
					LogEvent $global:LogFile "$linecount : $remedy"
                    $RemedyLog.Add("$linecount : $remedy") | Out-Null
				}
				if ($error -contains ("ERROR: Service should not be stopped unless '$Server' is part of a cluster")){	#Timeout Exception
					$linecount++ | Out-Null
					$remedy = "Service State Error: Service should be 'Running' unless it is part of a cluster. Check if '$Server' is part of a cluster."
					LogEvent $global:LogFile "$linecount : $remedy"
                    $RemedyLog.Add("$linecount : $remedy") | Out-Null
                }
               	if ($error -like ("*directory path*")){	#Timeout Exception
					$linecount++ | Out-Null
					$remedy = "Directory Path Error: Verify that all domains listed in the Opt File are valid local drives."
					LogEvent $global:LogFile "$linecount : $remedy"
                    $RemedyLog.Add("$linecount : $remedy") | Out-Null
                }
               	if ($error -contains ("ERROR: TSM Backup Client may still be running")){	#Timeout Exception
					$linecount++ | Out-Null
					$remedy = "Check schedule log to determine if TSM Client Backup is still running"
					LogEvent $global:LogFile "$linecount : $remedy"
                    $RemedyLog.Add("$linecount : $remedy") | Out-Null
                }
               	if (($error -like "*end*") -or ($error -like "*fail*")){	#Timeout Exception
					$linecount++ | Out-Null
					$remedy = "Last backup failed or ended before completion, $Server may have shut down during backup."
					LogEvent $global:LogFile "$linecount : $remedy"
                    $RemedyLog.Add("$linecount : $remedy") | Out-Null
                }
                	if ($error -like "*drive volume*"){	#Timeout Exception
					$linecount++ | Out-Null
					$remedy = "Check to ensure that drive listed exists, if it should be backed up, and how it is listed in the Opt File."
					LogEvent $global:LogFile "$linecount : $remedy"
                    $RemedyLog.Add("$linecount : $remedy") | Out-Null
                }
			} 
			LogEvent $global:LogFile "----------------------------"
            
            #Write to the CSV file
            CSVEvent $global:CSVFile $Server $IPAddress $Uptime $ServiceName $ServiceState `
			$ServiceStartMode $TSMNodeName $TSMOptFile $TSMSchedLog $TSMErrorLog $ErrorLog $RemedyLog

			$ErrorLog.Clear() | Out-Null
            $RemedyLog.Clear() | Out-Null
		}
		catch{
			LogEvent $global:LogFile "ERROR: Could not get service properties for '$ServiceName'"
		}
	}
	END {}
}

function Get-OptFile{
	param(
		[string]$Server, 
		[string]$TSMOptFile,
		[System.Collections.ArrayList]$ErrorLog
	)
	LogEvent $global:LogFile "`tChecking for TSM Options File : $TSMOptFile"
	try{
		#Get contents of opt file
		$FileContents = Invoke-Command -ComputerName $Server -Command {Get-Content -Path $args[0]} -ArgumentList $TSMOptFile
		LogEvent $global:LogFile "`tDSM.opt File found : $TSMOptFile"

		foreach ($line in $FileContents){
			#TCPPort
			if($line -like ("*TCPPort*")){
				$TCPPortRaw = $line.split('`t')[-1]
				$TCPPort = $TCPPortRaw.replace(" ","")
				LogEvent $global:LogFile "`t`tTivoli TCPPort is : $TCPPort"
			}
			#TSM Server Name
			if($line -like ("*TCPServeraddress*")){
				$TCPServerSplit = ($line -split "TCPServeraddress").Trim()
				$TCPServerName = $TCPServerSplit[-1]
				LogEvent $global:LogFile "`t`tTivoli Server Name is : $TCPServerName"
			}
			#SchedLog name
			if($line -like ("*schedlogname*")){
				$SchedLogName = $line.split('"')[1]
				LogEvent $global:LogFile "`t`tTSM SchedLogName From DSM.opt file is : $SchedLogName"
			}
			#ErrorLog name
			if($line -like "*errorlogname*"){
				$ErrorLogName = $line.split('"')[1]
				LogEvent $global:LogFile "`t`tTSM ErrorLogName From DSM.opt file is : $ErrorLogName"
			}
			#Read opt file for Domain names
			if($line -like ("*DOMAIN*")){
				$domainline = $line.replace(" ","")
				$domainline = $domainline[-2]
				LogEvent $global:LogFile "`t`tDomain entry found : $line"
			}
		}
		
# 		#Read opt file for Domain names
#  		$DomainNames = @($FileContents | Where-Object {$_.Contains("*DOMAIN*")})
#  		foreach ($domain in $DomainNames) {
#  			LogEvent $global:LogFile "`t`tDomain entry found : $domain"
#  		}
	}
	catch{
		LogEvent $global:LogFile "`tERROR: TSM Options File not found at : $TSMOptFile"
		$ErrorLog.Add("ERROR: TSM Options File not found at : $TSMOptFile") | Out-Null
	}
}

function Get-ErrorLog{
	param(
		[string]$Server, 
		[string]$TSMErrorLog,
		[System.Collections.ArrayList]$ErrorLog
	)

    $BACKUPS = 3 #Number of previous backups to include in backlog output

	LogEvent $global:LogFile "`tChecking for TSM Error Log : $TSMErrorLog"
	try{
		#Get contents of error log file
		$fileContents = Invoke-Command -ComputerName $Server -Command {Get-Content -Path $args[0]} -ArgumentList $TSMErrorLog
		LogEvent $global:LogFile "`tdsmerror.log File found : $TSMErrorLog"
		LogEvent $global:LogFile "`t`tChecking recent backup results..."
		
		#Read error log for recent backup results
		$logResults = @($fileContents | Where-Object {$_.Contains("finished")})
		$errorResults = @($fileContents | Where-Object {$_.Contains("connection lost") `
                                        -or $_.Contains("shutdown") `
                                        -or $_.Contains("interrupt")`
                                        -or $_.Contains("directory path")})
		$count = 0
        $start = -2*$BACKUPS
		foreach ($logresult in $logResults[$start..-1]){
			if ($count % 2 -eq 0){
				LogEvent $global:LogFile "`t`t`tBackup Result Found : $logresult"
				$TimeStamp = [string]$logresult.substring(0,10)
				foreach ($errorresult in $errorResults){
					if ($errorresult -contains("$TimeStamp")){
						LogEvent $global:LogFile "'t't't't ERROR: $errorresult"
						$ErrorLog.Add("ERROR: $errorresult") | Out-Null
					}
				}
			}
			
			$count++ | Out-Null
		}
	}
	catch{
		LogEvent $global:LogFile "`tERROR: dsmerror.log not found at : $TSMErrorLog"
		$ErrorLog.Add("ERROR: dsmerror.log not found at : $TSMErrorLog") | Out-Null
	}
}

function Get-SchedLog{
	param(
		[string]$Server, 
		[string]$TSMSchedLog,
		[System.Collections.ArrayList]$ErrorLog
	)

    $BACKUPS = 3 #Number of previous backups to include in backlog output

	LogEvent $global:LogFile "`tChecking for TSM Schedule Log : $TSMSchedLog"
	try{
		#Get contents of sched log file
		$fileContents = Invoke-Command -ComputerName $Server -Command {Get-Content -Path $args[0]} -ArgumentList $TSMSchedLog
		LogEvent $global:LogFile "`tdsmsched.log File found : $TSMSchedLog"
		LogEvent $global:LogFile "`t`tChecking recent backup results..."
		
		#Read sched log for recent backup info
		$logResults = @($fileContents | Where-Object {$_.Contains("STATUS BEGIN") `
                                        -or $_.Contains("SCHEDULEREC OBJECT BEGIN") `
                                        -or $_.Contains("Scheduled event '") `
                                        -or $_.Contains("Elapsed processing time:")})
        $start = -4*$BACKUPS
        if ($logResults.length -ne 0) {
        	LogEvent $global:LogFile "`t`t`t----------------------------------------------------------------------------------------"
		}
		foreach ($logresult in $logResults[$start..-1]){
			if ($logresult -Match("SCHEDULEREC OBJECT BEGIN")){
				$starttime = $logresult.Substring(0,19)
			}
            elseif ($logresult -Match("SCHEDULEREC STATUS BEGIN")){
                LogEvent $global:LogFile "`t`t`tBackup Result Found : $logResult ---"
                LogEvent $global:LogFile "`t`t`tBackup Result Found : Backup Start Time: $starttime"
            }
            elseif ($logresult -Match("Scheduled event")){
            	LogEvent $global:LogFile "`t`t`tBackup Result Found : $logResult"
            	LogEvent $global:LogFile "`t`t`t----------------------------------------------------------------------------------------" # Close Sched Log Info Block
            }
            else{
    			LogEvent $global:LogFile "`t`t`tBackup Result Found : $logResult"
        	}
        	
        	#Check if elapsed processing time exceeded 24 hours and caused an error
        	if ($logresult -Match("Elapsed processing time:")){
				[int]$BackupTime = [convert]::ToInt32($logresult[-8] + $logresult[-7], 10) #Convert elapsed hours string into an int
					if ($BackupTime -gt 23){
						LogEvent $global:LogFile "`t`t`t`tERROR: Elapsed processing time exceeded 24 hours"
						$ErrorLog.Add("ERROR: Elapsed processing time exceeded 24 hours") | Out-Null
					}
        	}
    	}
    	
    	$volumeErrors = @($fileContents | Where-Object {$_.Contains("drive volume")})
    	if ($volumeErrors.length -ne 0) {
    		foreach ($volumeError in $volumeErrors) {
    		   	LogEvent $global:LogFile "`t`t`t Backup Result Found : $volumeError)"
    		   	$ErrorLog.Add("ERROR: Volume Not Found : $volumeError") | Out-Null
    		}
    	}
    	    	
   	 	# Get last backup date, status of last backup, and date of last successful backup
   	 	foreach($line in $fileContents){
        	$lastbackupdate = "None"
        	$lastbackupstatus = "None"
        	$lastsuccess = "None"
        	if ($logresult -Match("Scheduled event")){
        	 	$lastbackupdate = $logresult.substring(0,19)
        	 	if ($logresults -like "*success*"){
        	 		$lastbackupstatus = "Success"
        	 		$lastsuccess = $logresult.substring(0,19)
        	 	}
        	 	else{
        	 		$lastbackupstatus = "Failed"
        	 	}
        	}
       	}
        	
    	# Check if backup may still be running
    	$running = "true"
    	foreach ($line in $fileContents[-10..1]){
    	    if (($line -like "*command will be executed*") -or ($line -like "*will end*") -or ($line -like "*success*") -or ($line -like "*fail*") -or ($line -like "*next scheduled*")){
    	    	if (($line -like "*will end*") -or ($line -like "*fail*")){
    	    		LogEvent $global:LogFile "ERROR: $line"
    	    		$ErrorLog.Add("ERROR: $line") | Out-Null
    	    	}
   				$running = "false"
    		}
    	}
    	if ($running -match "true"){
    		# A backup may still be running
    		LogEvent $global:LogFile "`t`t`t`tERROR: TSM Backup Client may still be running"
			$ErrorLog.Add("ERROR: TSM Backup Client may still be running") | Out-Null
    	}
    	
    	# Backup stats
    	LogEvent $global:LogFile "------- BACKUP STATS -------"
    	LogEvent $global:LogFile "Date/Time of Last Backup : $lastbackupdate"
    	LogEvent $global:LogFile "Status of Last Backup : $lastbackupstatus"
    	LogEvent $global:LogFile "Date/Time of Last SUCCESSFUL Backup : $lastsuccess"
    	LogEvent $global:LogFile "----------------------------"
   	}
	catch{
		LogEvent $global:LogFile "`tERROR: dsmsched.log not found at : $TSMSchedLog"
		$ErrorLog.Add("ERROR: dsmsched.log not found at : $TSMSchedLog") | Out-Null
	}
}

function LogEvent{
	param(
	[string]$LogFileFullName,
	[string]$EventToLog,
	[switch]$OnScreen=$true
	)
	$LogTime = Get-Date -Format u
	$LogTime = $LogTime -replace "Z", ""
		
	# using this log file : $LogFileFullName"	
	# output to the console
	if ($OnScreen)
		{
		"$LogTime `t $EventToLog"
		}
	#end-if ($OnScreen)
		
	#"$LogTime `t $EventToLog"
		
	# output to the log-file
	
	try
		{
		if (Test-Path $LogFileFullName)
			# file exists
			{
			"$LogTime `t $EventToLog" | Out-File $LogFileFullName -append
			}
		else
			# file does NOT exist
			{
			"$LogTime `t $EventToLog" | Out-File $LogFileFullName
			}
		}
	catch
		{
		"Could not write to log file - '$LogFileFullName'."
		}
}

function CSVEvent{
	param(
	[string]$CSVFileFullName = "nil",
	[string]$ServerName = "nil",
	[string]$IPAddress = "nil",
	[string]$Uptime = "nil",
	[string]$ServiceName = "nil",
	[string]$ServiceState = "nil",
	[string]$StartMode = "nil",
	[string]$NodeName = "nil",
	[string]$OptPath = "nil",
	[string]$SchedPath = "nil",
	[string]$ErrorPath = "nil",
	[System.Collections.ArrayList]$ErrorLog,
	[System.Collections.ArrayList]$RemedyLog
	)
	
    BEGIN{}

    PROCESS{
	# Using this log file : $CSVFileFullName"	
	# Output to the CSV File
    $ErrorString = ($ErrorLog -join "`n")
    $RemedyString = ($RemedyLog -join "`n")

       	$CSVFile = New-Object PSObject
	    	#Add Row/Empty Content
    		$CSVFile | Add-Member NoteProperty ServerName $ServerName -Force #ServerName
			$CSVFile | Add-Member NoteProperty IPAddress $IPAddress -Force #IPAddress
		   	$CSVFile | Add-Member NoteProperty Uptime $Uptime -Force #Uptime
	    	$CSVFile | Add-Member NoteProperty ServiceName $ServiceName -Force #Service
    		$CSVFile | Add-Member NoteProperty ServiceState $ServiceState -Force #Service State
 		    $CSVFile | Add-Member NoteProperty StartMode $StartMode -Force #Start-Mode
 	    	$CSVFile | Add-Member NoteProperty NodeName $NodeName -Force #Node-Name
     		$CSVFile | Add-Member NoteProperty OptPath $OptPath -Force #Opt Path
    		$CSVFile | Add-Member NoteProperty SchedPath $SchedPath -Force #Sched Path
 		    $CSVFile | Add-Member NoteProperty ErrorPath $ErrorPath -Force #Error Path
 		   	$CSVFile | Add-Member NoteProperty ErrorList $ErrorString -Force #Error Master List
            $CSVFile | Add-Member NoteProperty RemedyList $RemedyString -Force #Remedy Master Listz
    	try
    		{
    		if (Test-Path $CSVFileFullName){ # File exist
		    	$CSVFile | Export-Csv $CSVFileFullName -append -Force
	    		}
    		else{ #File does NOT exists
			    MakeCSVFile #Make new file before appending
			    $CSVFile | Export-Csv $CSVFileFullName -append -Force
		    	}
	    	}
    	catch
		    {
	    	"Could not write to CSV file - '$CSVFileFullName'."
    		}
    }
    END{}	
}
                            
#"C:\Users\rlarouche\AppData\Local\Temp\servers.txt"
#Import-Module -force "\\NASDATA201\sharedata\NSUH-IS01\Data\OC Tools\PowerShell-scripts\NwHS-TSMInfo.psm1"
#WW7WB972NOC007
