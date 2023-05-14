$timeSelector = [System.Diagnostics.Eventing.Reader.EventLogPropertySelector]::new([string[]]@('Event/EventData/Data[@Name="UtcTime"]'))
$parentCmdSelector = [System.Diagnostics.Eventing.Reader.EventLogPropertySelector]::new([string[]]@('Event/EventData/Data[@Name="ParentCommandLine"]'))
$parentProcIdSelector = [System.Diagnostics.Eventing.Reader.EventLogPropertySelector]::new([string[]]@('Event/EventData/Data[@Name="ParentProcessId"]'))
$processIdSelector = [System.Diagnostics.Eventing.Reader.EventLogPropertySelector]::new([string[]]@('Event/EventData/Data[@Name="ProcessId"]'))
$cmdLineSelector = [System.Diagnostics.Eventing.Reader.EventLogPropertySelector]::new([string[]]@('Event/EventData/Data[@Name="CommandLine"]'))
$imageSelector = [System.Diagnostics.Eventing.Reader.EventLogPropertySelector]::new([string[]]@('Event/EventData/Data[@Name="Image"]'))
$tgtFileNameSelector = [System.Diagnostics.Eventing.Reader.EventLogPropertySelector]::new([string[]]@('Event/EventData/Data[@Name="TargetFilename"]'))

Get-WinEvent -FilterHashtable @{Path="..Path\to\file\6-sysmon.evtx"} | ForEach-Object {
    $time = $_.GetPropertyValues($timeSelector)[0]
    $parentCmd = $_.GetPropertyValues($parentCmdSelector)[0]
    $parentProcId = $_.GetPropertyValues($parentProcIdSelector)[0]
    $processId = $_.GetPropertyValues($processIdSelector)[0]
    $cmdLine = $_.GetPropertyValues($cmdLineSelector)[0]
    $image = $_.GetPropertyValues($imageSelector)[0]   
    $tgtFileName = $_.GetPropertyValues($tgtFileNameSelector)[0]

    if (![string]::IsNullOrWhiteSpace($cmdLine) -or ![string]::IsNullOrWhiteSpace($tgtFileName)) {
        [pscustomobject]@{Time=$time; parentCmd=$parentCmd; ParentProcId=$parentProcId; ProcessId=$processId; cmdLine=$cmdLine;  Image=$image; TargetFileName=$tgtFileName }
    }
} | sort time | Out-GridView
