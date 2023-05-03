<#
# INFO: [System.Security.AccessControl.FileSystemRights]
+-------------+------------------------------+------------------------------+---------------------------------------------------------------+
|    Value    |             Name             |            Alias             |                         Alias                                 |
+-------------+------------------------------+------------------------------+---------------------------------------------------------------+
| -2147483648 | GENERIC_READ                 | GENERIC_READ                 |                                                               |
|           1 | ReadData                     | ListDirectory                | Ordner auflisten                                              |
|           1 | ReadData                     | ReadData                     | Daten Lesen                                                   |
|           2 | CreateFiles                  | CreateFiles                  | Dateien erstellen                                             |
|           2 | CreateFiles                  | WriteData                    | Daten Schreiben                                               |
|           4 | AppendData                   | AppendData                   | Daten anhängen                                                |
|           4 | AppendData                   | CreateDirectories            | Ordner erstellen                                              |
|           8 | ReadExtendedAttributes       | ReadExtendedAttributes       | Erweiterte Attribute Lesen                                    |
|          16 | WriteExtendedAttributes      | WriteExtendedAttributes      | Datei Ausführen                                               |
|          32 | ExecuteFile                  | ExecuteFile                  | Ordner durchsuchen                                            |
|          32 | ExecuteFile                  | Traverse                     | Datei Ausführen                                               |
|          64 | DeleteSubdirectoriesAndFiles | DeleteSubdirectoriesAndFiles | Unterordner und Dateien löschen                               |
|         128 | ReadAttributes               | ReadAttributes               | Attribute lesen                                               |
|         256 | WriteAttributes              | WriteAttributes              | Attribute Schreiben                                           |
|         278 | Write                        | Write                        | Schreiben (einfache Ansicht)                                  |
|       65536 | Delete                       | Delete                       | löschen                                                       |
|      131072 | ReadPermissions              | ReadPermissions              | Berechtigung Lesen                                            |
|      131209 | Read                         | Read                         | Lesen (einfache Ansicht)                                      |
|      131241 | ReadAndExecute               | ReadAndExecute               | Lesen,Ausführen (Ordnerinhalt anzeigen) (einfache Ansicht)    |
|      197055 | Modify                       | Modify                       | Ändern (einfache Ansicht)                                     |
|      262144 | ChangePermissions            | ChangePermissions            | Berechtigung ändern                                           |
|      524288 | TakeOwnership                | TakeOwnership                | Besitz übernehmen                                             |
|     1048576 | Synchronize                  | Synchronize                  |                                                               |
|     2032127 | FullControl                  | FullControl                  | Vollzugriff                                                   |
|   268435456 | GENERIC_ALL                  | GENERIC_ALL                  |                                                               |
|   536870912 | GENERIC_EXECUTE              | GENERIC_EXECUTE              |                                                               |
|  1073741824 | GENERIC_WRITE                | GENERIC_WRITE                |                                                               |
+-------------+------------------------------+------------------------------+---------------------------------------------------------------+
# INFO: [System.Security.AccessControl.InheritanceFlags]
+-------------+------------------------------+----------------------------------------------------------------------------------------------+
|    Value    |             Name             |                                      Alias                                                   |
+-------------+------------------------------+----------------------------------------------------------------------------------------------+
|           1 | ContainerInherit             | Der ACE wird von untergeordneten Containerobjekten geerbt.                                   |
|           0 | None                         | Der ACE wird nicht von untergeordneten Objekten geerbt.                                      |
|           2 | ObjectInherit                | Der ACE wird von untergeordneten Endobjekten geerbt.                                         |
+-------------+------------------------------+----------------------------------------------------------------------------------------------+
# INFO: [System.Security.AccessControl.PropagationFlags]
+-------------+------------------------------+----------------------------------------------------------------------------------------------+
|    Value    |             Name             |                                      Alias                                                   |
+-------------+------------------------------+----------------------------------------------------------------------------------------------+
|           2 | InheritOnly                  | Gibt an, dass der ACE nur an untergeordnete Objekte weitergegeben wird. Dies schließt untergeordnete Container- und Endobjekte ein.
|           0 | None                         | Gibt an, dass keine Vererbungsflags festgelegt sind.                                         |
|           1 | NoPropagateInherit           | Gibt an, dass der ACE nicht an untergeordnete Objekte weitergegeben wird.                    |
+-------------+------------------------------+----------------------------------------------------------------------------------------------+
# INFO: [System.Security.AccessControl.AccessControlType]
+-------------+------------------------------+----------------------------------------------------------------------------------------------+
|    Value    |             Name             |                                      Alias                                                   |
+-------------+------------------------------+----------------------------------------------------------------------------------------------+
|           0 | Allow                        | Mithilfe des AccessRule-Objekts wird der Zugriff auf ein gesichertes Objekt zugelassen.      |
|           1 | Deny                         | Mithilfe des AccessRule-Objekts wird der Zugriff auf ein gesichertes Objekt verweigert.      |
+-------------+------------------------------+----------------------------------------------------------------------------------------------+
#>

class NiceFileSystemAccessRule {
    [System.Security.AccessControl.FileSystemRights]$FileSystemRights
    [System.Security.AccessControl.InheritanceFlags]$InheritanceFlags
    [System.Security.AccessControl.PropagationFlags]$PropagationFlags
    [System.Security.AccessControl.AccessControlType]$AccessControlType

    [System.Security.AccessControl.FileSystemAccessRule] NewFSAR($ACLGroupName) {
        return [System.Security.AccessControl.FileSystemAccessRule]::new($ACLGroupName, $this.FileSystemRights, $this.InheritanceFlags, $this.PropagationFlags, $this.AccessControlType)
    }
    <#
        INFO: Create a new NiceFileSystemAccessRule with NewFSAR()
        $ReadData = [NiceFileSystemAccessRule]::new()
        $ReadData = [NiceFileSystemAccessRule]@{
            FileSystemRights  = 1
            AccessControlType = 0
            InheritanceFlags  = 3
            PropagationFlags  = 1
        }
        $ReadData.NewFSAR($ACLGroupName)
    #>
    [System.Security.AccessControl.FileSystemAccessRule] Default() {
        $FileSystemRights2 = $this.FileSystemRights = 2032127   # ReadAndExecute, Synchronize
        $InheritanceFlags2 = $this.InheritanceFlags = 3         # \\__ Nur Unterordner und Dateien
        $PropagationFlags2 = $this.PropagationFlags = 0         # //
        $AccessControlType2 = $this.AccessControlType = 0       # Zulassen
        return [System.Security.AccessControl.FileSystemAccessRule]::new('VORDEFINIERT\Administratoren', $FileSystemRights2, $InheritanceFlags2, $PropagationFlags2, $AccessControlType2)
    }
    [System.Security.AccessControl.FileSystemAccessRule] RO($ACLGroupName) {
        $FileSystemRights2 = $this.FileSystemRights = 1179817   # ReadAndExecute, Synchronize
        $InheritanceFlags2 = $this.InheritanceFlags = 3         # \\__ Nur Unterordner und Dateien
        $PropagationFlags2 = $this.PropagationFlags = 2         # //
        $AccessControlType2 = $this.AccessControlType = 0       # Zulassen
        return [System.Security.AccessControl.FileSystemAccessRule]::new($ACLGroupName, $FileSystemRights2, $InheritanceFlags2, $PropagationFlags2, $AccessControlType2)
    }
    [System.Security.AccessControl.FileSystemAccessRule] RW($ACLGroupName) {
        $FileSystemRights2 = $this.FileSystemRights = 131519    # Write, ReadAndExecute
        $InheritanceFlags2 = $this.InheritanceFlags = 3         # \\__ Nur Unterordner und Dateien
        $PropagationFlags2 = $this.PropagationFlags = 2         # //
        $AccessControlType2 = $this.AccessControlType = 0       # Zulassen
        return [System.Security.AccessControl.FileSystemAccessRule]::new($ACLGroupName, $FileSystemRights2, $InheritanceFlags2, $PropagationFlags2, $AccessControlType2)
    }
    # TODO: Create more Methods of FileSystemAccessRules
}

function Set-NiceFileSystemAccessRule {
    <#
    .SYNOPSIS
        Short description
    .DESCRIPTION
        Long description
    .EXAMPLE
        Set-NiceFileSystemAccessRule -DirectoryGroupObject $myObject -Verbose
    .EXAMPLE
        Set-NiceFileSystemAccessRule -Path 'C:\tmp\test2' -Group 'Benutzer' -Verbose
    .NOTES
        Functionname: Set-NiceFileSystemAccessRule
        Author: Stefan Jansen
        Modified date: 10.04.2023
        Version : 1.0
    #>
    [CmdletBinding(DefaultParameterSetName = 'WithAObject', SupportsShouldProcess, ConfirmImpact = 'High')]
    param (
        [parameter(Mandatory = $true,
            ParameterSetName = "WithAObject")]
        [PSCustomObject]$DirectoryGroupObject,
    
        [parameter(Mandatory = $true,
            ParameterSetName = "ManuallyPathAndGroup",
            HelpMessage = 'Path where the permission should be set')]
        [String]$Path,
    
        [parameter(Mandatory = $true,
            ParameterSetName = "ManuallyPathAndGroup",
            HelpMessage = 'Group for authorization')]
        [String]$Group,

        [parameter(Mandatory = $false,
            ParameterSetName = "ManuallyPathAndGroup",
            HelpMessage = 'Group for authorization')]
        [String]$FileSystemAccessRule

    )
    begin {
        Write-Verbose 'Set FileSystemAccessRule to specific folder'
    }
    process {
        if ($DirectoryGroupObject) {
            Write-Verbose 'Use ParameterSet "WithAObject"'
            Write-Verbose 'Group Object by "Path"'
            $GroupObjectByDirectory = $DirectoryGroupObject | Group-Object 'Path'
            foreach ($GroupObject in $GroupObjectByDirectory) {
                Write-Verbose "Set FileSystemAccessRule to Path: $($GroupObject.Name)"
                try {
                    $CurrentACL = Get-Acl -Path $GroupObject.Name

                    if ($CurrentACL.AreAccessRulesProtected) { 
                        $CurrentACL.Access | ForEach-Object { $CurrentACL.purgeaccessrules($_.IdentityReference) } 
                    }
                    else {
                        $isProtected = $true 
                        $preserveInheritance = $false
                        $CurrentACL.SetAccessRuleProtection($isProtected, $preserveInheritance) 
                    }

                    $CurrentACL.SetAccessRule([NiceFileSystemAccessRule]::new().Default())
                    foreach ($Item in $GroupObject.Group) {
                        # TODO : Permission filter by group name
                        $PermissionIdentifier = $Item.Group.Split('-')[3]
                        switch ($PermissionIdentifier) {
                            'TF' {
                                [System.Security.AccessControl.FileSystemAccessRule]$FileSystemAccessRule = [NiceFileSystemAccessRule]::new().TF($Item.Group)
                                Write-Verbose "Used group for FileSystemAccessRule: $($Item.Group)"
                                Write-Verbose "FileSystemAccessRule:"
                                if ($VerbosePreference) {
                                    Write-Output -Verbose $($FileSystemAccessRule)
                                }
                                $CurrentACL.AddAccessRule($FileSystemAccessRule)
                                $FileSystemAccessRule = $null
                            }
                            'RO' {
                                [System.Security.AccessControl.FileSystemAccessRule]$FileSystemAccessRule = [NiceFileSystemAccessRule]::new().RO($Item.Group)
                                Write-Verbose "Used group for FileSystemAccessRule: $($Item.Group)"
                                Write-Verbose "FileSystemAccessRule:"
                                if ($VerbosePreference) {
                                    Write-Output -Verbose $($FileSystemAccessRule)
                                }
                                $CurrentACL.AddAccessRule($FileSystemAccessRule)
                                $FileSystemAccessRule = $null
                            }
                            'RW' {
                                [System.Security.AccessControl.FileSystemAccessRule]$FileSystemAccessRule = [NiceFileSystemAccessRule]::new().RW($Item.Group)
                                Write-Verbose "Used group for FileSystemAccessRule: $($Item.Group)"
                                Write-Verbose "FileSystemAccessRule:"
                                if ($VerbosePreference) {
                                    Write-Output -Verbose $($FileSystemAccessRule)
                                }
                                $CurrentACL.AddAccessRule($FileSystemAccessRule)
                                $FileSystemAccessRule = $null
                            }
                        }
                    }
                    Set-Acl $CurrentACL -Path $GroupObject.Name -Confirm:$ConfirmPreference -WhatIf:$WhatIfPreference -Verbose:$VerbosePreference
                }
                catch {
                    $_
                }
            }
        }
        if ($Path) {
            try {
                if ($FileSystemAccessRule) {
                    Write-Verbose 'Use ParameterSet "ManuallyPathAndGroup"'
                    $CurrentACL = Get-Acl -Path $Path
                    # TODO : Permission filter by group name
                    $CurrentACL.AddAccessRule([NiceFileSystemAccessRule]::new().RW($Group))
                    Write-Verbose "Used group for FileSystemAccessRule: $($Group)"
                    Write-Verbose "FileSystemAccessRule:"
                    if ($VerbosePreference) {
                        Write-Output -Verbose $([NiceFileSystemAccessRule]::new().RW($Group))
                    }
                    Set-Acl $CurrentACL -Path $Path -Confirm:$ConfirmPreference -WhatIf:$WhatIfPreference -Verbose:$VerbosePreference
                }
                Write-Verbose 'Use ParameterSet "ManuallyPathAndGroup"'
                $CurrentACL = Get-Acl -Path $Path
                # TODO : Permission filter by group name
                $CurrentACL.AddAccessRule([NiceFileSystemAccessRule]::new().RW($Group))
                Write-Verbose "Used group for FileSystemAccessRule: $($Group)"
                Write-Verbose "FileSystemAccessRule:"
                if ($VerbosePreference) {
                    Write-Output -Verbose $([NiceFileSystemAccessRule]::new().RW($Group))
                }
                Set-Acl $CurrentACL -Path $Path -Confirm:$ConfirmPreference -WhatIf:$WhatIfPreference -Verbose:$VerbosePreference
            }
            catch {
                $_
            }
        }
    }
}

