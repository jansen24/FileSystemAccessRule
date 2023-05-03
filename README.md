# FileSystemAccessRule

```Powershell
$myObject = @()
$myObject += [PSCustomObject]@{
    Path  = 'C:\tmp\test'
    Group = 'Benutzer'
}
$myObject += [PSCustomObject]@{
    Path  = 'C:\tmp\test'
    Group = 'Benutzer'
}
$myObject += [PSCustomObject]@{
    Path  = 'C:\tmp\test2'
    Group = 'Benutzer'
}

Set-NiceFileSystemAccessRule -DirectoryGroupObject $myObject -Verbose -Confirm:$false
Set-NiceFileSystemAccessRule -Path 'C:\tmp\test2' -Group 'Benutzer' -Verbose
```
