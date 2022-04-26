# UserImport.ps1
#
# A Windows Powershell script to read user details from a CSV file and import 
# them to a Sophos Firewall using the XML API
#
# Before using this script, you need to enable XML API access on your 
# firewall for the IP address of the Windows computer that you're going 
# to run it on.
#
# In the web admin console of your Firewall, go to 
#        System > Backup & Firmware > API
# Ensure that the 'Enabled' checkbox is set for API configuration and that 
# the IP address of your Windows computer is in the 'Allowed IP address' list
#
# Run the script from the Windows Powershell prompt as follows:
# .\UserImport.ps1 -infile <csv file name> -fw <target firewall>
# 
# Other parameters are optional:
#  -username    Admin account name to use - defaults to 'admin'
#  -password    Admin account password - a prompt will be shown if you don't 
#               provide this at the command line
#  -operation   Defaults to 'set' but 'update' can be used if modifying 
#               existing user objects
#  -lang        If your firewall has been reset with a default configuration 
#               language other than English, specify the language here to use
#               translated names for built-in policies and object.
#               See the list of language codes below.
#  -validate    If set, validate the TLS cert of the firewall. Defaults to
#               not validating because SFOS uses a self-signed certificate
#               by default.
#

param (
    [string]$infile, 
    [string]$fw = $null, 
    [string]$username='admin', 
    [string]$password = $( 
        if(-not [string]::IsNullOrEmpty($fw)) 
        { 
            $spw= Read-Host -AsSecureString "Password for" `
                                            "'$($username)' on $($fw)"
            [pscredential]::new('jpgr', $spw).GetNetworkCredential().Password
        } 
                ), 
    [string]$operation='set', 
    [string]$lang="EN",
    [switch]$validate=$false
       )

# Set up callback to ignore certificate validation because most Firewalls
# run with the default self-signed certificates.

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

    if (-not ([System.Management.Automation.PSTypeName]'ServerCertificateValidationCallback').Type)
    {
        $certCallback = @"
    using System;
    using System.Net;
    using System.Net.Security;
    using System.Security.Cryptography.X509Certificates;
    public class ServerCertificateValidationCallback
    {
        public static void Ignore()
        {
            if(ServicePointManager.ServerCertificateValidationCallback ==null)
            {
                ServicePointManager.ServerCertificateValidationCallback += 
                    delegate
                    (
                        Object obj, 
                        X509Certificate certificate, 
                        X509Chain chain, 
                        SslPolicyErrors errors
                    )
                    {
                        return true;
                    };
            }
        }
        public static void UnIgnore()
        {
            ServicePointManager.ServerCertificateValidationCallback = null;
        }
    }
"@
        Add-Type $certCallback
     }
if ( $validate ) 
{
    [ServerCertificateValidationCallback]::UnIgnore()
} else {
    [ServerCertificateValidationCallback]::Ignore()
}

# Set up data and functions for later

$langcode = @{
    "EN" = 0;		# English
    "DE" = 1;		# German
    "ES" = 2;		# Spanish
    "FR" = 3;		# French
    "IT" = 4;		# Italian
    "JP" = 5;		# Japanese
    "KR" = 6;		# Korean
    "PT" = 7;		# Portuguese (Brazilian)
    "RU" = 8;		# Russian
    "ZH-CN" = 9;    # Simplified Chinese
    "ZH-TW" = 10	# Traditional Chinese
}

$transobj = @{
    "Open Group" =
        "Open Group", "Offene Gruppe", "Grupo abierto",
         "Groupe ouvert", "Gruppo aperto", "オープングループ", "공개 그룹",
         "Grupo aberto", "Открытая группа", "开放组,開啟群組";
    "All the time" =
        "All the time", "Jederzeit", "Siempre", "Tout le temps",
         "Sempre", "常時", "항상", "O tempo todo", "Все время", "一直,隨時";
    "Allowed all the time" =
        "Allowed all the time", "Immer erlaubt", "Permitido siempre",
         "Toujours autorisé", "Sempre consentito", "常に許可", "항상 허용됨",
         "Sempre permitido", "Разрешены все время", "所有时间允许,任何時間都允許";
    "Unlimited Internet Access" =
         "Unlimited Internet Access", "Unbegrenzter Internetzugriff",
         "Acceso a Internet ilimitado", "Accès Internet illimité",
         "Accesso illimitato a Internet", "インターネットアクセスを制限しない",
         "무제한 인터넷 액세스", "Acesso à Internet ilimitado",
         "Безлимитный Интернет-доступ", "不受限制的互联网访问", "無限制網際網路存取"
}

$required=@("Name","Username","Password","Email Address","Group")

# Function to convert strings that are translated on Firewalls that have been
# switched to a different language.
function Get-Translation {
    param ( [string]$phrase, [string]$lang )
    $output=$phrase
    if ($langcode.ContainsKey($lang))
    {
        if ($transobj.ContainsKey($phrase))
        {
            $output=$transobj.$phrase[$langcode.$lang]
        }
    } 
    $output
}

# Main stream of execution starts here
# Check command-line parameters

if ($operation -ne "set" -and $operation -ne 'update')
{
    write-host "Invalid operation: Must be 'set' or 'update', not " `
               "'$($operation)'"
    exit
}


if (-not $langcode.ContainsKey($lang))
{
    write-host "Unsupported language: You entered '$($lang)'"
    write-host "Valid options: $($langcode.keys -join ', ')"
    exit
}

# Open the CSV file for reading - you might want to change some parameters 
# here if your CSV file is non-standard

$csv=Import-csv -path $infile -Encoding utf8

# Check that the CSV file has the required columns
$validCsv=$true
$csvColumns=$csv[0].psobject.Properties.Name

foreach($col in $required) 
{
    if( -not ($csvColumns -contains $col) ) 
    {
        write-host "Missing column: $col"
        $validCsv=$false
    }
}

if( -not $validCsv)
{
    write-host "CSV file $($infile) does not contain the required fields"
    write-host "Required columns are: $($required -join ", ")"
    write-host "Your file has: $($csvColumns -join ", ")"
    exit
}

# Now get a temp file name to write the XML API request file
$xmlfile=[System.IO.Path]::GetTempFileName()
#[string]$xmlfile="$(Get-Location)\out.xml"
# write-host $xmlfile

$xmlout = New-Object System.Xml.XmlTextWriter($xmlfile, $Null )

$xmlout.Formatting = 'Indented'
$xmlout.Indentation = 1

# Write the login section of the XMLAPI call

$xmlout.WriteStartDocument()
$xmlout.WriteStartElement('Request')
$xmlout.WriteStartElement('Login')
$xmlout.WriteElementString('Username', $username)
$xmlout.WriteElementString('Password', $password)
$xmlout.WriteEndElement()

# Now start the main 'Set' element

$xmlout.WriteStartElement('Set')
$xmlout.WriteAttributeString('operation', $operation)

$serial=1
$readItems=@{}

# Loop through the CSV file line-by-line and generate XML for each line

foreach($line in $csv)
{
    $xmlout.WriteStartElement('User')
    $xmlout.WriteAttributeString('transactionid', $serial)
    $xmlout.WriteElementString('Username',$line.Username)
    $xmlout.WriteElementString('Name', $line.Name)
    $xmlout.WriteElementString('Password', $line.Password)
    $xmlout.WriteStartElement('EmailList')
    $xmlout.WriteElementString('EmailID', $line.'Email Address')
    $xmlout.WriteEndElement()
   
 
    $xmlout.WriteElementString('Group', 
                ( Get-Translation -phrase $line.Group -lang $lang) )
   
    $xmlout.WriteElementString('SurfingQuotaPolicy', 
                $transobj.'Unlimited Internet Access'[$langcode.$lang])
    $xmlout.WriteElementString('AccessTimePolicy', 
                $transobj.'Allowed all the time'[$langcode.$lang])
    $xmlout.WriteElementString('DataTransferPolicy', "")
    $xmlout.WriteElementString('QoSPolicy',"")
    $xmlout.WriteElementString('SSLVPNPolicy',"")
    $xmlout.WriteElementString('Status',"Active")
    $xmlout.WriteElementString('L2TP',"Disable")
    $xmlout.WriteElementString('PPTP',"Disable")
    $xmlout.WriteElementString('CISCO',"Disable")
    $xmlout.WriteElementString('QuarantineDigest',"Disable")
    $xmlout.WriteElementString('MACBinding',"Disable")
    $xmlout.WriteElementString('LoginRestriction',"UserGroupNode")
    $xmlout.WriteElementString('ScheduleForApplianceAccess',
                $transobj.'All the time'[$langcode.$lang])
    $xmlout.WriteElementString('LoginRestrictionForAppliance', "")
    $xmlout.WriteElementString('IsEncryptCert', "Disable")
    $xmlout.WriteElementString('SimultaneousLoginsGlobal', "Enable")
    
    $xmlout.WriteEndElement()

    # Remember key details for displaying when processing the API call result 
    $readItems.add($serial++, "$($line.Name) ($($line.Username))")
}

$xmlout.WriteEndElement()
$xmlout.WriteEndDocument()
$xmlout.Flush()
$xmlout.Close()

write-host "Read $($serial-1) users from $($infile)"
write-host

# Display the XML content on screen

# Send the XML to the firewall if one was specified
if (-not [string]::IsNullOrEmpty($fw)) {
  

    $uri="https://$($fw):4444/webconsole/APIController"

    write-host "Posting to $($uri)"

    $resp=Invoke-WebRequest -Uri $uri  -Method Post `
                      -Body @{"reqxml" = Get-Content -Path $xmlfile -Raw}

# Check the response XML for information about the result
    if (-not [string]::IsNullOrEmpty($resp.Content)) 
    {
        Write-host "Returned $($resp.StatusCode) - $($resp.StatusDescription)"
        write-host $resp.Content

        [xml]$resxml=$resp.Content
        Select-Xml -Xml $resxml -XPath '/Response/User' | ForEach-Object {
            $thisid=[int]$_.node.transactionid
            write-host "$($thisid) - $($readItems.$thisid) : " `
                       "$($_.node.status.'#text') ($($_.node.status.code))"
        }
    }
} 
else 
{
    write-host "No firewall specified - here's the XML I would have sent:"
    Get-Content -Encoding UTF8 $xmlfile 
}

# Clean up by deleting the generated XML

Remove-Item $xmlfile