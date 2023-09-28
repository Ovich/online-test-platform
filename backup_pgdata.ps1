# Backup-RemotePgData.ps1

# Variables for your SSH setup
$sshUser = $env:REMOTE_USER
$sshHost = $env:REMOTE_HOST

# Check if necessary environment variables are set for SSH
if (!$sshUser -or !$sshHost) {
    Write-Host "Please ensure that all necessary environment variables are set for SSH. (REMOTE_USER, REMOTE_HOST)"
    exit 1
}

# Combine user and host into a connection string for ssh commands
$sshTarget = "{0}@{1}" -f $sshUser, $sshHost

# Variables for backup process
$backupFilename = "pgdata_backup.tar.gz"
$backupLocalPath = "./$backupFilename"
$backupRemotePath = "~/$backupFilename"

# Backup the Docker volume on the remote server.
Write-Host "Backing up the PostgreSQL volume on the remote server..."

$backupCommand = @"
docker run --rm \
  --volume onlinetest_pgdata:/volume \
  --volume ~/:/backup \
  alpine \
  tar -czf /backup/$backupFilename -C /volume ./
"@

ssh $sshTarget $backupCommand

# Fetch the backup archive from the remote server to the local machine
Write-Host "Fetching the backup archive from the remote server..."

# Adjusting the SCP target to fetch the backup
$scpTargetForBackup = "{0}@{1}:$backupRemotePath" -f $sshUser, $sshHost
scp $scpTargetForBackup $backupLocalPath

Write-Host "Backup completed and stored at $backupLocalPath"
