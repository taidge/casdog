param([string]$OutputDirectory = (Join-Path $PSScriptRoot '../target/phase13/kerby'))
$ErrorActionPreference = 'Stop'
# Test-only Apache Kerby dependencies; never install a service or change the
# machine Kerberos configuration. Maven Central supplies the published jars.
$destination = [IO.Path]::GetFullPath($OutputDirectory)
New-Item -ItemType Directory -Force -Path $destination | Out-Null
$artifacts = @(
    'kerb-simplekdc','kerb-client','kerb-admin','kerb-server','kerb-common',
    'kerb-core','kerb-identity','kerb-crypto','kerb-util','kerby-asn1',
    'kerby-config','kerby-pkix','kerby-util','kerby-xdr','token-provider'
) | ForEach-Object { "org/apache/kerby/$_/2.1.2/$_-2.1.2.jar" }
$artifacts += @(
    'org/slf4j/slf4j-api/1.7.36/slf4j-api-1.7.36.jar',
    'org/slf4j/slf4j-simple/1.7.36/slf4j-simple-1.7.36.jar',
    'com/nimbusds/nimbus-jose-jwt/10.9.1/nimbus-jose-jwt-10.9.1.jar',
    'org/jline/jline/3.30.6/jline-3.30.6.jar',
    'org/jboss/xnio/xnio-api/3.8.17.Final/xnio-api-3.8.17.Final.jar'
)
foreach ($artifact in $artifacts) {
    $url = "https://repo.maven.apache.org/maven2/$artifact"
    $path = Join-Path $destination ([IO.Path]::GetFileName($artifact))
    if (-not (Test-Path -LiteralPath $path)) { Invoke-WebRequest $url -OutFile $path }
    $expected = (Invoke-WebRequest "$url.sha1").Content.Trim().ToUpperInvariant()
    $actual = (Get-FileHash -LiteralPath $path -Algorithm SHA1).Hash
    if ($expected -ne $actual) { throw "Maven checksum mismatch for $artifact" }
}
Write-Output "CASDOG_KERBY_CLASSPATH=$destination/*"
