# Read-only baseline serialization and stable recovery comparison.
# V21 adds permanent hardware address + network-address override diagnostics.
# The effective/current MAC comparison remains strict; no MAC-drift waiver is introduced.
# Adapter InterfaceIndex may legitimately change across disable/enable and is deliberately excluded.
Set-StrictMode -Version 2.0

function Get-P5GRequiredProperty {
    param([object]$Object, [string]$Name)
    $property = $Object.PSObject.Properties[$Name]
    if ($null -eq $property -or $null -eq $property.Value) { throw "NETWORK_SCHEMA_REQUIRED_PROPERTY:$Name" }
    return $property.Value
}

function Get-P5GOptionalProperty {
    param([object]$Object, [string]$Name)
    $property = $Object.PSObject.Properties[$Name]
    if ($null -eq $property -or $null -eq $property.Value) { return '' }
    return [string]$property.Value
}

function Get-P5GNetworkAddressOverride {
    param([string]$Name)
    try {
        $property = @(Get-NetAdapterAdvancedProperty -Name $Name -RegistryKeyword 'NetworkAddress' -ErrorAction Stop | Select-Object -First 1)
        if ($property.Count -eq 1) { return [string]$property[0].DisplayValue }
    } catch {}
    return ''
}

function ConvertTo-P5GRouteRecord {
    param([object]$Route)
    $optional = [ordered]@{}
    foreach ($name in @('PolicyStore','Store','Protocol','Publish','State','InterfaceMetric','CompartmentId')) {
        $property = $Route.PSObject.Properties[$name]
        if ($null -ne $property) { $optional[$name] = [string]$property.Value }
    }
    $family = [string](Get-P5GRequiredProperty $Route 'AddressFamily')
    $prefix = [string](Get-P5GRequiredProperty $Route 'DestinationPrefix')
    if (@('IPv4','IPv6') -cnotcontains $family) { throw "NETWORK_SCHEMA_ADDRESS_FAMILY:$family" }
    return [pscustomobject][ordered]@{
        AddressFamily=$family
        DestinationPrefix=$prefix
        InterfaceAlias=[string](Get-P5GRequiredProperty $Route 'InterfaceAlias')
        InterfaceIndex=[int](Get-P5GRequiredProperty $Route 'InterfaceIndex')
        NextHop=[string](Get-P5GRequiredProperty $Route 'NextHop')
        RouteMetric=[int](Get-P5GRequiredProperty $Route 'RouteMetric')
        IsDefaultRoute=($prefix -ceq '0.0.0.0/0' -or $prefix -ceq '::/0')
        OptionalProperties=$optional
    }
}

function Get-P5GRouteIdentity {
    param([object]$Route)
    # InterfaceIndex is deliberately excluded: Windows can re-enumerate it after disable/enable.
    return (@(
        [string]$Route.AddressFamily,
        [string]$Route.DestinationPrefix,
        [string]$Route.InterfaceAlias,
        [string]$Route.NextHop,
        [string]$Route.RouteMetric
    ) | ConvertTo-Json -Compress)
}

function Get-P5GNetworkBaseline {
    param([string]$AttemptID, [string]$RunID)
    $adapters = @(Get-NetAdapter -Physical -ErrorAction Stop | ForEach-Object {
        [pscustomobject][ordered]@{
            Name=[string]$_.Name
            InterfaceDescription=[string]$_.InterfaceDescription
            InterfaceIndex=[int]$_.ifIndex
            MacAddress=([string]$_.MacAddress).ToUpperInvariant()
            PermanentAddress=(Get-P5GOptionalProperty $_ 'PermanentAddress').ToUpperInvariant()
            NetworkAddressOverride=(Get-P5GNetworkAddressOverride -Name ([string]$_.Name))
            NdisPhysicalMedium=(Get-P5GOptionalProperty $_ 'NdisPhysicalMedium')
            InitialStatus=[string]$_.Status
        }
    })
    $routes = @(Get-NetRoute -ErrorAction Stop | ForEach-Object { ConvertTo-P5GRouteRecord $_ })
    return [pscustomobject][ordered]@{
        schema_version='6.1'
        AttemptID=$AttemptID
        RunID=$RunID
        CapturedUtc=[DateTime]::UtcNow.ToString('o')
        PhysicalAdapters=$adapters
        OriginallyUpAdapters=@($adapters | Where-Object { $_.InitialStatus -ceq 'Up' })
        Routes=$routes
        DefaultRoutes=@($routes | Where-Object { $_.IsDefaultRoute })
    }
}

function Test-P5GNetworkRestored {
    param([object]$Baseline, [object[]]$CurrentPhysicalAdapters, [object[]]$CurrentRoutes, [object]$PersistedState)

    if ($PersistedState.vms_safe -isnot [bool] -or -not $PersistedState.vms_safe) {
        return [pscustomobject][ordered]@{restored=$false;reason='NETWORK_RESTORE_FORBIDDEN_WITHOUT_PERSISTED_VM_SAFE'}
    }

    # Host-network recovery is an adapter-restoration gate, not a connectivity gate.
    # The workload and telemetry have already completed under isolation. A laptop may
    # legitimately switch between Wi-Fi, mobile hotspot, Ethernet, or have no associated
    # network/DHCP lease/default route/Internet access after recovery. Acceptance requires
    # only that at least one physical adapter is enabled (Status='Up'); exact adapter name,
    # MAC, description, permanent address, or route identity are intentionally not checked
    # because Windows can re-enumerate adapters after VM snapshot revert and disable/enable.
    $upAdapters = @($CurrentPhysicalAdapters | Where-Object { [string]$_.InitialStatus -ceq 'Up' })
    if ($upAdapters.Count -eq 0) {
        return [pscustomobject][ordered]@{restored=$false;reason='NO_PHYSICAL_ADAPTER_UP_AFTER_RESTORE'}
    }

    return [pscustomobject][ordered]@{restored=$true;reason='PASS_ADAPTER_UP'}
}

function Assert-P5GNetworkRestored {
    param([object]$Baseline, [object[]]$CurrentPhysicalAdapters, [object[]]$CurrentRoutes, [object]$PersistedState)
    $check=Test-P5GNetworkRestored $Baseline $CurrentPhysicalAdapters $CurrentRoutes $PersistedState
    if (-not [bool]$check.restored) { throw ([string]$check.reason) }
    return $true
}
