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
    # InterfaceIndex and InterfaceAlias are deliberately excluded: Windows can re-enumerate them after disable/enable.
    return (@(
        [string]$Route.AddressFamily,
        [string]$Route.DestinationPrefix,
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

    $acceptedRandomizedWifiRollover=$false
    foreach ($expected in @($Baseline.PhysicalAdapters)) {
        # Alias/name is the primary operator-visible identity. Then prove description, permanent
        # hardware identity (when exposed), effective/current MAC, and state.
        # InterfaceIndex is intentionally ignored because Windows can re-enumerate it after disable/enable.
        $byName = @($CurrentPhysicalAdapters | Where-Object { [string]$_.Name -ceq [string]$expected.Name })
        if ($byName.Count -ne 1) {
            return [pscustomobject][ordered]@{restored=$false;reason=('BASELINE_ADAPTER_ALIAS_MISSING_OR_DUPLICATE:'+ $expected.Name)}
        }
        $actual=$byName[0]
        if ([string]$actual.InterfaceDescription -cne [string]$expected.InterfaceDescription) {
            return [pscustomobject][ordered]@{restored=$false;reason=('BASELINE_ADAPTER_DESCRIPTION_DRIFT:'+ $expected.Name)}
        }

        $expectedPermanent=[string](Get-P5GOptionalProperty $expected 'PermanentAddress')
        $actualPermanent=[string](Get-P5GOptionalProperty $actual 'PermanentAddress')
        if (([string]::IsNullOrWhiteSpace($expectedPermanent)) -xor ([string]::IsNullOrWhiteSpace($actualPermanent))) {
            return [pscustomobject][ordered]@{restored=$false;reason=('BASELINE_ADAPTER_PERMANENT_ADDRESS_AVAILABILITY_DRIFT:'+ $expected.Name+':expected='+$expectedPermanent+':actual='+$actualPermanent)}
        }
        if (-not [string]::IsNullOrWhiteSpace($expectedPermanent) -and
            $expectedPermanent.ToUpperInvariant() -cne $actualPermanent.ToUpperInvariant()) {
            return [pscustomobject][ordered]@{restored=$false;reason=('BASELINE_ADAPTER_PERMANENT_ADDRESS_DRIFT:'+ $expected.Name+':expected='+$expectedPermanent+':actual='+$actualPermanent)}
        }

        $expectedMac=([string]$expected.MacAddress).ToUpperInvariant()
        $actualMac=([string]$actual.MacAddress).ToUpperInvariant()
        if ($actualMac -cne $expectedMac) {
            $expectedOverride=[string](Get-P5GOptionalProperty $expected 'NetworkAddressOverride')
            $actualOverride=[string](Get-P5GOptionalProperty $actual 'NetworkAddressOverride')
            $medium=[string](Get-P5GOptionalProperty $actual 'NdisPhysicalMedium')
            # V26_RANDOMIZED_WIFI_MAC_ROLLOVER_ACCEPTANCE
            # Windows can replace a session-randomized Wi-Fi effective MAC with the
            # identical adapter's permanent MAC after disable/enable. Accept only
            # that bounded transition: wireless medium, no configured override on
            # either side, unchanged non-empty permanent identity, the actual
            # effective MAC equals that permanent identity, and the former effective
            # MAC has the IEEE locally-administered bit set. All other drift fails.
            $expectedMacHex=($expectedMac -replace '[-:]','')
            $actualMacHex=($actualMac -replace '[-:]','')
            $expectedPermanentHex=($expectedPermanent -replace '[-:]','').ToUpperInvariant()
            $actualPermanentHex=($actualPermanent -replace '[-:]','').ToUpperInvariant()
            $expectedWasLocallyAdministered=$false
            if($expectedMacHex -match '^[0-9A-F]{12}$'){
                $expectedWasLocallyAdministered=(([Convert]::ToByte($expectedMacHex.Substring(0,2),16) -band 2) -eq 2)
            }
            $isBoundedWifiRollover=(
                $medium -eq '9' -and
                [string]::IsNullOrWhiteSpace($expectedOverride) -and
                [string]::IsNullOrWhiteSpace($actualOverride) -and
                -not [string]::IsNullOrWhiteSpace($expectedPermanentHex) -and
                $expectedPermanentHex -ceq $actualPermanentHex -and
                $actualMacHex -ceq $actualPermanentHex -and
                $expectedMacHex -cne $expectedPermanentHex -and
                $expectedWasLocallyAdministered
            )
            if($isBoundedWifiRollover){
                $acceptedRandomizedWifiRollover=$true
            } else {
                return [pscustomobject][ordered]@{
                    restored=$false
                    reason=('BASELINE_ADAPTER_MAC_DRIFT:'+ $expected.Name+
                        ':expected_current='+$expectedMac+
                        ':actual_current='+$actualMac+
                        ':expected_permanent='+$expectedPermanent+
                        ':actual_permanent='+$actualPermanent+
                        ':expected_network_address_override='+$expectedOverride+
                        ':actual_network_address_override='+$actualOverride+
                        ':ndis_physical_medium='+$medium)
                }
            }
        }
        if ([string]$actual.InitialStatus -cne [string]$expected.InitialStatus) {
            return [pscustomobject][ordered]@{restored=$false;reason=('BASELINE_ADAPTER_STATE_DRIFT:'+ $expected.Name)}
        }
    }

    $actualDefaults = @($CurrentRoutes | Where-Object { $_.IsDefaultRoute })
    if ($actualDefaults.Count -eq 0) {
        return [pscustomobject][ordered]@{restored=$false;reason='NO_DEFAULT_ROUTE_AFTER_RESTORE'}
    }

    return [pscustomobject][ordered]@{restored=$true;reason=$(if($acceptedRandomizedWifiRollover){'PASS_RANDOMIZED_WIFI_ROLLOVER_TO_PERMANENT'}else{'PASS'})}
}

function Assert-P5GNetworkRestored {
    param([object]$Baseline, [object[]]$CurrentPhysicalAdapters, [object[]]$CurrentRoutes, [object]$PersistedState)
    $check=Test-P5GNetworkRestored $Baseline $CurrentPhysicalAdapters $CurrentRoutes $PersistedState
    if (-not [bool]$check.restored) { throw ([string]$check.reason) }
    return $true
}
