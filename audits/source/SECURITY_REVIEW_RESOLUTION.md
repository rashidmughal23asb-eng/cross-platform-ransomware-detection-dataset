# Security Review Resolution

The publication source audit flagged two instances of HCQNativeBase.ps1
because a VMware VIX property identifier contains the word "PASSWORD".

The relevant identifier is:

VIX_PROPERTY_VM_ENCRYPTION_PASSWORD

This is a VMware VIX SDK constant/property name. It is not a password,
credential value, API key, token, or secret.

The publication hard-coded-secret gate passed.

No guest password or VMware encryption password is distributed in this
release.
