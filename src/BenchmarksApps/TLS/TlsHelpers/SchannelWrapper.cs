using System;
using Microsoft.Win32;

namespace TlsHelpers
{
    public static class SchannelWrapper
    {
        public static void DisableTlsResumption()
        {
            if (!OperatingSystem.IsWindows())
            {
                return;
            }

            // https://learn.microsoft.com/en-us/windows-server/security/tls/tls-registry-settings?tabs=diffie-hellman#maximumcachesize
            // HKLM SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL
            const string registryPath = @"SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL";
            const string valueName = "MaximumCacheSize";
            const int valueData = 0;

            try
            {
                using RegistryKey key = Registry.LocalMachine.OpenSubKey(registryPath, writable: true);
                if (key != null)
                {
                    key.SetValue(valueName, valueData, RegistryValueKind.DWord);
                    Console.WriteLine("TLS resumption disabled successfully.");
                }
                else
                {
                    Console.WriteLine("Registry path not found.");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"An error occurred: {ex.Message}");
            }
        }

        public static void RollbackTlsResumptionToDefault()
        {
            if (!OperatingSystem.IsWindows())
            {
                return;
            }

            const string registryPath = @"SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL";
            const string valueName = "MaximumCacheSize";

            try
            {
                using RegistryKey key = Registry.LocalMachine.OpenSubKey(registryPath, writable: true);
                if (key != null)
                {
                    key.DeleteValue(valueName, throwOnMissingValue: false);
                    Console.WriteLine("TLS resumption setting removed successfully.");
                }
                else
                {
                    Console.WriteLine("Registry path not found.");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"An error occurred: {ex.Message}");
            }
        }
    }
}