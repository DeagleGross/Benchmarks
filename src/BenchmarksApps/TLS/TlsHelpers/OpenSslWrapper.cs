using System;
using System.Diagnostics;

namespace TlsHelpers
{
    public static class OpenSslWrapper
    {
        public static void LogOpenSSLVersion()
        {
            if (!(OperatingSystem.IsLinux() || OperatingSystem.IsMacOS()))
            {
                return;
            }

            using var process = new Process()
            {
                StartInfo =
                {
                    FileName = "/usr/bin/env",
                    Arguments = "openssl version",
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    UseShellExecute = false,
                    CreateNoWindow = true
                },
            };

            process.Start();
            process.WaitForExit();
            var output = process.StandardOutput.ReadToEnd();
            Console.WriteLine(output);
        }
    }
}
