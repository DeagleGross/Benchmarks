using Microsoft.AspNetCore.DataProtection;

namespace Antiforgery
{
    public class NoOpDataProtector : IDataProtector
    {
        public IDataProtector CreateProtector(string purpose) => new NoOpDataProtector();
        public byte[] Protect(byte[] plaintext) => plaintext;
        public byte[] Unprotect(byte[] protectedData) => protectedData;
    }
}
