using JwtEncryption.Models;

namespace JwtEncryption.Services
{
    public interface IJwtService
    {
        string Generate(User user);
    }
}