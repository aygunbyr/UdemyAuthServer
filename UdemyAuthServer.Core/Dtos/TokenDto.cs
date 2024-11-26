using System;

namespace UdemyAuthServer.Core.Dtos
{
    public class TokenDto
    {
        public string AccessToken { get; set; }
        public DateTime AccessTokenExpiration { get; set; }
    }
}
