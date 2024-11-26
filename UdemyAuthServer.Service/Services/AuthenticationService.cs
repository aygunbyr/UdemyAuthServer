using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using SharedLibrary.Configurations;
using SharedLibrary.Dtos;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Threading.Tasks;
using UdemyAuthServer.Core.Configuration;
using UdemyAuthServer.Core.Dtos;
using UdemyAuthServer.Core.Models;
using UdemyAuthServer.Core.Repositories;
using UdemyAuthServer.Core.Services;
using UdemyAuthServer.Core.UnitOfWork;

namespace UdemyAuthServer.Service.Services
{
    public class AuthenticationService : IAuthenticationService
    {
        private readonly IHttpContextAccessor _httpContextAccessor;
        private readonly List<Client> _clients;
        private readonly ITokenService _tokenService;
        private readonly UserManager<UserApp> _userManager;
        private readonly IUnitOfWork _unitOfWork;
        private readonly IGenericRepository<UserRefreshToken> _userRefreshTokenService;
        private readonly CustomTokenOption _tokenOption;

        public AuthenticationService(IHttpContextAccessor httpContextAccessor, IOptions<List<Client>> optionsClient, ITokenService tokenService, UserManager<UserApp> userManager, IUnitOfWork unitOfWork, IGenericRepository<UserRefreshToken> userRefreshTokenService, IOptions<CustomTokenOption> tokenOption)
        {
            _httpContextAccessor = httpContextAccessor;
            _clients = optionsClient.Value;
            _tokenService = tokenService;
            _userManager = userManager;
            _unitOfWork = unitOfWork;
            _userRefreshTokenService = userRefreshTokenService;
            _tokenOption = tokenOption.Value;
        }

        public async Task<Response<TokenDto>> CreateTokenAsync(LoginDto loginDto)
        {
            if (loginDto == null) throw new ArgumentNullException(nameof(loginDto));

            var user = await _userManager.FindByEmailAsync(loginDto.Email);

            if (user == null || !await _userManager.CheckPasswordAsync(user, loginDto.Password))
            {
                return Response<TokenDto>.Fail("Email or Password is wrong", 400, true);
            }

            // Access token oluştur
            var tokenDto = await _tokenService.CreateToken(user);

            // Refresh token oluştur
            var refreshToken = CreateRefreshToken();
            var refreshTokenExpiration = DateTime.Now.AddMinutes(_tokenOption.RefreshTokenExpiration);

            var userRefreshToken = await _userRefreshTokenService
                .Where(x => x.UserId == user.Id)
                .SingleOrDefaultAsync();

            if (userRefreshToken == null)
            {
                // Yeni refresh token kaydet
                await _userRefreshTokenService.AddAsync(new UserRefreshToken
                {
                    UserId = user.Id,
                    Code = refreshToken,
                    Expiration = refreshTokenExpiration
                });
            }
            else
            {
                // Var olan refresh token güncelle
                userRefreshToken.Code = refreshToken;
                userRefreshToken.Expiration = refreshTokenExpiration;
            }

            await _unitOfWork.CommmitAsync();

            // Refresh token'ı cookie'ye yaz
            SetRefreshTokenCookie(refreshToken, refreshTokenExpiration);

            // Sadece access token ve expiration'ı döndür
            return Response<TokenDto>.Success(new TokenDto
            {
                AccessToken = tokenDto.AccessToken,
                AccessTokenExpiration = tokenDto.AccessTokenExpiration
            }, 200);
        }

        // Refresh token oluşturma metodu
        private string CreateRefreshToken()
        {
            var numberByte = new byte[32];
            using var rnd = RandomNumberGenerator.Create();
            rnd.GetBytes(numberByte);
            return Convert.ToBase64String(numberByte);
        }

        // Refresh token expiration süresini döndürme
        private int GetRefreshTokenExpirationMinutes()
        {
            return _tokenOption.RefreshTokenExpiration;
        }


        public void SetRefreshTokenCookie(string refreshToken, DateTime expiration)
        {
            var cookieOptions = new CookieOptions
            {
                HttpOnly = true,
                Secure = true,
                SameSite = SameSiteMode.None,
                Expires = expiration
            };

            _httpContextAccessor.HttpContext.Response.Cookies.Append("refreshToken", refreshToken, cookieOptions);
        }

        private string CreateCookieHeader(string name, string value, DateTime expiration)
        {
            return $"{name}={value}; Path=/; HttpOnly; Secure; SameSite=None; Expires={{expiration:R}}\";";
        }

        public Response<ClientTokenDto> CreateTokenByClient(ClientLoginDto clientLoginDto)
        {
            var client = _clients.SingleOrDefault(x => x.Id == clientLoginDto.ClientId && x.Secret == clientLoginDto.ClientSecret);

            if (client == null)
            {
                return Response<ClientTokenDto>.Fail("ClientId or ClientSecret not found", 404, true);
            }

            var token = _tokenService.CreateTokenByClient(client);

            return Response<ClientTokenDto>.Success(token, 200);
        }

        public async Task<Response<TokenDto>> CreateTokenByRefreshToken()
        {
            var refreshToken = _httpContextAccessor.HttpContext.Request.Cookies["refreshToken"];

            if (string.IsNullOrEmpty(refreshToken))
            {
                return Response<TokenDto>.Fail("Refresh token not found in cookies", 404, true);
            }

            var existRefreshToken = await _userRefreshTokenService.Where(x => x.Code == refreshToken).SingleOrDefaultAsync();

            if (existRefreshToken == null)
            {
                return Response<TokenDto>.Fail("Refresh token not found", 404, true);
            }

            var user = await _userManager.FindByIdAsync(existRefreshToken.UserId);

            if (user == null)
            {
                return Response<TokenDto>.Fail("User Id not found", 404, true);
            }

            var tokenDto = await _tokenService.CreateToken(user);

            existRefreshToken.Code = CreateRefreshToken();
            existRefreshToken.Expiration = DateTime.Now.AddMinutes(_tokenOption.RefreshTokenExpiration);

            await _unitOfWork.CommmitAsync();

            SetRefreshTokenCookie(existRefreshToken.Code, existRefreshToken.Expiration);

            return Response<TokenDto>.Success(tokenDto, 200);
        }

        public async Task<Response<NoDataDto>> RevokeRefreshToken()
        {
            var refreshToken = _httpContextAccessor.HttpContext.Request.Cookies["refreshToken"];

            if (string.IsNullOrEmpty(refreshToken))
            {
                return Response<NoDataDto>.Fail("Refresh token not found in cookies", 404, true);
            }

            var existRefreshToken = await _userRefreshTokenService.Where(x => x.Code == refreshToken).SingleOrDefaultAsync();

            if (existRefreshToken == null)
            {
                return Response<NoDataDto>.Fail("Refresh token not found", 404, true);
            }

            _userRefreshTokenService.Remove(existRefreshToken);

            await _unitOfWork.CommmitAsync();

            _httpContextAccessor.HttpContext.Response.Cookies.Delete("refreshToken");

            return Response<NoDataDto>.Success(200);
        }
    }
}