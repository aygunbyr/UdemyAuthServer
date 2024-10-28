using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using System.Linq;
using System.Security.Claims;

namespace MiniApp1.API.Controllers
{
    [Authorize(Roles = "admin,manager")]
    [Route("api/[controller]")]
    [ApiController]
    public class StockController : ControllerBase
    {
        [HttpGet]
        public IActionResult GetStock()
        {
            var userName = HttpContext.User.Identity.Name;

            var userIdClaim = User.Claims.FirstOrDefault(x => x.Type == ClaimTypes.NameIdentifier);

            var emailClaim = User.Claims.FirstOrDefault(x => x.Type == ClaimTypes.Email);

            // veri tabanında userId veya userName alanları üzerinden stok bilgilerini getirebilirsiniz

            // stockId, stockQuantity, category, userId or userName fields

            return Ok($"Stock => UserName: {userName} - UserId: {userIdClaim.Value} - Email: {emailClaim.Value}");
        }
    }
}
