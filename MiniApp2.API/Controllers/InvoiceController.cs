using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using System.Linq;
using System.Security.Claims;

namespace MiniApp2.API.Controllers
{
    [Authorize]
    [Route("api/[controller]")]
    [ApiController]
    public class InvoiceController : ControllerBase
    {
        [HttpGet]
        public IActionResult GetInvoices()
        {
            var userName = HttpContext.User.Identity.Name;

            var userIdClaim = User.Claims.FirstOrDefault(x => x.Type == ClaimTypes.NameIdentifier);

            var emailClaim = User.Claims.FirstOrDefault(x => x.Type == ClaimTypes.Email);

            // veri tabanında userId veya userName alanları üzerinden fatura bilgilerini getirebilirsiniz

            // invoice fields, userId or userName fields

            return Ok($"Invoice => UserName: {userName} - UserId: {userIdClaim.Value} - Email: {emailClaim.Value}");
        }
    }
}
