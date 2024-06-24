using Microsoft.AspNetCore.Identity;
using System.ComponentModel.DataAnnotations.Schema;

namespace ImportantCode.Entity
{
    [Table("User")]
    public class User: IdentityUser
    {
        //public string FullName { get; set; }
        //public string LoginName { get; set; }
        public string? UserType { get; set; }
        public string? Status { get; set; }
        public DateTime? StatusChangedDate { get; set; }
        public DateTime CreatedDate { get; set; }
        public DateTime CreatedBy { get; set; }
        public List<RefreshToken> RefreshTokens { get; set; }

    }
}