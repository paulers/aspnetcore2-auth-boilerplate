using System.ComponentModel.DataAnnotations;

namespace AspNetCore2AuthBoilerplate.Models
{
    public class LoginRequestModel
    {
        [Required, DataType(DataType.EmailAddress)]
        public string Username { get; set; }
        [Required, DataType(DataType.Password)]
        public string Password { get; set; }
        public bool RememberMe { get; set; }
        public string ReturnUrl { get; set; }
    }
}
