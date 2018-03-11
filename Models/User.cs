using System;

namespace AspNetCore2AuthBoilerplate.Models
{
    public class User
    {
        public Guid Id { get; set; }
        public string Name { get; set; }
        public string Email { get; set; }
        public string Bio { get; set; }
    }
}
