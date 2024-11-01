using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Entity.ModelsDto
{
    public class UserLoginDto
    {
        public string UserName { get; set; }
        public string Password { get; set; }
        public Guid CompanyId { get; set; }
        public Guid ApplicationId { get; set; }
    }

}
