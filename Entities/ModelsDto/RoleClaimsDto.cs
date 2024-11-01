using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Entity.ModelsDto
{
    public class RoleClaimsDto
    {
        public string RoleId { get; set; }
        public List<ClaimDto> Claims { get; set; }
    }

}
