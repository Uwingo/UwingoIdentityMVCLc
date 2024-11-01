using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Entity.ModelsDto
{
    public class RoleDto
    {
        public string Id { get; set; }
        public string Name { get; set; }
        public string Description { get; set; }
        public Guid CompanyId { get; set; }
        public Guid ApplicationId { get; set; }
    }
}
