using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Entity.ModelsDto
{
    public class CompanyApplicationDto
    {
        public Guid Id { get; set; }
        public Guid CompanyId { get; set; }
        public Guid ApplicationId { get; set; }
        public string DbConnection { get; set; }
    }
}
