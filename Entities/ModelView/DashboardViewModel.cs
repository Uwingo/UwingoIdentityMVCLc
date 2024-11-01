using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Entity.ModelsDto
{
    public class DashboardViewModel
    {
        public int CompanyCount { get; set; }
        public int CompanyApplicationCount { get; set; }
        public int ApplicationCount { get; set; }
        public int RoleCount { get; set; }
        public int TenantCount { get; set; }
        public int UserCount { get; set; }
    }
}
