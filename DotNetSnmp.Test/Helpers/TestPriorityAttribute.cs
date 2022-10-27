using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace DotNetSnmp.Test.Helpers
{
    namespace XUnit.Project.Attributes
    {
        [AttributeUsage(AttributeTargets.Method, AllowMultiple = false)]
        public class TestPriorityAttribute : Attribute
        {
            public int Priority { get; private set; }

            public TestPriorityAttribute(int priority) => Priority = priority;
        }
    }

}
