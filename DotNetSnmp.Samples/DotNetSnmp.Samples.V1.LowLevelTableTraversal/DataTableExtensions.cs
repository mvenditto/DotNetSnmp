using System.Data;

namespace DotNetSnmp.Samples.V1.LowLevelTableTraversal
{
    public static class DataTableExtensions
    {
        public static void PrettyPrint(this DataTable dt)
        {
            var paddings = new int[dt.Columns.Count];

            for (var i = 0; i < dt.Columns.Count; i++)
            {
                paddings[i] = int.MinValue;
            }

            foreach (DataRow row in dt.Rows)
            {
                for (var i = 0; i < dt.Columns.Count; i++)
                {
                    var len = row[i]?.ToString()?.Length;

                    if (len.HasValue && len.Value > paddings[i])
                    {
                        paddings[i] = len.Value;
                    }
                }
            }

            for (var i = 0; i < dt.Columns.Count; i++)
            {
                Console.Write(dt.Columns[i].ColumnName.PadRight(paddings[i]) + " ");
            }

            Console.WriteLine();

            foreach (DataRow row in dt.Rows)
            {
                for (var i = 0; i < dt.Columns.Count; i++)
                {
                    Console.Write(row[i]?.ToString()?.PadRight(paddings[i]) + " ");
                }
                Console.WriteLine();
            }
        }
    }
}
