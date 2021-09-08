﻿using PKISharp.WACS.Configuration;
using PKISharp.WACS.Configuration.Arguments;

namespace PKISharp.WACS.Plugins.StorePlugins
{
    public class S3StorageArguments : BaseArguments
    {
        [CommandLine(Description = "S3 Bucket to storage certificate")]
        public string Bucket { get; set; }

        [CommandLine(Description = "S3 file key")]
        public string FileKey { get; set; }

        [CommandLine(Description = "Amazon access key")]
        public string AccessKey { get; set; }

        [CommandLine(Description = "Amazon secure key", Secret = true)]
        public string SecretKey { get; set; }

        [CommandLine(Description = "Password to set for .pfx files exported to the folder.", Secret = true)]
        public string PfxPassword { get; set; }

        public override string Name => "S3";

        public override string Group => "Store";

        public override string Condition => "--store s3";
    }
}
