﻿using PKISharp.WACS.Extensions;
using PKISharp.WACS.Plugins.Base.Factories;
using PKISharp.WACS.Plugins.ValidationPlugins.Dns;
using PKISharp.WACS.Services;
using PKISharp.WACS.Services.Serialization;
using System;
using System.Threading.Tasks;

namespace PKISharp.WACS.Plugins.StorePlugins
{
    internal class S3StorageOptionsFactory : StorePluginOptionsFactory<S3Storage, S3StorageOptions>
    {
        private readonly ISettingsService _settings;

        private readonly ArgumentsInputService _arguments;

        public S3StorageOptionsFactory(ISettingsService settings, ArgumentsInputService arguments)
        {
            _settings = settings;
            _arguments = arguments;
        }

        private ArgumentResult<string> Bucket => _arguments.
            GetString<S3StorageArguments>(a => a.Bucket).
            Required();

        private ArgumentResult<string> FileKey => _arguments.
            GetString<S3StorageArguments>(a => a.FileKey).
            Required();

        private ArgumentResult<ProtectedString> AccessKey => _arguments.
            GetProtectedString<S3StorageArguments?>(a => a.AccessKey).
            DefaultAsNull();

        private ArgumentResult<ProtectedString> SecretKey => _arguments.
            GetProtectedString<S3StorageArguments?>(a => a.SecretKey).
            DefaultAsNull();

        private ArgumentResult<ProtectedString> PfxPassword => _arguments.
           GetProtectedString<S3StorageArguments?>(a => a.PfxPassword, true).
           WithDefault(S3Storage.DefaultPassword(_settings).Protect()).
           DefaultAsNull();

        public override async Task<S3StorageOptions> Aquire(IInputService inputService, RunLevel runLevel)
        {
            var options = new S3StorageOptions
            {
                Bucket = await Bucket.Interactive(inputService, "S3 Bucket").GetValue(),
                FileKey = await FileKey.Interactive(inputService, "Certificate key file").GetValue(),
                AccessKey = await AccessKey.Interactive(inputService, "Amazon access key").GetValue(),
                SecretKey = await SecretKey.Interactive(inputService, "Amazon secure key").GetValue(),
                PfxPassword = await PfxPassword.Interactive(inputService, "Pfx Password").GetValue()
            };

            return options;
        }

        public override Task<S3StorageOptions> Default()
        {
            throw new NotImplementedException();
        }
    }
}
