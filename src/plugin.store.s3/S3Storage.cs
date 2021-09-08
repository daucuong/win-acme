using Amazon.S3.Model;
using PKISharp.WACS.DomainObjects;
using PKISharp.WACS.Plugins.Interfaces;
using PKISharp.WACS.Services;
using System;
using System.IO;
using System.Runtime.Versioning;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;

[assembly: SupportedOSPlatform("windows")]

namespace PKISharp.WACS.Plugins.StorePlugins
{
    internal class S3Storage : IStorePlugin
    {
        private readonly S3StorageOptions _options;
        private readonly ILogService _log;
        private readonly string? _password;

        public static string DefaultPassword(ISettingsService settings)
            => settings.Store.PfxFile?.DefaultPassword;

        public S3Storage(S3StorageOptions options,
            ILogService log,
            ISettingsService settings,
            SecretServiceManager secretServiceManager)
        {
            _options = options;
            _log = log;

            var passwordRaw = !string.IsNullOrWhiteSpace(options.PfxPassword?.Value) ?
               options.PfxPassword.Value :
               settings.Store.PfxFile?.DefaultPassword;

            _password = secretServiceManager.EvaluateSecret(passwordRaw);
        }

        public (bool, string) Disabled => (false, "");

        public Task Delete(CertificateInfo certificateInfo) => Task.CompletedTask;

        public async Task Save(CertificateInfo certificateInfo)
        {
            try
            {
                //AWSCredentials credential;
                //if (_options.AccessKey != null && _options.SecretKey != null)
                //    credential = new BasicAWSCredentials(_options.AccessKey.Value, _options.SecretKey.Value);
                //else
                //    credential = new InstanceProfileAWSCredentials();

                _log.Information("Upload {0} to s3://{1}/{2}", certificateInfo.CommonName.Value, _options.Bucket, _options.FileKey);
                var collection = new X509Certificate2Collection
                {
                    certificateInfo.Certificate
                };

                collection.AddRange(certificateInfo.Chain.ToArray());
                var certs = collection.Export(X509ContentType.Pfx, _password);
                using var stream = new MemoryStream(certs);
                using var s3Client = new Amazon.S3.AmazonS3Client();
                var request = new PutObjectRequest
                {
                    InputStream = stream,
                    Key = _options.FileKey,
                    BucketName = _options.Bucket,
                    CannedACL = Amazon.S3.S3CannedACL.PublicRead
                };

                var response = await s3Client.PutObjectAsync(request);
            }
            catch (Exception ex)
            {
                _log.Error(ex, "Error importing certificate to S3");
            }
        }
    }
}
