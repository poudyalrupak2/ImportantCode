using ImportantCode.Service;

namespace ImportantCode.Infrastructure
{
    public class JwtRefreshTokenCache : IHostedService, IDisposable
    {
        private Timer _timer = null!;
        private readonly ILogger _logger;
        private readonly IServiceProvider _serviceProvider;

        public JwtRefreshTokenCache(IServiceProvider serviceProvider, ILogger<JwtRefreshTokenCache> logger)
        {
            _serviceProvider = serviceProvider;
            _logger = logger;
        }

        public Task StartAsync(CancellationToken stoppingToken)
        {
            // remove expired refresh tokens from cache every minute
            _timer = new Timer(DoWork!, null, TimeSpan.Zero, TimeSpan.FromMinutes(1));
            return Task.CompletedTask;
        }

        private void DoWork(object state)
        {
            using (var scope = _serviceProvider.CreateScope())
            {
                var jwtAuthManager = scope.ServiceProvider.GetRequiredService<IJwtAuthManager>();

                jwtAuthManager.RemoveExpiredRefreshTokens(DateTime.Now);
            }
        }

        public Task StopAsync(CancellationToken stoppingToken)
        {
            _timer.Change(Timeout.Infinite, 0);
            return Task.CompletedTask;
        }

        public void Dispose()
        {
            _timer.Dispose();
            GC.SuppressFinalize(this);
        }
    }
}
