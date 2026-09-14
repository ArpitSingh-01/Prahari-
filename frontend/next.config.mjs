/** @type {import('next').NextConfig} */
const nextConfig = {
  output: "standalone",
  async rewrites() {
    // Proxy API calls in dev to avoid CORS setup; in prod the full URL is used.
    const api = process.env.API_PROXY_TARGET;
    if (!api) return [];
    return [{ source: "/backend/:path*", destination: `${api}/:path*` }];
  },
};

export default nextConfig;
