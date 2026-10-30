import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  // Allow images from any external source (for future avatar / thumbnail use)
  images: {
    remotePatterns: [{ protocol: "https", hostname: "**" }],
  },
};

export default nextConfig;
