import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { defineConfig } from "vitepress";

const configDir = dirname(fileURLToPath(import.meta.url));
const cargoToml = readFileSync(resolve(configDir, "../../Cargo.toml"), "utf8");
const versionMatch = cargoToml.match(
  /^\[workspace\.package\][\s\S]*?^\s*version\s*=\s*"([^"]+)"/m,
);
if (!versionMatch) {
  console.warn("Unable to find workspace package version in Cargo.toml");
}
const latestVersion = versionMatch?.[1] ?? "0.0.0";
const siteUrl = "https://pacvamp.com";
const description =
  "Install trusted packages from distribution repositories and the AUR with policy, provenance, and repeatable system state.";

export default defineConfig({
  title: "pacvamp",
  description,
  lang: "en-US",
  head: [
    ["meta", { property: "og:type", content: "website" }],
    ["meta", { property: "og:site_name", content: "pacvamp" }],
    ["meta", { property: "og:locale", content: "en_US" }],
    ["meta", { property: "og:image", content: "https://pacvamp.com/og-image.png" }],
    ["meta", { property: "og:image:type", content: "image/png" }],
    ["meta", { property: "og:image:width", content: "1200" }],
    ["meta", { property: "og:image:height", content: "630" }],
    ["meta", { property: "og:image:alt", content: "pacvamp — a pacman frontend with fangs. Official repos, third-party repos, and AUR — one command, trust tiers built in." }],
    ["meta", { name: "twitter:card", content: "summary_large_image" }],
    ["meta", { name: "twitter:site", content: "@jdxcode" }],
    ["meta", { name: "twitter:image", content: "https://pacvamp.com/og-image.png" }],
    ["meta", { name: "twitter:image:alt", content: "pacvamp — a pacman frontend with fangs. Official repos, third-party repos, and AUR — one command, trust tiers built in." }],
    ["link", { rel: "icon", href: "/favicon.ico", sizes: "any" }],
    ["link", { rel: "icon", type: "image/png", sizes: "32x32", href: "/favicon-32x32.png" }],
    ["link", { rel: "icon", type: "image/svg+xml", href: "/favicon.svg" }],
    ["link", { rel: "apple-touch-icon", sizes: "180x180", href: "/apple-touch-icon.png" }],
    ["link", { rel: "manifest", href: "/site.webmanifest" }],
    ["meta", { name: "theme-color", content: "#17112b" }],
  ],
  transformHead: ({ pageData, title, description: pageDescription }) => {
    const pagePath = pageData.relativePath
      .replace(/(^|\/)index\.md$/, "$1")
      .replace(/\.md$/, "");
    const url = new URL(pagePath, `${siteUrl}/`).toString();

    return [
      ["link", { rel: "canonical", href: url }],
      ["meta", { property: "og:url", content: url }],
      ["meta", { property: "og:title", content: title }],
      ["meta", { property: "og:description", content: pageDescription }],
      ["meta", { name: "twitter:title", content: title }],
      ["meta", { name: "twitter:description", content: pageDescription }],
      [
        "script",
        { type: "application/ld+json" },
        JSON.stringify({
          "@context": "https://schema.org",
          "@type": "WebPage",
          name: title,
          description: pageDescription,
          url,
          isPartOf: {
            "@type": "WebSite",
            name: "pacvamp",
            url: siteUrl,
          },
        }),
      ],
    ];
  },
  cleanUrls: true,
  lastUpdated: true,
  sitemap: {
    hostname: siteUrl,
  },
  themeConfig: {
    logo: { src: "/logo.svg", alt: "pacvamp" },
    nav: [
      { text: "Guide", link: "/" },
      { text: "Install", link: "/install" },
      { text: "Trust", link: "/trust" },
      { text: "Client CLI", link: "/cli/pacvamp/" },
      { text: "Repository CLI", link: "/cli/pacvamp-repo/" },
      { text: "Packslip", link: "/spec/packslip" },
      {
        text: `v${latestVersion}`,
        link: "https://github.com/jdx/pacvamp/releases",
      },
    ],
    sidebar: [
      {
        text: "Get started",
        items: [
          { text: "Overview", link: "/" },
          { text: "Install Pacvamp", link: "/install" },
          { text: "Trust roots", link: "/trust" },
          { text: "Run a registry", link: "/operations/registry" },
          { text: "Omarchy", link: "/adoption/omarchy" },
          { text: "Repository operators", link: "/adoption/opr" },
          { text: "mise tool channel", link: "/adoption/mise" },
        ],
      },
      {
        text: "Command line",
        items: [
          { text: "pacvamp", link: "/cli/pacvamp/" },
          { text: "pacvamp-repo", link: "/cli/pacvamp-repo/" },
          { text: "packslip", link: "https://packslip.dev/cli/" },
        ],
      },
      {
        text: "Specifications",
        collapsed: false,
        items: [
          { text: "Packslip", link: "/spec/packslip" },
          { text: "Repository feeds", link: "/spec/repository-feeds" },
          { text: "Build provenance", link: "/spec/provenance" },
          { text: "Vendor pipeline", link: "/spec/vendor-pipeline" },
          { text: "AUR sync gate", link: "/spec/sync-gate" },
          { text: "Release train", link: "/spec/release-train" },
          { text: "Snapshot store", link: "/spec/snapshot-store" },
          { text: "Tool channel", link: "/spec/tool-channel" },
        ],
      },
    ],
    outline: "deep",
    search: {
      provider: "local",
    },
    socialLinks: [
      { icon: "github", link: "https://github.com/jdx/pacvamp" },
    ],
    editLink: {
      pattern: "https://github.com/jdx/pacvamp/edit/main/docs/:path",
    },
    footer: {
      message: "Released under the MIT License.",
    },
  },
});
