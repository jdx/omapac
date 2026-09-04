import { defineConfig } from "vitepress";

export default defineConfig({
  title: "pacvamp",
  description: "Trusted packages for pacman-based Linux distributions",
  lang: "en-US",
  cleanUrls: true,
  lastUpdated: true,
  sitemap: {
    hostname: "https://pacvamp.com",
  },
  themeConfig: {
    nav: [
      { text: "Guide", link: "/" },
      { text: "Install", link: "/install" },
      { text: "Trust", link: "/trust" },
      { text: "Client CLI", link: "/cli/pacvamp/" },
      { text: "Repository CLI", link: "/cli/pacvamp-repo/" },
      { text: "Packslip", link: "/spec/packslip" },
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
          { text: "packslip", link: "/cli/packslip/" },
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
