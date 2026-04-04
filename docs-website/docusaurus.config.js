// @ts-check

import {themes as prismThemes} from 'prism-react-renderer';

/** @type {import('@docusaurus/types').Config} */
const config = {
  title: 'aflock',
  tagline: 'Cryptographically signed policies for constrained AI agent execution',
  favicon: '/img/favicon.ico',

  url: 'https://aflock.ai',
  baseUrl: '/',

  organizationName: 'aflock-ai',
  projectName: 'aflock',

  onBrokenLinks: 'warn',
  onBrokenMarkdownLinks: 'warn',

  i18n: {
    defaultLocale: 'en',
    locales: ['en'],
  },

  presets: [
    [
      'classic',
      /** @type {import('@docusaurus/preset-classic').Options} */
      ({
        docs: {
          path: "..",
          include: [
            "README.md",
            "docs/**/*.{md,mdx}",
          ],
          sidebarPath: './sidebars.js',
          routeBasePath: "/docs",
        },
        blog: false,
        theme: {
          customCss: './src/css/custom.css',
        },
      }),
    ],
  ],

  themeConfig:
    /** @type {import('@docusaurus/preset-classic').ThemeConfig} */
    ({
      announcementBar: {
        id: 'alpha_notice',
        content:
          '🚧 <b>Early Alpha</b> · aflock has not had a stable release yet and is under active development. Some documented features are still work-in-progress. <a href="https://github.com/aflock-ai/aflock/issues">Open issues</a> · <a href="https://github.com/aflock-ai/aflock#contributing">Contributions welcome</a> · ⭐ <a href="https://github.com/aflock-ai/aflock">Star us on GitHub</a>',
        isCloseable: false,
      },
      image: 'img/aflock-og.png',
      navbar: {
        title: 'aflock',
        logo: {
          alt: 'aflock Logo',
          src: 'img/logo.svg',
        },
        items: [
          {
            type: "doc",
            docId: "README",
            position: "left",
            label: "About",
          },
          {
            type: "doc",
            docId: "docs/tutorials/getting-started",
            position: "left",
            label: "Tutorials",
          },
          {
            type: "doc",
            docId: "docs/concepts/policies",
            position: "left",
            label: "Concepts",
          },
          {
            type: "search",
            position: "right",
          },
          {
            href: "https://github.com/aflock-ai/aflock",
            position: "right",
            className: "header-github-link",
            "aria-label": "GitHub repository",
          },
        ],
      },
      footer: {
        style: 'dark',
        links: [
          {
            title: 'Docs',
            items: [
              {
                label: 'Getting Started',
                to: 'docs/docs/tutorials/getting-started',
              },
              {
                label: 'Policy Schema',
                to: 'docs/docs/reference/policy-schema',
              },
              {
                label: 'Comparison',
                to: 'docs/docs/reference/comparison',
              },
            ],
          },
          {
            title: 'Community',
            items: [
              {
                label: 'GitHub',
                href: 'https://github.com/aflock-ai/aflock',
              },
              {
                label: 'Witness',
                href: 'https://witness.dev',
              },
              {
                label: 'TestifySec',
                href: 'https://testifysec.com',
              },
              {
                label: 'Discussions',
                href: 'https://github.com/orgs/aflock-ai/discussions',
              },
            ],
          },
          {
            title: 'More',
            items: [
              {
                label: 'Paper',
                href: 'https://github.com/aflock-ai/aflock/blob/main/paper/aflock.pdf',
              },
              {
                label: 'Specification',
                to: 'docs/docs/reference/policy-schema',
              },
              {
                label: 'Rookery',
                href: 'https://github.com/aflock-ai/rookery',
              },
            ],
          },
        ],
        copyright: `Copyright \u00a9 ${new Date().getFullYear()} TestifySec, Inc. Built with Docusaurus.`,
      },
      prism: {
        theme: prismThemes.github,
        darkTheme: prismThemes.dracula,
        additionalLanguages: ['json', 'bash', 'go', 'rego'],
      },
    }),
};

export default config;
