import {themes as prismThemes} from 'prism-react-renderer';
import type {Config} from '@docusaurus/types';
import type * as Preset from '@docusaurus/preset-classic';

// Docs for ssas-xmla-tcp, published by pages.yml to
// https://oluies.github.io/ssas-xmla-tcp/.
//
// The site is the repository's own docs, restated for a reader who has not
// cloned it. It must not overstate what has been verified: what is UNVERIFIED
// in docs/discovery-brief.md stays UNVERIFIED here.

const config: Config = {
  title: 'SSAS XMLA over TCP',
  tagline:
    'A pure-Python client for the Analysis Services native XMLA/TCP binding — read SSAS metadata from Linux with no IIS and no Windows components.',
  favicon: 'img/favicon.svg',

  url: 'https://oluies.github.io',
  baseUrl: '/ssas-xmla-tcp/',
  trailingSlash: true,

  organizationName: 'oluies',
  projectName: 'ssas-xmla-tcp',

  // 'throw', not 'warn': docs-build.yml is the PR gate for website/, and a gate
  // that exits 0 on a broken link does not gate anything.
  onBrokenLinks: 'throw',
  onBrokenAnchors: 'throw',

  i18n: {
    defaultLocale: 'en',
    locales: ['en'],
  },

  presets: [
    [
      'classic',
      {
        docs: {
          sidebarPath: './sidebars.ts',
          // Docs ARE the site: /ssas-xmla-tcp/<page>/
          routeBasePath: '/',
          editUrl: 'https://github.com/oluies/ssas-xmla-tcp/tree/main/website/',
          showLastUpdateTime: true,
        },
        blog: false,
        theme: {
          customCss: './src/css/custom.css',
        },
      } satisfies Preset.Options,
    ],
  ],

  themes: ['@docusaurus/theme-mermaid'],

  markdown: {
    mermaid: true,
    hooks: {
      onBrokenMarkdownLinks: 'throw',
    },
  },

  themeConfig: {
    metadata: [
      {
        name: 'keywords',
        content:
          'SSAS, Analysis Services, XMLA, TCP, DIME, SPNEGO, Kerberos, NTLM, Python, Linux, msmdpump, MS-SSAS',
      },
      {
        name: 'description',
        content:
          'Pure-Python client for the SQL Server Analysis Services native XMLA/TCP binding, built from the Microsoft Open Specifications.',
      },
    ],
    navbar: {
      title: 'ssas-xmla-tcp',
      logo: {
        alt: 'ssas-xmla-tcp',
        src: 'img/logo.svg',
        href: '/',
      },
      items: [
        {
          type: 'docSidebar',
          sidebarId: 'docsSidebar',
          position: 'left',
          label: 'Docs',
        },
        {to: '/protocol/', label: 'Protocol', position: 'left'},
        {to: '/reference/api/', label: 'API', position: 'left'},
        {
          href: 'https://github.com/oluies/ssas-xmla-tcp',
          label: 'GitHub',
          position: 'right',
        },
      ],
    },
    colorMode: {
      defaultMode: 'light',
      respectPrefersColorScheme: true,
    },
    footer: {
      style: 'dark',
      links: [
        {
          title: 'Docs',
          items: [
            {label: 'Getting Started', to: '/getting-started/'},
            {label: 'Connecting', to: '/connection/'},
            {label: 'Reading metadata', to: '/reading/metadata/'},
            {label: 'Limitations', to: '/reference/limitations/'},
          ],
        },
        {
          title: 'The protocol',
          items: [
            {label: 'The layers', to: '/protocol/'},
            {label: 'DIME framing', to: '/protocol/framing/'},
            {label: 'The sealed frame', to: '/protocol/sealing/'},
            {
              label: '[MS-SSAS]',
              href: 'https://learn.microsoft.com/en-us/openspecs/sql_server_protocols/ms-ssas/cc9c04c8-df61-40aa-b9bf-49d06b3ac888',
            },
          ],
        },
        {
          title: 'Project',
          items: [
            {label: 'GitHub', href: 'https://github.com/oluies/ssas-xmla-tcp'},
            {label: 'Issues', href: 'https://github.com/oluies/ssas-xmla-tcp/issues'},
            {label: 'Development', to: '/development/'},
            {
              label: 'xmla-extention (DuckDB)',
              href: 'https://hugr-lab.github.io/xmla-extention/',
            },
          ],
        },
      ],
      copyright: `Copyright © ${new Date().getFullYear()} Örjan Lundberg. Apache-2.0.`,
    },
    prism: {
      theme: prismThemes.github,
      darkTheme: prismThemes.dracula,
      additionalLanguages: ['python', 'bash', 'ini', 'sql'],
    },
  } satisfies Preset.ThemeConfig,
};

export default config;
