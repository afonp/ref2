// @ts-check
const { themes } = require('prism-react-renderer');

/** @type {import('@docusaurus/types').Config} */
const config = {
  title:   'ref2',
  tagline: 'automatic protocol grammar & message format inference',
  url:     'https://github.com',
  baseUrl: '/',

  onBrokenLinks:        'throw',
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
          sidebarPath: require.resolve('./sidebars.js'),
          routeBasePath: '/',
        },
        blog: false,
        theme: {
          customCss: require.resolve('./src/css/custom.css'),
        },
      }),
    ],
  ],

  themeConfig:
    /** @type {import('@docusaurus/preset-classic').ThemeConfig} */
    ({
      navbar: {
        title: 'ref2',
        items: [
          {
            type: 'docSidebar',
            sidebarId: 'mainSidebar',
            position: 'left',
            label: 'docs',
          },
          {
            href: 'https://github.com',
            label: 'github',
            position: 'right',
          },
        ],
      },
      footer: {
        style: 'dark',
        copyright: 'ref2 — automatic protocol inference',
      },
      prism: {
        theme:     themes.github,
        darkTheme: themes.dracula,
        additionalLanguages: ['c', 'rust', 'bash', 'python', 'json'],
      },
      colorMode: {
        defaultMode:          'dark',
        disableSwitch:        false,
        respectPrefersColorScheme: true,
      },
    }),
};

module.exports = config;
