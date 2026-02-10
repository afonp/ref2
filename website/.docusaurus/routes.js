import React from 'react';
import ComponentCreator from '@docusaurus/ComponentCreator';

export default [
  {
    path: '/__docusaurus/debug',
    component: ComponentCreator('/__docusaurus/debug', '5ff'),
    exact: true
  },
  {
    path: '/__docusaurus/debug/config',
    component: ComponentCreator('/__docusaurus/debug/config', '5ba'),
    exact: true
  },
  {
    path: '/__docusaurus/debug/content',
    component: ComponentCreator('/__docusaurus/debug/content', 'a2b'),
    exact: true
  },
  {
    path: '/__docusaurus/debug/globalData',
    component: ComponentCreator('/__docusaurus/debug/globalData', 'c3c'),
    exact: true
  },
  {
    path: '/__docusaurus/debug/metadata',
    component: ComponentCreator('/__docusaurus/debug/metadata', '156'),
    exact: true
  },
  {
    path: '/__docusaurus/debug/registry',
    component: ComponentCreator('/__docusaurus/debug/registry', '88c'),
    exact: true
  },
  {
    path: '/__docusaurus/debug/routes',
    component: ComponentCreator('/__docusaurus/debug/routes', '000'),
    exact: true
  },
  {
    path: '/',
    component: ComponentCreator('/', 'e8c'),
    routes: [
      {
        path: '/',
        component: ComponentCreator('/', 'd83'),
        routes: [
          {
            path: '/',
            component: ComponentCreator('/', '4f4'),
            routes: [
              {
                path: '/architecture',
                component: ComponentCreator('/architecture', '67c'),
                exact: true,
                sidebar: "mainSidebar"
              },
              {
                path: '/cli/dissect',
                component: ComponentCreator('/cli/dissect', '9b9'),
                exact: true,
                sidebar: "mainSidebar"
              },
              {
                path: '/cli/infer',
                component: ComponentCreator('/cli/infer', '594'),
                exact: true,
                sidebar: "mainSidebar"
              },
              {
                path: '/cli/view',
                component: ComponentCreator('/cli/view', '439'),
                exact: true,
                sidebar: "mainSidebar"
              },
              {
                path: '/evaluation/metrics',
                component: ComponentCreator('/evaluation/metrics', '5e8'),
                exact: true,
                sidebar: "mainSidebar"
              },
              {
                path: '/evaluation/protocols',
                component: ComponentCreator('/evaluation/protocols', '927'),
                exact: true,
                sidebar: "mainSidebar"
              },
              {
                path: '/getting-started/installation',
                component: ComponentCreator('/getting-started/installation', '4f1'),
                exact: true,
                sidebar: "mainSidebar"
              },
              {
                path: '/getting-started/quickstart',
                component: ComponentCreator('/getting-started/quickstart', '6cd'),
                exact: true,
                sidebar: "mainSidebar"
              },
              {
                path: '/internals/format-inference',
                component: ComponentCreator('/internals/format-inference', 'c05'),
                exact: true,
                sidebar: "mainSidebar"
              },
              {
                path: '/internals/grammar-induction',
                component: ComponentCreator('/internals/grammar-induction', 'a70'),
                exact: true,
                sidebar: "mainSidebar"
              },
              {
                path: '/internals/ingestion',
                component: ComponentCreator('/internals/ingestion', '575'),
                exact: true,
                sidebar: "mainSidebar"
              },
              {
                path: '/internals/output-formats',
                component: ComponentCreator('/internals/output-formats', 'ae0'),
                exact: true,
                sidebar: "mainSidebar"
              },
              {
                path: '/internals/overview',
                component: ComponentCreator('/internals/overview', '0c8'),
                exact: true,
                sidebar: "mainSidebar"
              },
              {
                path: '/internals/tokenization',
                component: ComponentCreator('/internals/tokenization', '7f7'),
                exact: true,
                sidebar: "mainSidebar"
              },
              {
                path: '/',
                component: ComponentCreator('/', 'e98'),
                exact: true,
                sidebar: "mainSidebar"
              }
            ]
          }
        ]
      }
    ]
  },
  {
    path: '*',
    component: ComponentCreator('*'),
  },
];
