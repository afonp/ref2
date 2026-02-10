/** @type {import('@docusaurus/plugin-content-docs').SidebarsConfig} */
const sidebars = {
  mainSidebar: [
    {
      type: 'doc',
      id:   'intro',
      label: 'intro',
    },
    {
      type:  'category',
      label: 'getting started',
      collapsed: false,
      items: [
        'getting-started/installation',
        'getting-started/quickstart',
      ],
    },
    {
      type:  'category',
      label: 'cli reference',
      items: [
        'cli/infer',
        'cli/dissect',
        'cli/view',
      ],
    },
    {
      type:  'category',
      label: 'how it works',
      items: [
        'internals/overview',
        'internals/ingestion',
        'internals/tokenization',
        'internals/format-inference',
        'internals/grammar-induction',
        'internals/output-formats',
      ],
    },
    {
      type:  'category',
      label: 'evaluation',
      items: [
        'evaluation/metrics',
        'evaluation/protocols',
      ],
    },
    {
      type: 'doc',
      id:   'architecture',
      label: 'architecture',
    },
  ],
};

module.exports = sidebars;
