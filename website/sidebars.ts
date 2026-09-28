import type {SidebarsConfig} from '@docusaurus/plugin-content-docs';

const sidebars: SidebarsConfig = {
  docsSidebar: [
    'index',
    'getting-started',
    {
      type: 'category',
      label: 'Connecting',
      link: {type: 'doc', id: 'connection/index'},
      items: ['connection/ntlm', 'connection/kerberos'],
    },
    {
      type: 'category',
      label: 'Reading',
      items: ['reading/metadata', 'reading/queries'],
    },
    {
      type: 'category',
      label: 'The protocol',
      link: {type: 'doc', id: 'protocol/index'},
      items: ['protocol/framing', 'protocol/sealing'],
    },
    {
      type: 'category',
      label: 'Reference',
      items: [
        'reference/api',
        'reference/errors',
        'reference/limitations',
        'reference/troubleshooting',
      ],
    },
    'development',
  ],
};

export default sidebars;
