import { EuiDataGridColumn } from '@elastic/eui';

export const runtimeJavaVulnerabilitiesDefaultColumns: EuiDataGridColumn[] = [
  {
    id: 'wazuh.agent.name',
  },
  {
    id: 'runtime_java.component.package.name',
  },
  {
    id: 'runtime_java.component.package.version',
  },
  {
    id: 'runtime_java.component.runtime_path',
  },
  {
    id: 'runtime_java.vulnerability.severity',
  },
  {
    id: 'runtime_java.vulnerability.id',
  },
  {
    id: 'runtime_java.vulnerability.fixed_versions',
  },
  {
    id: 'runtime_java.vulnerability.match_confidence',
  },
];

export const runtimeJavaVulnerabilitiesHistoryDefaultColumns: EuiDataGridColumn[] =
  [
    {
      id: 'event.created',
    },
    {
      id: 'event.action',
    },
    {
      id: 'wazuh.agent.name',
    },
    {
      id: 'runtime_java.component.package.name',
    },
    {
      id: 'runtime_java.component.package.version',
    },
    {
      id: 'runtime_java.component.runtime_path',
    },
    {
      id: 'runtime_java.vulnerability.severity',
    },
    {
      id: 'runtime_java.vulnerability.id',
    },
  ];
