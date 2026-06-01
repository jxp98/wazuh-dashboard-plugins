import React, { useEffect, useState } from 'react';
import {
  EuiBasicTableColumn,
  EuiFlexGrid,
  EuiFlexGroup,
  EuiFlexItem,
  EuiInMemoryTable,
  EuiPanel,
  EuiSpacer,
  EuiStat,
  EuiText,
  EuiTitle,
} from '@elastic/eui';
import { SearchResponse } from '../../../../../../../../src/core/server';
import { tSearchParams } from '../../../../common/data-source';

type RuntimeJavaBucket = {
  key: string;
  doc_count: number;
};

type RuntimeJavaSummaryProps = {
  fetchData: (params: Omit<tSearchParams, 'filters'>) => Promise<SearchResponse>;
  query: tSearchParams['query'];
  isLoading: boolean;
  fingerprint: string;
  filtersFingerprint: string;
};

const topTableColumns = (
  label: string,
): EuiBasicTableColumn<RuntimeJavaBucket>[] => [
  {
    field: 'key',
    name: label,
    sortable: true,
    truncateText: true,
  },
  {
    field: 'doc_count',
    name: 'Findings',
    align: 'right',
    sortable: true,
  },
];

const RuntimeJavaTopTable = ({
  title,
  label,
  items,
  isLoading,
}: {
  title: string;
  label: string;
  items: RuntimeJavaBucket[];
  isLoading: boolean;
}) => (
  <EuiPanel paddingSize='m' hasBorder={true}>
    <EuiTitle size='xxs'>
      <h3>{title}</h3>
    </EuiTitle>
    <EuiSpacer size='s' />
    <EuiInMemoryTable
      items={items}
      columns={topTableColumns(label)}
      loading={isLoading}
      pagination={false}
      sorting={{
        sort: {
          field: 'doc_count',
          direction: 'desc',
        },
      }}
    />
  </EuiPanel>
);

export const RuntimeJavaVulnerabilitiesSummary = ({
  fetchData,
  query,
  isLoading,
  fingerprint,
  filtersFingerprint,
}: RuntimeJavaSummaryProps) => {
  const [isSummaryLoading, setIsSummaryLoading] = useState(false);
  const [summaryResults, setSummaryResults] = useState<SearchResponse>();
  const [error, setError] = useState<Error>();

  useEffect(() => {
    if (isLoading) {
      return;
    }

    const aggs = {
      severity: {
        terms: {
          field: 'runtime_java.vulnerability.severity',
          size: 10,
        },
      },
      packages: {
        terms: {
          field: 'runtime_java.component.package.name.keyword',
          size: 10,
        },
      },
      runtime_paths: {
        terms: {
          field: 'runtime_java.component.runtime_path',
          size: 10,
        },
      },
      cves: {
        terms: {
          field: 'runtime_java.vulnerability.id',
          size: 10,
        },
      },
      affected_agents: {
        cardinality: {
          field: 'wazuh.agent.id',
        },
      },
      agent_distribution: {
        terms: {
          field: 'wazuh.agent.name',
          size: 10,
        },
      },
    };

    setIsSummaryLoading(true);
    setError(undefined);
    fetchData({
      query,
      pagination: {
        pageIndex: 0,
        pageSize: 0,
      },
      aggs,
    })
      .then(results => setSummaryResults(results))
      .catch(error => setError(error))
      .finally(() => setIsSummaryLoading(false));
  }, [JSON.stringify(query), fingerprint, filtersFingerprint, isLoading]);

  const aggregations = summaryResults?.aggregations || {};
  const totalFindings =
    typeof summaryResults?.hits?.total === 'number'
      ? summaryResults.hits.total
      : summaryResults?.hits?.total?.value || 0;
  const affectedAgents = aggregations?.affected_agents?.value || 0;
  const severityBuckets = aggregations?.severity?.buckets || [];
  const packageBuckets = aggregations?.packages?.buckets || [];
  const runtimePathBuckets = aggregations?.runtime_paths?.buckets || [];
  const cveBuckets = aggregations?.cves?.buckets || [];
  const agentBuckets = aggregations?.agent_distribution?.buckets || [];

  return (
    <>
      <EuiFlexGroup gutterSize='m' responsive={true}>
        <EuiFlexItem grow={false}>
          <EuiPanel paddingSize='m' hasBorder={true}>
            <EuiStat
              title={totalFindings}
              description='Runtime Java findings'
              isLoading={isSummaryLoading}
              titleSize='s'
            />
          </EuiPanel>
        </EuiFlexItem>
        <EuiFlexItem grow={false}>
          <EuiPanel paddingSize='m' hasBorder={true}>
            <EuiStat
              title={affectedAgents}
              description='Affected agents'
              isLoading={isSummaryLoading}
              titleSize='s'
            />
          </EuiPanel>
        </EuiFlexItem>
        <EuiFlexItem>
          <RuntimeJavaTopTable
            title='Findings by severity'
            label='Severity'
            items={severityBuckets}
            isLoading={isSummaryLoading}
          />
        </EuiFlexItem>
      </EuiFlexGroup>

      {error ? (
        <>
          <EuiSpacer size='s' />
          <EuiText color='danger' size='s'>
            Runtime Java summary could not be loaded: {error.message || error}
          </EuiText>
        </>
      ) : null}

      <EuiSpacer size='m' />

      <EuiFlexGrid columns={4} gutterSize='m'>
        <EuiFlexItem>
          <RuntimeJavaTopTable
            title='Top vulnerable Java packages'
            label='Package'
            items={packageBuckets}
            isLoading={isSummaryLoading}
          />
        </EuiFlexItem>
        <EuiFlexItem>
          <RuntimeJavaTopTable
            title='Top affected runtime paths'
            label='Runtime path'
            items={runtimePathBuckets}
            isLoading={isSummaryLoading}
          />
        </EuiFlexItem>
        <EuiFlexItem>
          <RuntimeJavaTopTable
            title='Top CVEs'
            label='CVE'
            items={cveBuckets}
            isLoading={isSummaryLoading}
          />
        </EuiFlexItem>
        <EuiFlexItem>
          <RuntimeJavaTopTable
            title='Agent distribution'
            label='Agent'
            items={agentBuckets}
            isLoading={isSummaryLoading}
          />
        </EuiFlexItem>
      </EuiFlexGrid>
    </>
  );
};
