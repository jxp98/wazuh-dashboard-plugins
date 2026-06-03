import React, { useEffect, useMemo, useState } from 'react';
import {
  EuiBasicTableColumn,
  EuiCard,
  EuiFlexGrid,
  EuiFlexItem,
  EuiHorizontalRule,
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

const severityPalette: Record<string, string> = {
  critical: '#cc5642',
  high: '#f5a700',
  medium: '#6092c0',
  low: '#209280',
};

const severityOrder = ['critical', 'high', 'medium', 'low'];

const topTableColumns = (label: string): EuiBasicTableColumn<RuntimeJavaBucket>[] => [
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

const formatLabel = (value: string) =>
  value ? value.charAt(0).toUpperCase() + value.slice(1).toLowerCase() : 'Unknown';

const RuntimeJavaSeverityCard = ({
  severity,
  count,
  isLoading,
}: {
  severity: string;
  count: number;
  isLoading: boolean;
}) => (
  <EuiPanel hasBorder paddingSize='m'>
    <EuiStat
      title={count}
      description={formatLabel(severity)}
      titleSize='m'
      isLoading={isLoading}
      titleColor='default'
    />
    <EuiHorizontalRule margin='s' />
    <EuiText size='xs' color='subdued'>
      <span
        style={{
          color: severityPalette[severity.toLowerCase()] || '#535966',
          fontWeight: 700,
        }}
      >
        Runtime Java severity bucket
      </span>
    </EuiText>
  </EuiPanel>
);

const RuntimeJavaOverviewCard = ({
  title,
  value,
  subtitle,
  isLoading,
}: {
  title: string;
  value: number;
  subtitle: string;
  isLoading: boolean;
}) => (
  <EuiCard
    textAlign='left'
    hasBorder
    paddingSize='m'
    title={title}
    description={subtitle}
    betaBadgeLabel={isLoading ? 'Loading' : undefined}
  >
    <EuiTitle size='l'>
      <h2>{value}</h2>
    </EuiTitle>
  </EuiCard>
);

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
  <EuiPanel paddingSize='m' hasBorder>
    <EuiTitle size='xs'>
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
  const queryFingerprint = JSON.stringify(query);
  const aggregations = useMemo(() => summaryResults?.aggregations || {}, [summaryResults]);

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
      runtimePaths: {
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
      affectedAgents: {
        cardinality: {
          field: 'wazuh.agent.id',
        },
      },
      agentDistribution: {
        terms: {
          field: 'wazuh.agent.name.keyword',
          size: 10,
        },
      },
      vulnerableComponents: {
        cardinality: {
          field: 'runtime_java.component.runtime_path',
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
      .catch(fetchError => setError(fetchError))
      .finally(() => setIsSummaryLoading(false));
  }, [query, queryFingerprint, fingerprint, filtersFingerprint, isLoading, fetchData]);

  const totalFindings =
    typeof summaryResults?.hits?.total === 'number'
      ? summaryResults.hits.total
      : summaryResults?.hits?.total?.value || 0;
  const affectedAgents = aggregations?.affectedAgents?.value || 0;
  const vulnerableComponents = aggregations?.vulnerableComponents?.value || 0;
  const packageBuckets = aggregations?.packages?.buckets || [];
  const runtimePathBuckets = aggregations?.runtimePaths?.buckets || [];
  const cveBuckets = aggregations?.cves?.buckets || [];
  const agentBuckets = aggregations?.agentDistribution?.buckets || [];

  const severityCounts = useMemo(() => {
    const counts: Record<string, number> = {
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
    };

    const severityBuckets = aggregations?.severity?.buckets || [];

    severityBuckets.forEach((bucket: RuntimeJavaBucket) => {
      const normalized = String(bucket.key || '').toLowerCase();
      if (normalized in counts) {
        counts[normalized] = bucket.doc_count;
      }
    });

    return counts;
  }, [aggregations]);

  return (
    <>
      <EuiPanel hasBorder paddingSize='m'>
        <EuiTitle size='s'>
          <h2>Runtime Java vulnerability overview</h2>
        </EuiTitle>
        <EuiSpacer size='xs' />
        <EuiText size='s' color='subdued'>
          Mirrors the native vulnerability dashboard structure while keeping Runtime Java specific dimensions such as
          runtime path, package and CVE concentration.
        </EuiText>
      </EuiPanel>

      <EuiSpacer size='m' />

      <EuiFlexGrid columns={4} gutterSize='m'>
        {severityOrder.map(severity => (
          <EuiFlexItem key={severity}>
            <RuntimeJavaSeverityCard
              severity={severity}
              count={severityCounts[severity] || 0}
              isLoading={isSummaryLoading}
            />
          </EuiFlexItem>
        ))}
      </EuiFlexGrid>

      <EuiSpacer size='m' />

      <EuiFlexGrid columns={3} gutterSize='m'>
        <EuiFlexItem>
          <RuntimeJavaOverviewCard
            title='Runtime findings'
            value={totalFindings}
            subtitle='Current Runtime Java vulnerability documents in the state index.'
            isLoading={isSummaryLoading}
          />
        </EuiFlexItem>
        <EuiFlexItem>
          <RuntimeJavaOverviewCard
            title='Affected agents'
            value={affectedAgents}
            subtitle='Unique agents with at least one Runtime Java vulnerability finding.'
            isLoading={isSummaryLoading}
          />
        </EuiFlexItem>
        <EuiFlexItem>
          <RuntimeJavaOverviewCard
            title='Vulnerable runtime paths'
            value={vulnerableComponents}
            subtitle='Distinct runtime paths currently associated with Runtime Java findings.'
            isLoading={isSummaryLoading}
          />
        </EuiFlexItem>
      </EuiFlexGrid>

      {error ? (
        <>
          <EuiSpacer size='m' />
          <EuiPanel color='danger' hasBorder paddingSize='m'>
            <EuiText color='danger' size='s'>
              Runtime Java summary could not be loaded: {error.message || String(error)}
            </EuiText>
          </EuiPanel>
        </>
      ) : null}

      <EuiSpacer size='m' />

      <EuiFlexGrid columns={2} gutterSize='m'>
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
